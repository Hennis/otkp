// ============================================================================
//  src/cli/enroll.rs  --  `otkp enroll`: create a user and hand out their secret
// ============================================================================
//
//  EXPERT VIEW:
//    Enrolment is the one moment the secret exists outside the server, and it is
//    therefore the most sensitive operation in the tool. Four rules govern it:
//
//      1. **The secret is generated on the server**, by the OS CSPRNG, never
//         chosen by a human and never derived from a password. A human-chosen
//         secret would collapse the protocol's security to password strength.
//      2. **It is printed exactly once**, to stdout, with clear instructions.
//         There is no `otkp show-secret` command, because such a command is a
//         permanent liability: it turns a one-time exposure into a queryable
//         secret store. (An operator who genuinely needs to re-issue can revoke
//         and re-enrol; see the roadmap for a rotation feature.)
//      3. **It is written to the keyring atomically and at 0600** before it is
//         printed, so a crash between the two leaves a consistent server state
//         (a secret that was never handed out, which the operator can revoke)
//         rather than the reverse (a secret handed out that the server does not
//         know).
//      4. **An enrolment URI is printed** so the user can paste one line into a
//         client rather than transcribing a 52-character base32 string.
//
//    The HOTP value is printed too. It is not used by the protocol; it exists so
//    the user can compare it against Google Authenticator or `oathtool` and
//    confirm the secret was copied correctly *before* they depend on it. That is
//    a small feature with a large effect on support burden.
//
//  KID VIEW:
//    Make a brand-new handshake for a new member, write it in the club's secret
//    book, and hand them a card with the handshake on it -- once. We also show
//    them the six-digit number their phone app would show, so they can check
//    they copied it right.
// ============================================================================

use crate::cli::Options;
use crate::config::ServerConfig;
use crate::crypto::{time_step, unix_now};
use crate::error::{OtkpError, Result};
use crate::keyring::Keyring;
use std::path::Path;

/// Run `otkp enroll <user>`.
///
/// EXPERT: Note the order of operations, which is the whole point of this
///         function: load, enrol in memory, *save*, then print. The save must
///         succeed before the print happens, because the print is the
///         irreversible step. If we printed first and the save failed, the user
///         would hold a secret the server had never recorded -- a guaranteed
///         "my client says the knock is wrong" bug report with no obvious cause.
/// KID: Write it in the book first, then hand over the card. Never the other way
///      round.
pub fn run(options: &Options, user: &str) -> Result<()> {
    let dir = Path::new(&options.dir);

    // ------------------------------------------------------------------
    // 1. Load the current state.
    // ------------------------------------------------------------------
    let config_path = dir.join("config.json");
    let keyring_path = dir.join("keyring.json");

    if !config_path.exists() || !keyring_path.exists() {
        return Err(OtkpError::config(format!(
            "'{}' is not initialised (no config.json/keyring.json). \
             Run `otkp init --dir {}` first.",
            dir.display(),
            dir.display()
        )));
    }

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|e| OtkpError::io_err(config_path.display().to_string(), e))?;
    let config: ServerConfig = serde_json::from_str(&config_text)
        .map_err(|e| OtkpError::Json(format!("{}: {e}", config_path.display())))?;
    config.validate()?;

    let mut keyring = Keyring::load(&keyring_path)?;

    // ------------------------------------------------------------------
    // 2. Enrol in memory. `enroll` rejects duplicates and generates the secret.
    // ------------------------------------------------------------------
    let now = unix_now();
    // `enroll` returns a borrow of the new entry; we clone the *user name* and
    // the secret's text form immediately, because the borrow must end before we
    // call `keyring.save()` (which needs `&self`... actually `&self` is fine, but
    // we will need to drop the borrow to keep the code obvious).
    let (secret_base32, secret_hex, enrolled_at) = {
        let enrollment = keyring.enroll(user, now)?;
        (
            enrollment.secret.to_base32(),
            enrollment.secret.to_hex(),
            enrollment.enrolled_at,
        )
    };

    // ------------------------------------------------------------------
    // 3. Save FIRST. Only then may we print.
    // ------------------------------------------------------------------
    keyring.save(&keyring_path)?;
    crate::log_info!(
        "enrolled '{user}' into {} (now {} user(s))",
        keyring_path.display(),
        keyring.len()
    );

    // ------------------------------------------------------------------
    // 4. Compute the reference values for the current window.
    // ------------------------------------------------------------------
    // We re-load the enrolment to derive from it. This is a little redundant, but
    // it keeps the borrow lifetimes trivial and the derivation goes through the
    // same `spec_and_hotp_for` path the daemon uses -- so what we print is
    // exactly what the daemon will expect.
    let step = time_step(now, config.step_seconds);
    // `None` for the source address: enrolment prints the *unbound* sequence,
    // which is what a client derives by default. If the server has binding
    // enabled, `verify` is the tool that shows the per-address sequences.
    let (spec, hotp_code) = keyring.spec_and_hotp_for(user, step, &config, None)?;

    // ------------------------------------------------------------------
    // 5. Print the enrolment information, once, to stdout.
    // ------------------------------------------------------------------
    //
    // EXPERT: All of this goes to *stdout* because it is the command's requested
    //         output. The surrounding log lines go to stderr. An operator can
    //         therefore redirect the secret to a file or a password manager
    //         without also capturing our log noise:
    //             otkp enroll alice > alice-otkp.txt
    //         That is a genuinely useful property and it is why the split matters.
    //
    // KID: The card we hand over. Printed loudly, with a warning.
    println!("============================================================");
    println!("  Enrolment created for user '{user}'");
    println!("============================================================");
    println!();
    println!("  Secret (base32) : {secret_base32}");
    println!("  Secret (hex)    : {secret_hex}");
    println!();
    println!("  Reference HOTP  : {hotp_code:06}  (NOT used to knock; for verifying");
    println!("                    the secret against any authenticator app)");
    println!();
    println!("  Current knocks  : {}", format_ports(&spec.knock_ports));
    println!("  Current open    : {}", spec.open_port);
    println!(
        "  Time step       : {step} (window = {}s)",
        config.step_seconds
    );
    println!();
    println!(
        "  Enrolment URI   : {}",
        enrolment_uri(
            user,
            &secret_base32,
            &options.dir,
            config.step_seconds,
            &spec,
        )
    );
    println!();
    println!("============================================================");
    println!("  Give the secret to '{user}' ONCE, over a channel you trust.");
    println!("  The server keeps its own copy in keyring.json; this is the");
    println!("  only time the secret is printed. There is no command to");
    println!("  show it again -- revoke and re-enrol if it is lost.");
    println!("============================================================");

    // A final, unmissable warning if the default firewall is still in dry-run
    // mode: the operator may believe the protection is live when it is not.
    if matches!(config.firewall, crate::config::FirewallConfig::DryRun) {
        println!();
        println!("NOTE: config.json still uses the \"DryRun\" firewall backend.");
        println!("      Start with `--firewall iptables` (or nftables) to enforce.");
    }

    // `enrolled_at` is currently only reported at debug level; it is recorded in
    // the keyring for audit purposes.
    crate::log_debug!("'{user}' enrolled at unix time {enrolled_at}");

    Ok(())
}

/// Format a list of ports as a comma-separated string.
///
/// EXPERT: A tiny formatting helper rather than `format!("{:?}", ports)`, which
///         would print `[41231, 58802]` -- the brackets are noise in a card the
///         user is meant to read. Small formatting decisions like this are most
///         of what "user experience" means in a CLI.
/// KID: Write the door numbers in a tidy list with commas.
fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        // `to_string` on a u16 gives its decimal form.
        .map(|p| p.to_string())
        // `join` puts a separator between the items.
        .collect::<Vec<_>>()
        .join(", ")
}

/// Build a single-line enrolment URI a client can parse.
///
/// EXPERT: A URI rather than a bespoke format, because URIs are universally
///         parseable and the `otpauth://` convention (used by every authenticator
///         app) has proven that this works well in practice. Our scheme is
///         `otkp://` and the fields are query parameters.
///
/// We do NOT URL-encode here, and that is a deliberate, documented
///         limitation: user names and hosts in our use case are simple tokens
///         (`alice`, `vps.example.com`). A production version would percent-encode
///         and this comment is the note to do so. Being explicit about the gap is
///         better than a half-correct encoder.
/// KID: One line that says everything: who you are, your handshake, and where to
///      knock. Easy to copy and paste.
fn enrolment_uri(
    user: &str,
    secret_base32: &str,
    server_hint: &str,
    step_seconds: u64,
    spec: &crate::crypto::KnockSpec,
) -> String {
    // The knock ports and open port are *hints* for a human reading the URI; the
    // client re-derives them from the secret, so they are not authoritative.
    // Including them makes the URI self-describing, which is helpful when
    // debugging "why does my client disagree with my server?".
    format!(
        "otkp://{user}?secret={secret}&step={step}&server={server}&knocks={knocks}&open={open}",
        secret = secret_base32,
        step = step_seconds,
        server = server_hint,
        knocks = format_ports(&spec.knock_ports),
        open = spec.open_port,
    )
}

/// Parse an enrolment URI back into its parts.
///
/// EXPERT: The inverse of `enrolment_uri`, and it exists for two reasons: (a) the
///         `knock` command can accept a URI instead of four separate flags, and
///         (b) having both directions lets a test assert the round trip, which
///         catches format drift that a one-directional implementation would miss.
///
/// The parser is deliberately forgiving: it ignores unknown query
///         parameters, so a client written today keeps working against a server
///         that adds a field tomorrow. Forward compatibility for free.
/// KID: Read the one-line card back into its pieces.
pub fn parse_enrolment_uri(uri: &str) -> Result<EnrolmentUri> {
    // Step 1: the scheme and the user name.
    let rest = uri.strip_prefix("otkp://").ok_or_else(|| {
        OtkpError::config(format!(
            "not an otkp enrolment URI (must start with 'otkp://'): {uri}"
        ))
    })?;

    // Split the user name from the query string.
    let (user, query) = rest.split_once('?').ok_or_else(|| {
        OtkpError::config("enrolment URI is missing its '?' query section".to_string())
    })?;

    if user.is_empty() {
        return Err(OtkpError::config("enrolment URI has an empty user name"));
    }

    // Step 2: walk the query parameters, collecting the ones we know.
    let mut secret: Option<String> = None;
    let mut step: Option<u64> = None;
    let mut server: Option<String> = None;

    for pair in query.split('&') {
        // `split_once('=')` gives (key, value). A parameter with no '=' is
        // skipped rather than treated as an error, for the same
        // forward-compatibility reason as above.
        let (key, value) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match key {
            "secret" => secret = Some(value.to_string()),
            "step" => {
                // A malformed step is a real error: the user is clearly trying to
                // specify one and we cannot silently ignore it.
                step = Some(value.parse::<u64>().map_err(|_| {
                    OtkpError::config(format!("enrolment URI has a bad step value '{value}'"))
                })?);
            }
            "server" => server = Some(value.to_string()),
            // Unknown keys are ignored on purpose. See the doc comment.
            _ => {}
        }
    }

    // `secret` is the only mandatory parameter: without it there is nothing to
    // knock with. `server` and `step` have sensible defaults.
    let secret = secret
        .ok_or_else(|| OtkpError::config("enrolment URI has no 'secret' parameter".to_string()))?;

    Ok(EnrolmentUri {
        user: user.to_string(),
        secret,
        step_seconds: step.unwrap_or(crate::DEFAULT_STEP_SECONDS),
        server,
    })
}

/// The parsed contents of an enrolment URI.
///
/// EXPERT: A named struct rather than a tuple, because three of the four fields
///         are `String`/`u64` and a tuple would be trivially mis-ordered at a
///         call site. Named fields cost nothing and eliminate a whole class of
///         silent bug.
/// KID: The pieces of the card, in labelled boxes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentUri {
    /// The user name.
    pub user: String,
    /// The secret, as base32 or hex text.
    pub secret: String,
    /// Seconds per time window.
    pub step_seconds: u64,
    /// The server hint, if the URI carried one.
    pub server: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::crypto::derive_with_hotp;
    use crate::keyring::Keyring;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("otkp-enroll-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// Initialise a directory the way `otkp init` would.
    fn setup(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        let opts = crate::cli::init::test_options(dir.to_str().unwrap());
        crate::cli::init::run(&opts).unwrap();
        dir
    }

    #[test]
    fn enroll_adds_a_user_to_the_keyring() {
        let dir = setup("adds");
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        run(&opts, "alice").unwrap();

        let kr = Keyring::load(&dir.join("keyring.json")).unwrap();
        assert_eq!(kr.len(), 1);
        assert!(kr.get("alice").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_generates_a_distinct_secret_per_user() {
        let dir = setup("distinct");
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        run(&opts, "alice").unwrap();
        run(&opts, "bob").unwrap();

        let kr = Keyring::load(&dir.join("keyring.json")).unwrap();
        let a = kr.get("alice").unwrap().secret.to_base32();
        let b = kr.get("bob").unwrap().secret.to_base32();
        assert_ne!(a, b, "each user must get an independent secret");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_rejects_a_duplicate_user() {
        let dir = setup("duplicate");
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        run(&opts, "alice").unwrap();
        let err = run(&opts, "alice").unwrap_err();
        assert!(err.to_string().contains("already enrolled"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_requires_an_initialised_directory() {
        let dir = temp_dir("uninitialised");
        std::fs::create_dir_all(&dir).unwrap();
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        let err = run(&opts, "alice").unwrap_err();
        assert!(err.to_string().contains("not initialised"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrolment_uri_round_trips() {
        let cfg = ServerConfig::default();
        let secret = crate::secret::MasterSecret::from_bytes([3; 32]);
        let spec = crate::crypto::derive_knock_spec(&secret, "alice", 100, &cfg, None);

        let uri = enrolment_uri(
            "alice",
            &secret.to_base32(),
            "/etc/otkp",
            cfg.step_seconds,
            &spec,
        );

        let parsed = parse_enrolment_uri(&uri).unwrap();
        assert_eq!(parsed.user, "alice");
        assert_eq!(parsed.secret, secret.to_base32());
        assert_eq!(parsed.step_seconds, cfg.step_seconds);
        assert_eq!(parsed.server.as_deref(), Some("/etc/otkp"));
    }

    #[test]
    fn uri_parser_ignores_unknown_parameters() {
        // Forward compatibility: a future server adding `&version=2` must not
        // break today's parser.
        let uri = "otkp://alice?secret=AAAA&step=30&version=2&future=yes";
        let parsed = parse_enrolment_uri(uri).unwrap();
        assert_eq!(parsed.secret, "AAAA");
        assert_eq!(parsed.step_seconds, 30);
    }

    #[test]
    fn uri_parser_rejects_bad_input() {
        assert!(parse_enrolment_uri("http://example.com").is_err());
        assert!(parse_enrolment_uri("otkp://alice").is_err()); // no query
        assert!(parse_enrolment_uri("otkp://?secret=X").is_err()); // no user
        assert!(parse_enrolment_uri("otkp://alice?step=30").is_err()); // no secret
        assert!(parse_enrolment_uri("otkp://alice?secret=X&step=soon").is_err());
    }

    #[test]
    fn uri_parser_applies_default_step() {
        let parsed = parse_enrolment_uri("otkp://alice?secret=AAAA").unwrap();
        assert_eq!(parsed.step_seconds, crate::DEFAULT_STEP_SECONDS);
        assert!(parsed.server.is_none());
    }

    #[test]
    fn format_ports_is_readable() {
        assert_eq!(format_ports(&[41231, 58802, 19904]), "41231, 58802, 19904");
        assert_eq!(format_ports(&[]), "");
        assert_eq!(format_ports(&[1]), "1");
    }

    #[test]
    fn derived_spec_matches_the_daemon_path() {
        // The values `enroll` prints must be exactly what the daemon will expect.
        // This is the single most important invariant of the command, because a
        // mismatch would look like "the client is broken" to the user.
        let dir = setup("matches");
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        run(&opts, "alice").unwrap();

        let cfg: ServerConfig =
            serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap())
                .unwrap();
        let kr = Keyring::load(&dir.join("keyring.json")).unwrap();

        // Derive through the keyring helper (what `enroll` uses)...
        let now = unix_now();
        let step = time_step(now, cfg.step_seconds);
        let (via_helper, code) = kr.spec_and_hotp_for("alice", step, &cfg, None).unwrap();

        // ...and derive directly from the stored secret (what the engine does).
        let enrollment = kr.get("alice").unwrap();
        let (direct, direct_code) = derive_with_hotp(&enrollment.secret, "alice", step, &cfg, None);

        assert_eq!(via_helper, direct);
        assert_eq!(code, direct_code);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
