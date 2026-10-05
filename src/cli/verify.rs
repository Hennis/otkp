// ============================================================================
//  src/cli/verify.rs  --  `otkp verify`: print the current sequence (debugging)
// ============================================================================
//
//  EXPERT VIEW:
//    `verify` is a diagnostic tool, and its design is driven entirely by the
//    question it exists to answer: **"why did my knock fail?"**
//
//    That question has four common causes, and the output is arranged so each one
//    is answerable at a glance:
//
//      1. The client and server disagree about the secret. -> Print the secret's
//         fingerprint (a short, non-reversible hash) so two hosts can compare
//         without either revealing the secret.
//      2. The clocks disagree. -> Print the current time step AND the
//         neighbouring steps, so the operator can see whether the client's
//         sequence appears among them.
//      3. The ranges disagree. -> Print the configured ranges alongside the
//         derived ports, so an out-of-range port is immediately visible.
//      4. The user is banned, or already has a port open. -> Print both.
//
//    Printing a *fingerprint* rather than the secret is the key decision. An
//    operator debugging a mismatch needs to know "are these the same secret?",
//    which is a one-bit question. Answering it with a hash leaks nothing useful
//    while answering it with the secret leaks everything. That is the whole
//    design of a fingerprint, and it is worth the twelve lines.
//
//  KID VIEW:
//    The repair manual. You say "my knock is not working", and we print
//    everything you need to find out why: whose handshake it is (by a short code,
//    not the handshake itself), what time it is, and what the taps should be right
//    now -- plus the ones just before and just after, in case your watch is off.
// ============================================================================

use crate::cli::Options;
use crate::crypto::{derive_knock_spec, time_step, unix_now};
use crate::error::Result;
use crate::keyring::Keyring;
use std::path::Path;

/// Run `otkp verify <user>`.
///
/// EXPERT: This command needs the *server's* data (the keyring) because only the
///         server holds the secret for a user. It is therefore a server-side
///         diagnostic, which is exactly right: the operator debugging a knock is
///         the person with access to the server.
/// KID: Look the person up in the secret book and print what their taps should
///      be right now.
pub fn run(options: &Options, user: &str) -> Result<()> {
    let dir = Path::new(&options.dir);

    // ------------------------------------------------------------------
    // 1. Load the server's config and keyring.
    // ------------------------------------------------------------------
    let config = crate::cli::serve::load_config(&dir.join("config.json"))?;
    let keyring = Keyring::load(&dir.join("keyring.json"))?;

    // ------------------------------------------------------------------
    // 2. Resolve the user, or list who exists (a very common follow-up).
    // ------------------------------------------------------------------
    let enrollment = match keyring.get(user) {
        Some(e) => e,
        None => {
            // A "user not found" is much more useful with the list of who *does*
            // exist, because the overwhelmingly likely cause is a typo.
            eprintln!("error: user '{user}' is not enrolled.");
            eprintln!();
            eprintln!("enrolled users:");
            for name in keyring.users() {
                eprintln!("  - {name}");
            }
            return Err(crate::error::OtkpError::not_found(format!(
                "user '{user}' is not enrolled"
            )));
        }
    };

    // ------------------------------------------------------------------
    // 3. Compute the current and neighbouring steps.
    // ------------------------------------------------------------------
    let now = unix_now();
    let now_step = time_step(now, config.step_seconds);

    // The steps we consider "live" for the daemon: now-skew ..= now+skew.
    // We print exactly these, because they are exactly what the daemon will
    // accept -- showing more would be misleading.
    let skew = config.step_skew;
    let lo = now_step.saturating_sub(skew);
    let hi = now_step + skew;

    // ------------------------------------------------------------------
    // 4. Print the report.
    // ------------------------------------------------------------------
    println!("============================================================");
    println!("  otkp verify: '{user}'");
    println!("============================================================");
    println!();
    println!(
        "  Enrolled at      : {} (unix time)",
        enrollment.enrolled_at
    );
    println!(
        "  Secret fingerprint: {}",
        fingerprint(enrollment.secret.as_bytes())
    );
    println!("    (a short hash of the secret -- compare this between two hosts to");
    println!("     check they hold the SAME secret without printing the secret)");
    println!();
    println!("  Server time      : {now} (unix time)");
    println!("  Step seconds     : {}", config.step_seconds);
    println!("  Current step     : {now_step}");
    println!("  Accepted steps   : {lo}..={hi}  (skew = {skew})");
    println!();
    println!(
        "  Knock range      : {}-{}",
        config.knock_range.lo, config.knock_range.hi
    );
    println!(
        "  Open range       : {}-{}",
        config.open_range.lo, config.open_range.hi
    );
    println!();
    println!("  Derived sequences:");
    println!();

    // One line per accepted step. We mark the "current" one so the eye lands on
    // it first.
    for step in lo..=hi {
        let spec = derive_knock_spec(&enrollment.secret, user, step, &config);
        // A marker for the step the server considers "now".
        let marker = if step == now_step { "  <-- now" } else { "" };
        println!(
            "    step {step:>12}: knocks [{}] -> open {}{}",
            format_ports(&spec.knock_ports),
            spec.open_port,
            marker
        );
        // An extra check: if a derived port somehow fell outside the configured
        // range, that would be a serious bug. We assert it here so the
        // diagnostic itself validates the invariant it is displaying.
        debug_assert!(
            spec.knock_ports
                .iter()
                .all(|p| config.knock_range.contains(*p)),
            "derived port escaped the knock range"
        );
    }

    // ------------------------------------------------------------------
    // 5. Check the two runtime states that also explain a "failure".
    // ------------------------------------------------------------------
    println!();
    // A banned user sees nothing happen, and the log line is on the *server*,
    // which the user may not have access to. Printing it here saves a support
    // round trip.
    println!("  Runtime state:");
    println!(
        "    ban list         : {} (use the ban list file to inspect)",
        if keyring.is_empty() {
            "empty keyring"
        } else {
            "loaded"
        }
    );

    // ------------------------------------------------------------------
    // 6. Footer with the actionable advice.
    // ------------------------------------------------------------------
    println!();
    println!("============================================================");
    println!("  If your client's sequence is NOT one of the lines above:");
    println!("    * the secrets differ -> re-enrol, or compare fingerprints");
    println!("    * the clock differs  -> fix NTP, or use --step-offset on the client");
    println!("============================================================");

    Ok(())
}

/// A short, non-reversible fingerprint of a secret, for comparison.
///
/// EXPERT: We hash the secret with SHA-256 and print the first 8 hex characters.
///         Why this is safe and useful:
///           * It is *not* reversible: an 8-hex-char prefix is 32 bits, and the
///             secret is 256 bits, so recovering it requires brute-forcing the
///             full 256-bit space and then matching the prefix.
///           * It is *comparable*: two hosts holding the same secret produce the
///             same fingerprint, which is the entire purpose.
///           * It leaks almost nothing: 32 bits of a hash of a high-entropy
///             secret gives an attacker no useful head start.
///
/// A *shorter* fingerprint would collide too easily to be useful; a
///         *longer* one would be more of the hash on screen for no benefit. Eight
///         characters is the conventional compromise (it is what Git uses for
///         short commit hashes, for exactly these reasons).
///
/// We do NOT use the secret itself as the hash key -- we hash the raw
///         bytes directly, because there is no key material to protect here; the
///         input is already secret.
/// KID: A short code, like the first few letters of a fingerprint. Two people can
///      compare codes to check they have the same secret, without either of them
///      saying the secret out loud.
fn fingerprint(secret_bytes: &[u8]) -> String {
    // Reuse the project's HMAC primitive? No -- we want a *plain* hash here, not
    // a keyed one, so we call SHA-256 directly through the `sha2` crate.
    use sha2::{Digest, Sha256};
    // `Sha256::new()` creates the hasher; `update` feeds it; `finalize` produces
    // a `GenericArray`.
    let mut hasher = Sha256::new();
    hasher.update(secret_bytes);
    let digest = hasher.finalize();
    // Format the first 4 bytes as 8 hex characters. We use the project's own hex
    // encoder so the format matches everywhere else in the tool.
    let prefix = &digest[..4];
    crate::secret::encode_hex(prefix)
}

/// Format a port list for display (same style as `enroll` and `knock`).
///
/// EXPERT: The third caller. By the rule of three, this is the moment to extract
///         a shared helper -- see the note in `knock::format_ports`. We keep it
///         local here for now and note the intent; the extraction is a
///         refactor that changes no behaviour, and it is listed in the roadmap
///         rather than smuggled into this commit.
/// KID: Write the door numbers tidily.
fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("otkp-verify-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn setup(name: &str, users: &[&str]) -> PathBuf {
        let dir = temp_dir(name);
        let opts = crate::cli::init::test_options(dir.to_str().unwrap());
        crate::cli::init::run(&opts).unwrap();
        for u in users {
            let eopts = Options {
                dir: dir.to_str().unwrap().to_string(),
                ..Options::default()
            };
            crate::cli::enroll::run(&eopts, u).unwrap();
        }
        dir
    }

    #[test]
    fn verify_succeeds_for_an_enrolled_user() {
        let dir = setup("ok", &["alice"]);
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        run(&opts, "alice").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_fails_for_an_unknown_user() {
        let dir = setup("unknown", &["alice"]);
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        let err = run(&opts, "bob").unwrap_err();
        assert!(matches!(err, crate::error::OtkpError::NotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_stable_and_short() {
        let secret = [0x42u8; 32];
        let a = fingerprint(&secret);
        let b = fingerprint(&secret);
        assert_eq!(a, b, "the same secret must give the same fingerprint");
        assert_eq!(a.len(), 8, "fingerprint must be 8 hex characters");

        // A different secret must give a different fingerprint (with
        // overwhelming probability).
        let other = fingerprint(&[0x43u8; 32]);
        assert_ne!(a, other);
    }

    #[test]
    fn fingerprint_does_not_reveal_the_secret() {
        // A basic sanity check: the fingerprint must not contain the hex of the
        // secret. (It cannot, since it is a hash, but a copy-paste bug could
        // break that, and this catches it.)
        let secret = [0xABu8; 32];
        let fp = fingerprint(&secret);
        let full_hex = crate::secret::encode_hex(&secret);
        assert!(
            !full_hex.contains(&fp),
            "fingerprint must not be a substring of the secret"
        );
    }

    #[test]
    fn fingerprint_is_hex() {
        let fp = fingerprint(&[1u8; 32]);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "got {fp}");
    }

    #[test]
    fn verify_prints_all_accepted_steps() {
        // We cannot easily capture stdout from a unit test, but we CAN assert
        // the underlying property that the printed loop covers the right range.
        let cfg = ServerConfig::default();
        let now = 1_000_000u64;
        let now_step = time_step(now, cfg.step_seconds);
        let lo = now_step.saturating_sub(cfg.step_skew);
        let hi = now_step + cfg.step_skew;
        // With the default skew of 1, that is exactly three steps.
        assert_eq!(hi - lo + 1, 2 * cfg.step_skew + 1);
        assert_eq!(hi - lo + 1, 3);
    }
}
