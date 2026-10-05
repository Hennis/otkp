// ============================================================================
//  src/cli/knock.rs  --  `otkp knock`: the client side
// ============================================================================
//
//  EXPERT VIEW:
//    The client is the smallest part of the system, and that is a compliment to
//    the protocol's design: because both sides derive the sequence from a shared
//    secret and the clock, the client needs no handshake, no server query, and no
//    state. It is:
//
//        parse inputs -> derive the spec -> send the packets -> tell the user
//        which port to connect to
//
//    There is exactly one piece of cleverness, and it is in service of
//    robustness: the `--step-offset` flag. A client whose clock is wrong by more
//    than the server's `step_skew` will derive a sequence the server is not
//    looking for, and the failure mode is a *ban* -- which is a harsh punishment
//    for a wrong clock. So we give the user a way to say "try the neighbouring
//    window" explicitly, and we document it as the first thing to try when a
//    knock mysteriously fails.
//
//    Note what the client deliberately does NOT do: it does not verify that the
//    knock succeeded. It cannot -- the server sends no acknowledgement, by
//    design (an acknowledgement would be an oracle an attacker could probe). The
//    client's job ends when the packets are on the wire, and the user's next step
//    (connecting to the opened port) is the real test. We say so in the output
//    rather than pretending we know more than we do.
//
//  KID VIEW:
//    Knock on the doors, then tell the person "you now have thirty seconds to
//    walk in through door number 27488". We cannot hear whether it worked, so we
//    do not pretend to -- we just tell them to go and try.
// ============================================================================

use crate::cli::Options;
use crate::crypto::{derive_knock_spec, time_step, unix_now, Mode};
use crate::error::{OtkpError, Result};
use crate::net::{send_knocks, SendTarget};
use crate::secret::MasterSecret;

/// The default port a client knocks on if none is given.
///
/// EXPERT: Matches `ServerConfig::default().listen_addr.port()`. A shared
///         constant would be better, but the two live in different modules and
///         the coupling is worth avoiding; the integration tests assert they
///         agree, which is the right place to catch drift.
/// KID: The usual door for the note-slips.
const DEFAULT_LISTEN_PORT: u16 = 62201;

/// Run `otkp knock`.
///
/// EXPERT: The straight-line shape is the point. Every step is a small, testable
///         transformation, and the function reads as the protocol description.
/// KID: Read the card, work out the taps, tap, then tell the person what to do.
pub fn run(options: &Options) -> Result<()> {
    // ------------------------------------------------------------------
    // 1. Gather the inputs, accepting either an enrolment URI or explicit flags.
    // ------------------------------------------------------------------
    let client = resolve_client_config(options)?;

    // ------------------------------------------------------------------
    // 2. Parse the secret into a zeroising container.
    // ------------------------------------------------------------------
    // EXPERT: From here on the secret is a `MasterSecret`, which wipes itself on
    //         drop. The plaintext `String` from argv is still in memory (we
    //         cannot scrub argv), which is a documented limitation of passing a
    //         secret on the command line. The README recommends an environment
    //         variable or a file for that reason, and the roadmap has OS keychain
    //         integration.
    let secret = MasterSecret::from_text(&client.secret)?;

    // ------------------------------------------------------------------
    // 3. Determine the time step, honouring --step-offset.
    // ------------------------------------------------------------------
    let now = unix_now();
    let base_step = time_step(now, client.step_seconds);

    // Apply the offset, clamping at zero so we cannot underflow. An offset that
    // would go before the epoch is meaningless, and clamping is the safe
    // interpretation.
    let step = if client.step_offset >= 0 {
        base_step.saturating_add(client.step_offset as u64)
    } else {
        // `unsigned_abs` on i64 gives a u64 without the overflow trap that
        // `-i64::MIN` would cause.
        base_step.saturating_sub(client.step_offset.unsigned_abs())
    };

    // ------------------------------------------------------------------
    // 4. Derive the sequence.
    // ------------------------------------------------------------------
    // We need a `ServerConfig` for its range and count settings. The client does
    // not have the server's config file, so it uses the *default* ranges, which
    // are what the server uses unless the operator changed them. This is the one
    // place where the client must know the server's policy, and it is why the
    // README tells operators to keep the default ranges unless they also
    // distribute a client config. A future version will carry the ranges in the
    // enrolment URI; the parser already tolerates the extra parameters.
    let cfg = crate::config::ServerConfig::default();
    let spec = derive_knock_spec(&secret, &client.user, step, &cfg);

    // ------------------------------------------------------------------
    // 5. Report what we are about to do.
    // ------------------------------------------------------------------
    // This goes to stdout: it is the command's output, and a user wants to read
    // it (and possibly script the "connect to port N" line).
    println!("[otkp] user          : {}", client.user);
    println!(
        "[otkp] time step     : {} ({} s window, offset {:+})",
        step, client.step_seconds, client.step_offset
    );
    println!("[otkp] derived knocks: {}", format_ports(&spec.knock_ports));
    println!("[otkp] will open port: {}", spec.open_port);
    println!(
        "[otkp] sending {} knock(s) to {}:{} ({})",
        spec.knock_ports.len(),
        client.server,
        client.listen_port,
        if client.raw_mode { "raw" } else { "udp" }
    );

    // ------------------------------------------------------------------
    // 6. Send.
    // ------------------------------------------------------------------
    let target = SendTarget {
        host: client.server.clone(),
        listen_port: client.listen_port,
        raw_mode: client.raw_mode,
        inter_knock_delay_ms: client.inter_knock_delay_ms,
    };

    let sent = send_knocks(&target, &spec)?;
    crate::log_info!("sent {sent} knock(s)");

    // ------------------------------------------------------------------
    // 7. Tell the user what to do next, honestly.
    // ------------------------------------------------------------------
    println!();
    println!(
        "[otkp] done. You now have about {}s to connect to {}:{}",
        cfg.open_ttl_seconds, client.server, spec.open_port
    );
    println!("[otkp] (the server sends no acknowledgement -- connecting is the test)");
    println!();
    println!(
        "[otkp] if the connection is refused, your clock may be off by more than {}s;",
        cfg.step_seconds
    );
    println!("[otkp] retry with --step-offset -1 or --step-offset 1.");

    Ok(())
}

/// The client's resolved configuration.
///
/// EXPERT: A private struct that exists because the CLI accepts two *shapes* of
///         input (an enrolment URI, or five separate flags) and the rest of the
///         function should not have to care which. Resolving the two shapes into
///         one normalised form at the boundary is the "parse, don't validate"
///         idea again: after `resolve_client_config`, the code below deals with
///         exactly one representation.
/// KID: Turn "here is a card" or "here are five answers" into one tidy list of
///      facts.
#[derive(Debug)]
struct ResolvedClient {
    /// The server's host.
    server: String,
    /// The listener port to send knocks to.
    listen_port: u16,
    /// The user name.
    user: String,
    /// The secret text.
    secret: String,
    /// Seconds per window.
    step_seconds: u64,
    /// Try a neighbouring window.
    step_offset: i64,
    /// Send to real ports rather than to the listener.
    raw_mode: bool,
    /// Milliseconds between knocks.
    inter_knock_delay_ms: u64,
}

/// Build a `ResolvedClient` from the parsed options.
///
/// EXPERT: The precedence rules are explicit and documented:
///           * If `--secret` looks like an `otkp://` URI, parse it and use the
///             URI's fields as defaults.
///           * Explicit flags always override URI values, so a user can paste a
///             URI and then correct one field.
///           * Missing required values produce an error naming the missing flag.
///
/// "Explicit flag beats URI" is the rule that makes the feature pleasant
///         rather than surprising; stating it here means a future change cannot
///         silently invert it.
/// KID: If the person handed you a card, read it. Then let anything they said out
///      loud override what the card says. If something is still missing, ask for
///      it clearly.
fn resolve_client_config(options: &Options) -> Result<ResolvedClient> {
    // Start from the CLI flags.
    let mut user = options.user.clone();
    let mut secret = options.secret.clone();
    let mut server = options.server.clone();
    let mut step_seconds = options.step_seconds;
    let listen_port = options.port;

    // If the "secret" is actually a URI, unpack it first.
    if let Some(s) = secret.as_deref() {
        if s.starts_with("otkp://") {
            let parsed = crate::cli::enroll::parse_enrolment_uri(s)?;
            // The URI's values fill in anything the flags did not provide.
            if user.is_none() {
                user = Some(parsed.user);
            }
            secret = Some(parsed.secret);
            if server.is_none() {
                // The URI's "server" field is free-form (we print a directory
                // path there in `enroll`), so we only adopt it if it looks like a
                // host. This is a heuristic, and a documented one.
                if let Some(hint) = parsed.server {
                    if !hint.contains('/') {
                        server = Some(hint);
                    }
                }
            }
            if step_seconds.is_none() {
                step_seconds = Some(parsed.step_seconds);
            }
        }
    }

    // Now require the three fields with no sensible default.
    let user = user.ok_or_else(|| {
        OtkpError::config("missing --user (or an enrolment URI with a user name)")
    })?;
    let secret = secret.ok_or_else(|| {
        OtkpError::config("missing --secret (or an enrolment URI containing one)")
    })?;
    let server =
        server.ok_or_else(|| OtkpError::config("missing --server (the host to knock on)"))?;

    // Transport mode.
    let raw_mode = match options.mode.as_deref() {
        None => false, // udp is the default: it needs no privileges
        Some(m) => Mode::parse(m)? == Mode::Raw,
    };

    // Validate the step offset: anything beyond ±2 is almost certainly a typo,
    // and allowing a wild value would just produce a confusing ban.
    if options.step_offset.abs() > 2 {
        return Err(OtkpError::config(format!(
            "--step-offset {} is implausible; expected -2..=2. \
             If your clock is that far off, fix the clock.",
            options.step_offset
        )));
    }

    Ok(ResolvedClient {
        server,
        listen_port: listen_port.unwrap_or(DEFAULT_LISTEN_PORT),
        user,
        secret,
        step_seconds: step_seconds.unwrap_or(crate::DEFAULT_STEP_SECONDS),
        step_offset: options.step_offset,
        raw_mode,
        // Default matches `ServerConfig::default().inter_knock_delay_ms`.
        inter_knock_delay_ms: options.inter_knock_delay_ms.unwrap_or(80),
    })
}

/// Format a port list for display (same style as `enroll`).
///
/// EXPERT: Duplicated from `enroll` rather than shared. Two three-line functions
///         with identical bodies is a smell, but the alternatives (a shared
///         `util` module, or making it `pub` in `enroll`) both add coupling for
///         less than a line of savings. When a third caller appears, it moves to
///         a utility module -- that is the rule of three, applied honestly.
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
    use crate::crypto::KnockSpec;

    /// Build an `Options` with only the fields a test cares about set.
    fn opts() -> Options {
        Options::default()
    }

    #[test]
    fn resolves_explicit_flags() {
        let mut o = opts();
        o.user = Some("alice".into());
        o.secret = Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into());
        o.server = Some("vps.example.com".into());
        o.port = Some(62201);

        let r = resolve_client_config(&o).unwrap();
        assert_eq!(r.user, "alice");
        assert_eq!(r.server, "vps.example.com");
        assert_eq!(r.listen_port, 62201);
        assert!(!r.raw_mode);
        assert_eq!(r.step_seconds, crate::DEFAULT_STEP_SECONDS);
    }

    #[test]
    fn resolves_an_enrolment_uri() {
        let uri = "otkp://alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                   &step=30&server=vps.example.com";
        let mut o = opts();
        o.secret = Some(uri.to_string());

        let r = resolve_client_config(&o).unwrap();
        assert_eq!(r.user, "alice");
        assert_eq!(r.server, "vps.example.com");
        assert_eq!(r.step_seconds, 30);
    }

    #[test]
    fn explicit_flags_override_the_uri() {
        let uri = "otkp://alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                   &step=30&server=old.example.com";
        let mut o = opts();
        o.secret = Some(uri.to_string());
        // Explicitly override the user and the server.
        o.user = Some("bob".into());
        o.server = Some("new.example.com".into());

        let r = resolve_client_config(&o).unwrap();
        assert_eq!(r.user, "bob");
        assert_eq!(r.server, "new.example.com");
    }

    #[test]
    fn uri_server_hint_that_is_a_path_is_ignored() {
        // `enroll` puts the *directory* in the server field, which is not a
        // hostname. We must not try to knock on "/etc/otkp".
        let uri = "otkp://alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\
                   &server=/etc/otkp";
        let mut o = opts();
        o.secret = Some(uri.to_string());
        // No --server, so the heuristic should leave `server` unset and the
        // resolver should then complain about the missing host.
        let err = resolve_client_config(&o).unwrap_err();
        assert!(err.to_string().contains("missing --server"));
    }

    #[test]
    fn missing_required_fields_are_named() {
        let mut o = opts();
        o.server = Some("host".into());
        let err = resolve_client_config(&o).unwrap_err();
        assert!(err.to_string().contains("--user"));

        let mut o = opts();
        o.user = Some("alice".into());
        o.server = Some("host".into());
        let err = resolve_client_config(&o).unwrap_err();
        assert!(err.to_string().contains("--secret"));

        let mut o = opts();
        o.user = Some("alice".into());
        o.secret = Some("AAAA".into());
        let err = resolve_client_config(&o).unwrap_err();
        assert!(err.to_string().contains("--server"));
    }

    #[test]
    fn mode_flag_selects_raw() {
        let mut o = opts();
        o.user = Some("alice".into());
        o.secret = Some("AAAA".into());
        o.server = Some("host".into());
        o.mode = Some("raw".into());
        assert!(resolve_client_config(&o).unwrap().raw_mode);

        o.mode = Some("udp".into());
        assert!(!resolve_client_config(&o).unwrap().raw_mode);

        o.mode = Some("carrier-pigeon".into());
        assert!(resolve_client_config(&o).is_err());
    }

    #[test]
    fn implausible_step_offset_is_rejected() {
        let mut o = opts();
        o.user = Some("alice".into());
        o.secret = Some("AAAA".into());
        o.server = Some("host".into());
        o.step_offset = 99;
        let err = resolve_client_config(&o).unwrap_err();
        assert!(err.to_string().contains("implausible"));

        // The plausible range must be accepted.
        o.step_offset = -2;
        assert!(resolve_client_config(&o).is_ok());
        o.step_offset = 2;
        assert!(resolve_client_config(&o).is_ok());
    }

    #[test]
    fn default_listen_port_matches_server_default() {
        // This is the drift guard promised in `DEFAULT_LISTEN_PORT`'s docs.
        let cfg = crate::config::ServerConfig::default();
        assert_eq!(cfg.listen_addr.port(), DEFAULT_LISTEN_PORT);
    }

    #[test]
    fn default_inter_knock_delay_matches_server_default() {
        let cfg = crate::config::ServerConfig::default();
        let mut o = opts();
        o.user = Some("alice".into());
        o.secret = Some("AAAA".into());
        o.server = Some("host".into());
        let r = resolve_client_config(&o).unwrap();
        assert_eq!(r.inter_knock_delay_ms, cfg.inter_knock_delay_ms);
    }

    #[test]
    fn format_ports_matches_enroll_style() {
        assert_eq!(format_ports(&[1, 2, 3]), "1, 2, 3");
    }

    #[test]
    fn negative_step_offset_saturates_at_zero() {
        // Deriving for step 0 when now is tiny must not underflow. We test the
        // arithmetic directly because `run` touches the network.
        let base_step = 0u64;
        let offset: i64 = -1;
        let step = if offset >= 0 {
            base_step.saturating_add(offset as u64)
        } else {
            base_step.saturating_sub(offset.unsigned_abs())
        };
        assert_eq!(step, 0, "must clamp at 0, not wrap to u64::MAX");
    }

    #[test]
    fn spec_derivation_is_shared_with_the_library() {
        // A guard that the client and the library derive identically. If this
        // ever fails, the client and server have diverged, which is the worst
        // possible bug in the project.
        let cfg = crate::config::ServerConfig::default();
        let secret = MasterSecret::from_bytes([9; 32]);
        let spec: KnockSpec = derive_knock_spec(&secret, "alice", 12345, &cfg);
        let via_keyring_helper = {
            let json = format!(
                r#"{{"entries":{{"alice":{{"user":"alice","secret":"{}","enrolled_at":0}}}}}}"#,
                secret.to_base32()
            );
            let kr: crate::keyring::Keyring = serde_json::from_str(&json).unwrap();
            kr.spec_for("alice", 12345, &cfg).unwrap()
        };
        assert_eq!(spec, via_keyring_helper);
    }
}
