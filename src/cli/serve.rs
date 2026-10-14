// ============================================================================
//  src/cli/serve.rs  --  `otkp serve`: start the daemon
// ============================================================================
//
//  EXPERT VIEW:
//    This command is a *composition root*: the one place in the program where
//    concrete implementations are chosen and wired together. Everything below it
//    works against traits and does not know which implementations it has.
//
//    The startup sequence is deliberately explicit and ordered, because several
//    steps can fail in ways an operator must understand:
//
//      1. Load and validate the config. Overlay the CLI flags on top, so
//         `--ban-threshold` beats the file. Flags win because they are the more
//         specific, more recent expression of intent.
//      2. Load the keyring. Refuse to start if it is empty -- a daemon that can
//         authenticate nobody is a misconfiguration, and failing loudly at
//         startup is far better than silently ignoring every knock.
//      3. Load the ban list from disk.
//      4. Build the engine.
//      5. Build the firewall backend and the knock source.
//      6. Restore persisted bans into the firewall (see `Daemon::restore_bans`
//         for why this matters).
//      7. Install signal handlers, then run.
//
//    Step 6 is easy to forget and important: the previous shutdown removed all
//    our firewall rules, so without re-applying the persisted bans, a daemon
//    restart would hand every banned attacker a fresh set of attempts.
//
//  KID VIEW:
//    Open the club for business. Read the rulebook, check the guest list is not
//    blank, get the naughty list out of the drawer, put the names from the
//    naughty list back on the door, then sit down and start listening for taps.
// ============================================================================

use crate::banlist::BanList;
use crate::cli::Options;
use crate::config::{FirewallConfig, ServerConfig};
use crate::crypto::Mode;
use crate::daemon::Daemon;
use crate::engine::{Engine, SystemClock};
use crate::error::{OtkpError, Result};
use crate::firewall;
use crate::keyring::Keyring;
use crate::net::{KnockSource, RawKnockSource, UdpKnockSource};
use std::path::Path;

/// Run `otkp serve`.
///
/// EXPERT: The `Result` returned here is only for *startup* failures. Once
///         `daemon.run()` is called, every runtime error is handled inside the
///         loop (see `daemon.rs`), so the only way this function returns is a
///         clean shutdown. That is a deliberate separation: startup failures are
///         fatal and informative; runtime failures are recoverable and logged.
/// KID: Set up the club, then stay open until someone says stop.
pub fn run(options: &Options) -> Result<()> {
    let dir = Path::new(&options.dir);

    // ------------------------------------------------------------------
    // 1. Load and validate the config, then apply the CLI overrides.
    // ------------------------------------------------------------------
    let config_path = dir.join("config.json");
    let mut config = load_config(&config_path)?;
    apply_overrides(&mut config, options)?;

    // Level 2 needs somewhere to write. If the operator asked for level 2 but
    // named no path, default it into the data directory rather than failing —
    // "audit" without a location is a decision we can make for them, unlike
    // *where a security log lives* in a managed deployment, which they can still
    // override with --audit-log.
    if config.security_level >= crate::config::SecurityLevel::Auditable
        && config.audit_log_path.is_none()
    {
        let default_path = dir.join("audit.jsonl");
        crate::log_info!(
            "security level 2 with no audit_log_path; defaulting to {}",
            default_path.display()
        );
        config.audit_log_path = Some(default_path);
    }
    // Re-validate AFTER the overrides: an override could break an invariant
    // (e.g. `--open-ttl 0`, or a ban threshold of 0), and catching that here
    // with a clear message beats a confusing runtime behaviour.
    config.validate()?;

    // ------------------------------------------------------------------
    // 2. Load the keyring; refuse to start with nobody enrolled.
    // ------------------------------------------------------------------
    let keyring_path = dir.join("keyring.json");
    let keyring = Keyring::load(&keyring_path)?;
    if keyring.is_empty() {
        return Err(OtkpError::config(format!(
            "{} contains no enrolled users; the daemon would authenticate nobody. \
             Run `otkp enroll <user> --dir {}` first.",
            keyring_path.display(),
            dir.display()
        )));
    }
    crate::log_info!("loaded {} enrolled user(s)", keyring.len());

    // Report which rung we are on, what it buys, what it costs, and what the next
    // rung would buy. A ratchet nobody knows how to climb is a ratchet nobody
    // climbs, so the tool advertises the next step at the moment the operator is
    // looking at the output.
    let level = config.security_level;
    crate::log_info!(
        "security level {} ({}) — buys: {}",
        level.number(),
        level.name(),
        level.buys()
    );
    if level > crate::config::SecurityLevel::Basic {
        crate::log_info!("security level cost: {}", level.costs());
    }
    match config.next_security_level() {
        Some(next) => crate::log_info!(
            "next rung: level {} ({}) — would buy: {} | would cost: {}",
            next.number(),
            next.name(),
            next.buys(),
            next.costs()
        ),
        None => crate::log_info!("at the top rung ({})", level.name()),
    }
    match (
        &config.audit_log_path,
        level >= crate::config::SecurityLevel::Auditable,
    ) {
        (Some(p), true) => crate::log_info!("audit stream: {}", p.display()),
        (None, true) => crate::log_warn!(
            "security level 2 is set but no audit_log_path is configured; \
             the audit stream is DISABLED"
        ),
        _ => {}
    }

    // Report the replay posture plainly. An operator who does not know binding is
    // off cannot make an informed decision about it.
    if config.bind_to_source_ip {
        crate::log_info!(
            "source-IP binding is ON: sequences are bound to the observed address \
             (replay from another address will not match)"
        );
    } else {
        crate::log_warn!(
            "source-IP binding is OFF: a captured sequence can be replayed from any \
             address within the same time window. Set \"bind_to_source_ip\": true to \
             close this (note: this breaks NAT and mobility)."
        );
    }

    // ------------------------------------------------------------------
    // 3. Load the ban list (missing file is fine; it is the normal first run).
    // ------------------------------------------------------------------
    let banlist_path = config
        .banlist_path
        .clone()
        // `unwrap_or_else` computes the default lazily, only when needed.
        .unwrap_or_else(|| dir.join("banlist.json"));
    let banlist = BanList::load(&banlist_path)?;
    crate::log_info!(
        "loaded {} persisted ban(s) from {}",
        banlist.raw_len(),
        banlist_path.display()
    );

    // ------------------------------------------------------------------
    // 4. Build the engine.
    // ------------------------------------------------------------------
    let engine = Engine::new(keyring, config.clone(), banlist);

    // ------------------------------------------------------------------
    // 5. Build the firewall backend.
    // ------------------------------------------------------------------
    let firewall = firewall::build(&config.firewall);
    // Warn loudly about dry-run: an operator who thinks they are protected but
    // is not is in the worst possible state.
    if matches!(config.firewall, FirewallConfig::DryRun) {
        crate::log_warn!(
            "firewall backend is 'dry-run': rules will be LOGGED but NOT APPLIED. \
             Pass --firewall iptables (or nftables) to enforce."
        );
    } else {
        crate::log_info!("firewall backend: {}", firewall.name());
    }

    // ------------------------------------------------------------------
    // 6. Build the knock source.
    // ------------------------------------------------------------------
    // `--source` on the command line wins; otherwise the client-facing default
    // is UDP, because raw needs privileges. Note the *config file* has no
    // "source" field: the choice is a property of how the daemon is launched
    // (and what privileges it has), not of the security policy, so it belongs in
    // the command line. That is a judgement call, and worth stating.
    let source_mode = match options.source.as_deref() {
        Some(s) => Mode::parse(s)?,
        None => Mode::Udp,
    };

    let source: Box<dyn KnockSource> = match source_mode {
        Mode::Udp => {
            crate::log_info!("listening for knocks on {} (udp mode)", config.listen_addr);
            Box::new(UdpKnockSource::bind(config.listen_addr)?)
        }
        Mode::Raw => {
            crate::log_info!(
                "sniffing for knocks on every interface (raw mode; needs CAP_NET_RAW)"
            );
            // Report the expected knock range so the operator can see at a
            // glance that the daemon and their client agree.
            crate::log_info!(
                "knock range: {}-{}, open range: {}-{}",
                config.knock_range.lo,
                config.knock_range.hi,
                config.open_range.lo,
                config.open_range.hi
            );
            Box::new(RawKnockSource::bind()?)
        }
    };

    // ------------------------------------------------------------------
    // 7. Assemble the daemon.
    // ------------------------------------------------------------------
    let audit = crate::audit::AuditLog::new(config.audit_log_path.clone());
    let mut daemon = Daemon::with_audit(engine, firewall, source, Box::new(SystemClock), audit);

    // ------------------------------------------------------------------
    // 8. Re-apply persisted bans to the firewall.
    // ------------------------------------------------------------------
    // Done before installing signal handlers so that a failure here is a startup
    // failure the operator sees, not a mid-run surprise.
    daemon.restore_bans()?;

    // ------------------------------------------------------------------
    // 9. Install signal handlers and run.
    // ------------------------------------------------------------------
    crate::daemon::install_signal_handlers();
    // Clear any stale flag (relevant if a future version restarts the daemon
    // in-process; harmless otherwise, and it makes the intent explicit).
    crate::daemon::clear_shutdown();

    // `--max-iterations` exists for the integration tests and for a bounded
    // smoke run: it steps the loop a fixed number of times and then shuts down.
    // We expose it in the CLI rather than behind `#[cfg(test)]` because a
    // bounded run is genuinely useful in a container's health check.
    if let Some(limit) = options.max_iterations {
        crate::log_info!("running for at most {limit} loop iteration(s), then exiting");
        let mut processed = 0usize;
        for _ in 0..limit {
            // Stop early if a signal arrived.
            if crate::daemon::shutdown_requested() {
                break;
            }
            processed += daemon.step()?;
        }
        crate::log_info!("processed {processed} knock event(s) in the bounded run");
        return daemon.shutdown();
    }

    daemon.run()
}

/// Load and validate `config.json`.
///
/// EXPERT: Factored out so `verify` can reuse it. The error message when the
///         file is missing points at `otkp init`, which is the single most
///         common first-run mistake and the cheapest one to fix by hand.
/// KID: Read the rulebook. If there is no rulebook, say "run `otkp init` first".
pub fn load_config(path: &Path) -> Result<ServerConfig> {
    if !path.exists() {
        return Err(OtkpError::config(format!(
            "no config file at '{}'. Run `otkp init --dir {}` first.",
            path.display(),
            path.parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        )));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| OtkpError::io_err(path.display().to_string(), e))?;
    let config: ServerConfig = serde_json::from_str(&text)
        .map_err(|e| OtkpError::Json(format!("{}: {e}", path.display())))?;
    config.validate()?;
    Ok(config)
}

/// Overlay the command-line flags onto a loaded config.
///
/// EXPERT: A separate function rather than inline `if let`s, because "which
///         flags override which fields" is a policy worth reading in one place.
///         Every field is `Option` in `Options` precisely so this function can
///         tell "the user did not mention it" from "the user said the default".
///         That distinction is why we do not put defaults in `Options` for these
///         fields -- a `--ban-threshold 0` must be distinguishable from no flag
///         at all, even though 0 is rejected by validation.
/// KID: Let anything the person said out loud override the rulebook.
fn apply_overrides(config: &mut ServerConfig, options: &Options) -> Result<()> {
    if let Some(secs) = options.step_seconds {
        crate::log_info!("override: step_seconds = {secs}");
        config.step_seconds = secs;
    }
    if let Some(n) = options.ban_fail_threshold {
        crate::log_info!("override: ban_fail_threshold = {n}");
        config.ban_fail_threshold = n;
    }
    if let Some(secs) = options.ban_window_seconds {
        crate::log_info!("override: ban_window_seconds = {secs}");
        config.ban_window_seconds = secs;
    }
    if let Some(secs) = options.open_ttl {
        crate::log_info!("override: open_ttl_seconds = {secs}");
        config.open_ttl_seconds = secs;
    }
    if let Some(secs) = options.ban_ttl {
        crate::log_info!("override: ban_ttl_seconds = {secs}");
        config.ban_ttl_seconds = secs;
    }
    if let Some(ms) = options.inter_knock_delay_ms {
        crate::log_info!("override: inter_knock_delay_ms = {ms}");
        config.inter_knock_delay_ms = ms;
    }

    // --- Security level -------------------------------------------------
    // Applied *before* the individual overrides below, so an explicit flag can
    // still win: `--security-level 1 --bind-ip off` is a contradictory request we
    // want `validate` to catch, not to silently resolve one way or the other.
    if let Some(spec) = options.security_level.as_deref() {
        let level = crate::config::SecurityLevel::parse(spec)?;
        crate::log_info!(
            "override: security_level = {} ({})",
            level.name(),
            level.number()
        );
        config.apply_security_level(level);
    }
    if let Some(path) = options.audit_log.as_deref() {
        crate::log_info!("override: audit_log_path = {path}");
        config.audit_log_path = Some(std::path::PathBuf::from(path));
    }

    // The firewall backend is chosen by a short name on the command line and
    // mapped onto the config's tagged enum here. That mapping is the one place
    // the CLI's vocabulary meets the config's vocabulary, and keeping it in one
    // function means the two cannot drift.
    if let Some(name) = options.firewall.as_deref() {
        let backend = match name.to_ascii_lowercase().as_str() {
            "dry-run" | "dryrun" | "dry" | "none" => FirewallConfig::DryRun,
            "iptables" => FirewallConfig::Iptables {
                chain: "OTKP".to_string(),
            },
            "nftables" | "nft" => FirewallConfig::Nftables {
                table: "otkp".to_string(),
                set: "otkp".to_string(),
            },
            other => {
                return Err(OtkpError::config(format!(
                    "unknown firewall backend '{other}'; \
                     expected dry-run, iptables, nftables or command"
                )))
            }
        };
        crate::log_info!("override: firewall = {name}");
        config.firewall = backend;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("otkp-serve-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn setup(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        let opts = crate::cli::init::test_options(dir.to_str().unwrap());
        crate::cli::init::run(&opts).unwrap();
        dir
    }

    #[test]
    fn load_config_reads_and_validates() {
        let dir = setup("load");
        let cfg = load_config(&dir.join("config.json")).unwrap();
        assert_eq!(cfg.step_seconds, crate::DEFAULT_STEP_SECONDS);
        assert_eq!(cfg.firewall, FirewallConfig::DryRun);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_config_missing_file_names_init() {
        let err = load_config(Path::new("/nonexistent/otkp/config.json")).unwrap_err();
        assert!(err.to_string().contains("otkp init"));
    }

    #[test]
    fn load_config_rejects_malformed_json() {
        let dir = temp_dir("malformed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), b"{ this is not json }").unwrap();
        let err = load_config(&dir.join("config.json")).unwrap_err();
        assert!(matches!(err, OtkpError::Json(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overrides_apply_in_order() {
        let mut cfg = ServerConfig::default();
        let mut o = Options::default();
        o.step_seconds = Some(15);
        o.ban_fail_threshold = Some(5);
        o.ban_window_seconds = Some(600);
        o.open_ttl = Some(60);
        o.ban_ttl = Some(0);
        o.inter_knock_delay_ms = Some(10);
        o.firewall = Some("iptables".into());

        apply_overrides(&mut cfg, &o).unwrap();
        assert_eq!(cfg.step_seconds, 15);
        assert_eq!(cfg.ban_fail_threshold, 5);
        assert_eq!(cfg.ban_window_seconds, 600);
        assert_eq!(cfg.open_ttl_seconds, 60);
        assert_eq!(cfg.ban_ttl_seconds, 0);
        assert_eq!(cfg.inter_knock_delay_ms, 10);
        assert_eq!(
            cfg.firewall,
            FirewallConfig::Iptables {
                chain: "OTKP".into()
            }
        );
    }

    #[test]
    fn firewall_names_map_to_backends() {
        // Every accepted spelling must produce the expected variant.
        let cases = [
            ("dry-run", FirewallConfig::DryRun),
            ("dry", FirewallConfig::DryRun),
            ("none", FirewallConfig::DryRun),
            (
                "iptables",
                FirewallConfig::Iptables {
                    chain: "OTKP".into(),
                },
            ),
            (
                "nft",
                FirewallConfig::Nftables {
                    table: "otkp".into(),
                    set: "otkp".into(),
                },
            ),
            (
                "NFTABLES",
                FirewallConfig::Nftables {
                    table: "otkp".into(),
                    set: "otkp".into(),
                },
            ),
        ];
        for (name, want) in cases {
            let mut cfg = ServerConfig::default();
            let mut o = Options::default();
            o.firewall = Some(name.to_string());
            apply_overrides(&mut cfg, &o).unwrap();
            assert_eq!(cfg.firewall, want, "for name '{name}'");
        }
    }

    #[test]
    fn unknown_firewall_name_is_rejected() {
        let mut cfg = ServerConfig::default();
        let mut o = Options::default();
        o.firewall = Some("smoke-signals".into());
        let err = apply_overrides(&mut cfg, &o).unwrap_err();
        assert!(err.to_string().contains("unknown firewall backend"));
    }

    #[test]
    fn overrides_are_re_validated() {
        // An override that breaks an invariant must be caught by `validate`.
        let mut cfg = ServerConfig::default();
        let mut o = Options::default();
        o.open_ttl = Some(0); // invalid: a port open forever
        apply_overrides(&mut cfg, &o).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn serve_refuses_an_empty_keyring() {
        // This is a startup guard worth its own test: an empty keyring would
        // otherwise produce a daemon that silently ignores every knock, which
        // looks exactly like "the protocol is broken".
        let dir = setup("empty-keyring");
        let opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            // Bound the loop so that, if the guard were missing, the test would
            // still terminate rather than hang.
            max_iterations: Some(1),
            ..Options::default()
        };
        let err = run(&opts).unwrap_err();
        assert!(err.to_string().contains("no enrolled users"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serve_runs_a_bounded_loop_with_one_user() {
        // End-to-end at the CLI level: init, enrol, then a bounded serve run.
        // It must complete without error and without touching a real firewall
        // (the default backend is dry-run).
        let dir = setup("bounded");
        let enroll_opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            ..Options::default()
        };
        crate::cli::enroll::run(&enroll_opts, "alice").unwrap();

        // Bind the listener on an ephemeral port so the test cannot collide with
        // anything, by editing the config before serving.
        let cfg_path = dir.join("config.json");
        let mut cfg: ServerConfig =
            serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
        cfg.listen_addr = "127.0.0.1:0".parse().unwrap();
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let serve_opts = Options {
            dir: dir.to_str().unwrap().to_string(),
            max_iterations: Some(2),
            source: Some("udp".into()),
            ..Options::default()
        };
        // Must not error. (We cannot easily assert on the dry-run log from here
        // because the CLI builds its own firewall; the integration test in
        // tests/daemon_loop.rs asserts on the log directly.)
        run(&serve_opts).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
