// ============================================================================
//  tests/daemon_loop.rs  --  end-to-end tests of the wired-together daemon
// ============================================================================
//
//  EXPERT VIEW:
//    This file is the integration test that justifies the whole trait-based
//    architecture. It runs the *real* daemon loop -- real `Engine`, real state
//    machine, real firewall call sites -- against a *real* UDP socket, and it
//    does so:
//
//        * without root,
//        * without touching any system firewall,
//        * without any timing flakiness (the clock is injected),
//        * in well under a second.
//
//    That combination is only possible because `KnockSource`, `Firewall` and
//    `Clock` are traits. If the daemon had called `UdpSocket::recv_from`,
//    `iptables` and `SystemTime::now` directly, this test could not exist -- and
//    the security-critical state machine would be tested only in isolation.
//
//    `RecordingFirewall` below is a *test double written in the test crate*. It
//    is worth noting that this compiles without any test-only hooks in the
//    library: the trait is public and implementable by anyone, which is exactly
//    what "program to an interface" is supposed to buy you.
//
//  KID VIEW:
//    The full rehearsal. We set up the real bouncer with a pretend pair of hands
//    that writes down everything it does, knock on the real (loopback) network,
//    and check the bouncer let the right person in and threw the wrong one out.
// ============================================================================

// See `src/lib.rs` for why these two lints are allowed crate-wide. Test crates
// do not inherit the library's configuration, so the allows are repeated here.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::field_reassign_with_default)]

use otkp::banlist::BanList;
use otkp::config::{FirewallConfig, PortRange, ServerConfig};
use otkp::crypto::{derive_knock_spec, time_step, KnockSpec};
use otkp::daemon::Daemon;
use otkp::engine::{Clock, Engine, KnockEvent};
use otkp::error::Result;
use otkp::firewall::Firewall;
use otkp::keyring::Keyring;
use otkp::net::{send_knocks, SendTarget, UdpKnockSource};
use otkp::secret::MasterSecret;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// A firewall that records every call instead of touching the system.
///
/// EXPERT: `Arc<Mutex<Vec<String>>>` lets the test keep a handle to the log
///         while the daemon owns the firewall behind a `Box<dyn Firewall>`. The
///         `Mutex` is not for concurrency (there is none) but because
///         `Box<dyn Firewall>` requires `Send`-free access and we want to share
///         ownership -- an `Rc<RefCell<..>>` would also work, but `Arc<Mutex>`
///         is the safer habit and costs nothing here.
///
///         We also record *failures* so we can test the rollback path.
/// KID: Pretend hands with a notepad. They write down every order they receive
///      instead of actually opening doors.
#[derive(Clone)]
struct RecordingFirewall {
    /// Every operation, in order, as human-readable lines.
    log: Arc<Mutex<Vec<String>>>,
    /// If true, every `open_port` call fails. Used to test rollback.
    fail_open: bool,
}

impl RecordingFirewall {
    fn new() -> Self {
        RecordingFirewall {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_open: false,
        }
    }

    /// A firewall whose `open_port` always fails.
    fn always_failing_open() -> Self {
        RecordingFirewall {
            log: Arc::new(Mutex::new(Vec::new())),
            fail_open: true,
        }
    }

    /// A clone of the log handle, for the test to inspect.
    fn log_handle(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.log)
    }

    /// Append a line to the log.
    ///
    /// EXPERT: We deliberately tolerate a poisoned mutex (`unwrap_or_else` on
    ///         the lock result) rather than propagating. A panic inside one test
    ///         thread must not make an unrelated assertion in another thread
    ///         panic with a confusing "poisoned" message.
    fn record(&self, line: String) {
        if let Ok(mut guard) = self.log.lock() {
            guard.push(line);
        }
    }
}

impl Firewall for RecordingFirewall {
    fn open_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        if self.fail_open {
            self.record(format!("FAILED open {port} for {ip}"));
            return Err(otkp::error::OtkpError::firewall(
                "simulated firewall failure".to_string(),
            ));
        }
        self.record(format!("open {port} for {ip}"));
        Ok(())
    }

    fn close_port(&mut self, ip: IpAddr, port: u16) -> Result<()> {
        self.record(format!("close {port} for {ip}"));
        Ok(())
    }

    fn ban_ip(&mut self, ip: IpAddr) -> Result<()> {
        self.record(format!("ban {ip}"));
        Ok(())
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<()> {
        self.record(format!("unban {ip}"));
        Ok(())
    }

    fn name(&self) -> &'static str {
        "recording"
    }

    fn cleanup(&mut self) -> Result<()> {
        self.record("cleanup".to_string());
        Ok(())
    }
}

/// A clock the test controls.
struct FixedClock(AtomicU64);

impl FixedClock {
    fn new(t: u64) -> Self {
        FixedClock(AtomicU64::new(t))
    }
    fn set(&self, t: u64) {
        self.0.store(t, Ordering::Relaxed);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// The known secret used by every test in this file.
const SECRET: [u8; 32] = [0xC3; 32];

/// Build a keyring with "alice" holding `SECRET`.
fn keyring() -> Keyring {
    let json = format!(
        r#"{{"entries":{{"alice":{{"user":"alice","secret":"{}","enrolled_at":0}}}}}}"#,
        MasterSecret::from_bytes(SECRET).to_base32()
    );
    serde_json::from_str(&json).expect("test keyring must parse")
}

/// A small, deterministic config.
fn config() -> ServerConfig {
    let mut cfg = ServerConfig::default();
    cfg.knock_range = PortRange::new(40_000, 40_099).unwrap();
    cfg.open_range = PortRange::new(50_000, 50_009).unwrap();
    cfg.knock_count_min = 3;
    cfg.knock_count_max = 3;
    // Threshold 1 keeps these tests focused on the knock/authorise path; the
    // rate-limit behaviour has its own unit tests in `src/engine.rs`.
    cfg.ban_fail_threshold = 1;
    cfg.ban_window_seconds = 3600;
    cfg.ban_ttl_seconds = 0; // permanent, so the test cannot race a TTL
    cfg.open_ttl_seconds = 30;
    cfg.step_seconds = 30;
    cfg.step_skew = 1;
    cfg.firewall = FirewallConfig::DryRun;
    cfg.validate().expect("test config must validate");
    cfg
}

/// The spec for "alice" at the given wall-clock time.
fn spec_at(cfg: &ServerConfig, now: u64) -> KnockSpec {
    let step = time_step(now, cfg.step_seconds);
    derive_knock_spec(&MasterSecret::from_bytes(SECRET), "alice", step, cfg, None)
}

/// Run the daemon loop until `n` events have been processed (or a safety cap).
///
/// EXPERT: The safety cap is essential. Without it, a bug that stops the daemon
///         from ever processing an event would make the test *hang* rather than
///         fail, and a hanging test is much worse than a failing one: it burns
///         CI minutes and hides the real error. `4*n + 16` iterations of a
///         250 ms-timeout socket is a generous bound that still terminates.
fn run_steps(daemon: &mut Daemon, n: usize) -> usize {
    let mut processed = 0;
    let cap = n * 4 + 16;
    for _ in 0..cap {
        match daemon.step() {
            Ok(p) => {
                processed += p;
                if processed >= n {
                    break;
                }
            }
            Err(e) => panic!("daemon step failed: {e}"),
        }
    }
    processed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A correct sequence over a real socket must open the port exactly once.
#[test]
fn correct_sequence_opens_the_port_once() {
    let now = 1_700_000_000u64;
    let cfg = config();
    let spec = spec_at(&cfg, now);

    // A real UDP listener on an ephemeral port.
    let source = UdpKnockSource::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = source.local_addr().unwrap();

    // A recording firewall we can inspect afterwards.
    let firewall = RecordingFirewall::new();
    let log = firewall.log_handle();

    let engine = Engine::new(keyring(), cfg.clone(), BanList::new());
    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        Box::new(source),
        Box::new(FixedClock::new(now)),
    );

    // Send the correct sequence over loopback.
    let target = SendTarget {
        host: "127.0.0.1".to_string(),
        listen_port: addr.port(),
        raw_mode: false,
        inter_knock_delay_ms: 0,
    };
    let sent = send_knocks(&target, &spec).expect("sending knocks must succeed");
    assert_eq!(sent, spec.knock_ports.len());

    // Drive the loop until every knock has been consumed.
    let processed = run_steps(&mut daemon, spec.knock_ports.len());
    assert_eq!(processed, spec.knock_ports.len(), "all knocks must be seen");

    // The engine must consider the port open for loopback.
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        daemon.engine().auth().is_open(ip, now),
        "the port should be open after a correct knock"
    );

    // And the firewall must have been asked to open exactly the derived port,
    // exactly once.
    let lines = log.lock().unwrap().clone();
    let opens: Vec<&String> = lines.iter().filter(|l| l.starts_with("open ")).collect();
    assert_eq!(opens.len(), 1, "expected exactly one open, got {lines:?}");
    assert_eq!(opens[0], &format!("open {} for {ip}", spec.open_port));
}

/// A single wrong knock must ban the source and record it in the firewall.
#[test]
fn wrong_knock_bans_and_records() {
    let now = 1_700_000_100u64;
    let cfg = config();
    let spec = spec_at(&cfg, now);

    // Find a port inside the knock range that is NOT part of the sequence.
    let wrong = (40_000u16..40_100)
        .find(|p| !spec.knock_ports.contains(p))
        .expect("there must be an unused port in a 100-port range");

    let source = UdpKnockSource::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = source.local_addr().unwrap();

    let firewall = RecordingFirewall::new();
    let log = firewall.log_handle();

    let engine = Engine::new(keyring(), cfg.clone(), BanList::new());
    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        Box::new(source),
        Box::new(FixedClock::new(now)),
    );

    // Send a single wrong knock. We build a one-element spec so we can reuse the
    // real sender, which also exercises the payload codec.
    let wrong_spec = KnockSpec {
        user: "alice".to_string(),
        time_step: spec.time_step,
        knock_ports: vec![wrong],
        open_port: 0,
    };
    let target = SendTarget {
        host: "127.0.0.1".to_string(),
        listen_port: addr.port(),
        raw_mode: false,
        inter_knock_delay_ms: 0,
    };
    send_knocks(&target, &wrong_spec).unwrap();

    let processed = run_steps(&mut daemon, 1);
    assert_eq!(processed, 1);

    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        daemon.engine().banlist().is_banned(ip, now),
        "a single wrong knock must ban the source"
    );

    let lines = log.lock().unwrap().clone();
    assert!(
        lines.iter().any(|l| l == &format!("ban {ip}")),
        "the firewall must be told to ban: {lines:?}"
    );
    // And crucially, no port was opened.
    assert!(
        !lines.iter().any(|l| l.starts_with("open ")),
        "nothing should have been opened: {lines:?}"
    );
}

/// Traffic to a port outside the knock range must be invisible to the protocol.
///
/// EXPERT: This is the property that keeps the ban list from filling with the
///         entire internet, and it is the one most likely to be broken by a
///         careless refactor of `Engine::observe`'s early returns. Testing it at
///         the integration level (rather than only as a unit test) proves the
///         ordering survives all the way through the daemon.
#[test]
fn unrelated_traffic_is_ignored_and_not_banned() {
    let now = 1_700_000_200u64;
    let cfg = config();

    let source = UdpKnockSource::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = source.local_addr().unwrap();

    let firewall = RecordingFirewall::new();
    let log = firewall.log_handle();

    let engine = Engine::new(keyring(), cfg.clone(), BanList::new());
    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        Box::new(source),
        Box::new(FixedClock::new(now)),
    );

    // A knock to a port nowhere near the knock range (and not a valid port
    // anyway). The sender will happily put it on the wire; the daemon must
    // ignore it entirely.
    let stray_spec = KnockSpec {
        user: "alice".to_string(),
        time_step: 0,
        knock_ports: vec![80],
        open_port: 0,
    };
    let target = SendTarget {
        host: "127.0.0.1".to_string(),
        listen_port: addr.port(),
        raw_mode: false,
        inter_knock_delay_ms: 0,
    };
    send_knocks(&target, &stray_spec).unwrap();

    let _ = run_steps(&mut daemon, 1);

    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(
        !daemon.engine().banlist().is_banned(ip, now),
        "stray traffic must NOT ban"
    );
    let lines = log.lock().unwrap().clone();
    assert!(
        lines.is_empty(),
        "nothing should have been recorded: {lines:?}"
    );
}

/// The port must close again when the TTL expires.
#[test]
fn port_closes_after_ttl() {
    let now = 1_700_000_300u64;
    let cfg = config();
    let spec = spec_at(&cfg, now);

    let source = UdpKnockSource::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = source.local_addr().unwrap();

    let firewall = RecordingFirewall::new();
    let log = firewall.log_handle();

    // The clock is shared (`Arc`) so the test can advance it after the daemon
    // has taken ownership of a clone. This is the clean way to make an injected
    // clock movable without adding a setter to the daemon's API.
    //
    // EXPERT: `Clock` requires `Send + Sync`, and `FixedClock` uses an atomic,
    //         so an `Arc<FixedClock>` is itself a valid `Clock` if we implement
    //         the trait for the Arc -- or, more simply, we implement it for
    //         `FixedClock` and pass a *second* handle to the test. Since
    //         `FixedClock`'s state is an `AtomicU64`, we can just clone the
    //         struct and both clones share nothing... which would be wrong.
    //         So we wrap it in an `Arc` and implement `Clock` for the `Arc`.
    let clock = Arc::new(FixedClock::new(now));

    let engine = Engine::new(keyring(), cfg.clone(), BanList::new());
    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        Box::new(source),
        // `Arc<FixedClock>` implements `Clock` (see the impl below), so it can
        // be boxed directly.
        Box::new(ArcClock(Arc::clone(&clock))),
    );

    let target = SendTarget {
        host: "127.0.0.1".to_string(),
        listen_port: addr.port(),
        raw_mode: false,
        inter_knock_delay_ms: 0,
    };
    send_knocks(&target, &spec).unwrap();
    let processed = run_steps(&mut daemon, spec.knock_ports.len());
    assert_eq!(processed, spec.knock_ports.len());

    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(daemon.engine().auth().is_open(ip, now));

    // Advance the shared clock past the open TTL, then step once. The daemon's
    // housekeeping must notice and close the port.
    //
    // NOTE: this is exactly the scenario that would be a slow, flaky test with
    // the real clock -- we would have to sleep 30 seconds. Injecting the clock
    // makes it instant and deterministic, which is the whole argument for the
    // `Clock` trait.
    clock.set(now + cfg.open_ttl_seconds + 1);
    let _ = daemon.step().unwrap();

    assert!(
        !daemon
            .engine()
            .auth()
            .is_open(ip, now + cfg.open_ttl_seconds + 1),
        "the port must be closed after the TTL"
    );

    // And the firewall must have been told to close exactly that port.
    let lines = log.lock().unwrap().clone();
    assert!(
        lines
            .iter()
            .any(|l| l == &format!("close {} for {ip}", spec.open_port)),
        "the firewall should have been told to close: {lines:?}"
    );
}

/// A newtype so we can implement `Clock` for a shared, test-controlled clock.
///
/// EXPERT: We could not implement `Clock` for `Arc<FixedClock>` directly,
///         because `FixedClock` and `Clock` are both defined... well,
///         `FixedClock` is defined in this test crate and `Clock` is defined in
///         the library, so the orphan rule *would* permit it. The newtype is
///         still clearer: it names the concept ("a clock handle I can share")
///         and avoids relying on a subtle coherence rule.
/// KID: A little box around the toy watch so two people can hold the same knob.
struct ArcClock(Arc<FixedClock>);

impl Clock for ArcClock {
    fn now(&self) -> u64 {
        // `Arc` derefs to the inner value.
        self.0.now()
    }
}

/// A firewall failure on open must be rolled back, not remembered as success.
///
/// EXPERT: This test covers the error path that the module header calls out as
///         the most dangerous to get wrong: a grant recorded but never enforced
///         would make the sweeper try to close a port that was never opened, and
///         would show a phantom open port in any status output.
#[test]
fn failed_firewall_open_is_rolled_back() {
    let now = 1_700_000_400u64;
    let cfg = config();
    let spec = spec_at(&cfg, now);

    let source = UdpKnockSource::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = source.local_addr().unwrap();

    let firewall = RecordingFirewall::always_failing_open();
    let log = firewall.log_handle();

    let engine = Engine::new(keyring(), cfg.clone(), BanList::new());
    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        Box::new(source),
        Box::new(FixedClock::new(now)),
    );

    let target = SendTarget {
        host: "127.0.0.1".to_string(),
        listen_port: addr.port(),
        raw_mode: false,
        inter_knock_delay_ms: 0,
    };
    send_knocks(&target, &spec).unwrap();
    let processed = run_steps(&mut daemon, spec.knock_ports.len());
    assert_eq!(processed, spec.knock_ports.len());

    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    // The firewall refused, so the engine must NOT claim the port is open.
    assert!(
        !daemon.engine().auth().is_open(ip, now),
        "a failed firewall open must be rolled back"
    );

    let lines = log.lock().unwrap().clone();
    assert!(
        lines.iter().any(|l| l.starts_with("FAILED open ")),
        "the failure must have been attempted: {lines:?}"
    );
}

/// Shutting down must close every open port and clean up.
#[test]
fn shutdown_closes_everything() {
    let now = 1_700_000_500u64;
    let cfg = config();

    let firewall = RecordingFirewall::new();
    let log = firewall.log_handle();

    let mut engine = Engine::new(keyring(), cfg.clone(), BanList::new());
    // Open two grants by hand, from two different addresses.
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    engine.auth_mut().open(ip1, 50_000, "alice", 0, now, 30);
    engine.auth_mut().open(ip2, 50_001, "alice", 0, now, 30);

    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        // An empty scripted source; we never step this daemon.
        Box::new(EmptySource),
        Box::new(FixedClock::new(now)),
    );

    daemon.shutdown().unwrap();

    let lines = log.lock().unwrap().clone();
    // Both ports must have been closed, and cleanup must have run.
    assert!(
        lines.contains(&"close 50000 for 10.0.0.1".to_string()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"close 50001 for 10.0.0.2".to_string()),
        "{lines:?}"
    );
    assert!(lines.contains(&"cleanup".to_string()), "{lines:?}");
}

/// A source that never produces events, for tests that drive the daemon by hand.
struct EmptySource;

impl otkp::net::KnockSource for EmptySource {
    fn recv_at(&mut self, _now: u64) -> Result<Option<KnockEvent>> {
        Ok(None)
    }
    fn name(&self) -> &'static str {
        "empty"
    }
}

/// Bans persisted on disk must be re-applied to the firewall at startup.
///
/// EXPERT: This covers the gap described in `Daemon::restore_bans`: the previous
///         shutdown removed all our firewall rules, so without this step a
///         daemon restart would hand every banned attacker a fresh set of
///         attempts. It is a subtle, high-consequence omission and deserves an
///         explicit test.
#[test]
fn persisted_bans_are_restored_at_startup() {
    let now = 1_700_000_600u64;
    let cfg = config();

    // Use a real on-disk ban list in a temp directory.
    let dir = std::env::temp_dir().join(format!("otkp-restore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("banlist.json");

    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    {
        // Write a ban list as a previous daemon run would have left it.
        let mut bl = BanList::new().with_path(path.clone());
        bl.ban(ip, now, 0, "previous run");
        bl.save().unwrap();
    }

    // Load it back, exactly as `serve` does.
    let banlist = BanList::load(&path).unwrap();
    let engine = Engine::new(keyring(), cfg.clone(), banlist);

    let firewall = RecordingFirewall::new();
    let log = firewall.log_handle();

    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        Box::new(EmptySource),
        Box::new(FixedClock::new(now)),
    );

    let restored = daemon.restore_bans().unwrap();
    assert_eq!(restored, 1, "the persisted ban must be reinstalled");

    let lines = log.lock().unwrap().clone();
    assert!(lines.contains(&format!("ban {ip}")), "{lines:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A full run of `run()` with a pre-set shutdown flag must return cleanly.
///
/// EXPERT: `run` is an infinite loop by design, so the only way to test it is to
///         request a shutdown before calling it. The global flag is process-wide,
///         so this test must not run concurrently with another test that uses
///         it; there is only one, and we clear the flag afterwards. Documenting
///         the shared-state constraint is the honest thing to do.
#[test]
fn run_exits_cleanly_when_shutdown_is_requested() {
    let now = 1_700_000_700u64;
    let cfg = config();

    let firewall = RecordingFirewall::new();
    let log = firewall.log_handle();

    let mut engine = Engine::new(keyring(), cfg.clone(), BanList::new());
    let ip: IpAddr = "10.0.0.9".parse().unwrap();
    engine.auth_mut().open(ip, 50_005, "alice", 0, now, 30);

    let mut daemon = Daemon::new(
        engine,
        Box::new(firewall),
        Box::new(EmptySource),
        Box::new(FixedClock::new(now)),
    );

    // Request shutdown *before* running, so the loop body never executes.
    otkp::daemon::clear_shutdown();
    otkp::daemon::request_shutdown();
    let result = daemon.run();
    otkp::daemon::clear_shutdown(); // leave global state as we found it

    assert!(result.is_ok(), "run must return cleanly: {result:?}");

    // And the shutdown path must have closed the open port and cleaned up.
    let lines = log.lock().unwrap().clone();
    assert!(
        lines.contains(&"close 50005 for 10.0.0.9".to_string()),
        "{lines:?}"
    );
    assert!(lines.contains(&"cleanup".to_string()), "{lines:?}");
}
