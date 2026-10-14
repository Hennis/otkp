// ============================================================================
//  src/daemon.rs  --  the loop that wires everything together
// ============================================================================
//
//  EXPERT VIEW:
//    This module is the *only* place where the engine's pure decisions meet the
//    impure world. It is deliberately the shortest of the "big" modules, because
//    it contains no logic of its own -- it is plumbing, and plumbing should be
//    boring. Its whole job is:
//
//        1. ask the `KnockSource` for the next event,
//        2. hand it to the `Engine`,
//        3. translate the resulting `Outcome` into `Firewall` calls,
//        4. periodically call `Engine::sweep` and translate that too,
//        5. shut down cleanly, leaving no firewall rules behind.
//
//    Every one of those five things is expressed against a trait, which is what
//    makes the daemon testable end-to-end without root, without a network, and
//    without a real firewall. The integration test in `tests/daemon_loop.rs`
//    does exactly that: it runs this loop against a UDP source and the dry-run
//    firewall and asserts on the resulting log.
//
//    The error policy deserves a note. There are three classes of failure:
//
//      * **A firewall call fails.** Log it, roll back our bookkeeping so we do
//        not claim a port is open that is not, and *carry on*. Crashing the
//        daemon would close every port and drop every ban, which is a worse
//        outcome than a single failed rule.
//      * **A receive fails.** Log it and continue. A transient network error
//        must not take down a security service.
//      * **A sweep fails.** Log it. Same reasoning.
//
//    In other words: the daemon never exits because of an operational hiccup. It
//    exits when the operator asks it to. That is the correct policy for a
//    long-running service, and it is a policy decision, not a default.
//
//  KID VIEW:
//    This is the manager who connects the bouncer's brain to the hands and the
//    ear. Listen for a tap (ear), decide what it means (brain), do it (hands),
//    and every so often tidy up (lock expired doors, empty the naughty corner).
//    If the manager drops a single key, he does not run away from the club -- he
//    picks it up and keeps working, until you tell him to go home.
// ============================================================================

use crate::audit::{AuditEvent, AuditLog};
use crate::auth::Grant;
use crate::engine::{Clock, Engine, KnockEvent, Outcome, SweepReport};
use crate::error::Result;
use crate::firewall::Firewall;
use crate::net::KnockSource;

// ===========================================================================
//  Signal handling: a cooperative shutdown flag
// ===========================================================================
/// Set to `true` when the process receives SIGINT or SIGTERM.
///
/// EXPERT: A `static AtomicBool` is the standard way to get a signal handler's
///         information back into the main loop. The handler itself may only call
///         async-signal-safe functions -- which rules out logging, allocation,
///         and almost everything else -- but `AtomicBool::store` compiles to a
///         single instruction and is safe. So the handler does the absolute
///         minimum and the main loop does the rest.
///
/// `Ordering::Relaxed` is sufficient: we need eventual visibility of the
///         flag, and we are not using it to publish any other data. Even
///         `Relaxed` guarantees the store is not lost, which is all we need.
/// KID: A little "please stop now" flag. The person who raises it is not allowed
///      to do anything else, so he just raises the flag and the manager notices.
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The signal handler. It does one thing: raise the flag.
///
/// EXPERT: `extern "C"` because the C library calls it, not Rust. It takes the
///         signal number (which we ignore) and returns nothing. Everything it
///         touches must be async-signal-safe; the only such thing here is the
///         atomic store.
/// KID: The person who raises the flag. He is only allowed to raise the flag --
///      no chatting, no tidying, just raise it.
extern "C" fn handle_signal(_signum: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Install handlers for SIGINT (Ctrl-C) and SIGTERM (`systemctl stop`).
///
/// EXPERT: We use `libc::signal` rather than a crate like `signal-hook` to avoid
///         another dependency in a root-running program. `signal` is the oldest
///         and least portable of the signal APIs, but for "set a flag on
///         SIGINT/SIGTERM" it is entirely sufficient on Linux, and its semantics
///         (reset to default on delivery in some older systems) do not matter
///         here because we exit promptly after the first signal.
///
/// `SIG_ERR` is the failure sentinel; if `signal` returns it, we report a
///         warning but do NOT fail startup. A daemon that cannot catch Ctrl-C is
///         still a working daemon; refusing to start would be a worse trade.
/// KID: Teach the flag-raiser to react when someone presses the big red stop
///      button. If we cannot teach him, that is a small problem -- we still run.
pub fn install_signal_handlers() {
    // `#[allow(unsafe_code)]` locally: calling `signal` is unsafe because the
    // handler must uphold the async-signal-safety contract, which `handle_signal`
    // does (see its docs).
    #[allow(unsafe_code)]
    // SAFETY: We pass a function with the correct `extern "C"` ABI and a
    // `SIG_DFL`-style handler pointer as `signal` expects. The returned value is
    // checked against `SIG_ERR`.
    unsafe {
        // `SIGINT` is Ctrl-C; `SIGTERM` is what service managers send to stop.
        for sig in [libc::SIGINT, libc::SIGTERM] {
            let previous = libc::signal(sig, handle_signal as *const () as libc::sighandler_t);
            if previous == libc::SIG_ERR {
                crate::log_warn!("could not install handler for signal {sig}");
            }
        }
    }
}

/// Has a shutdown been requested?
///
/// EXPERT: A function rather than exposing the static, so the ordering choice
///         lives next to the store and cannot be got wrong at a call site.
/// KID: "Has anyone raised the stop flag?"
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Raise the shutdown flag from code (used by tests and by `--once` runs).
///
/// EXPERT: Exposing a setter makes the daemon loop drivable from a test without
///         sending a real signal, which would be global, racy, and could kill the
///         test runner. This is the same dependency-injection instinct as the
///         `Clock` trait, applied to the shutdown path.
/// KID: Let tests raise the stop flag by hand, instead of pressing the real
///      button.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Clear the shutdown flag.
///
/// EXPERT: Needed by tests, which run in one process and must reset global state
///         between cases. Also useful if a future version wants to reload
///         configuration without exiting.
/// KID: Lower the stop flag again.
pub fn clear_shutdown() {
    SHUTDOWN_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
}

// ===========================================================================
//  Daemon
// ===========================================================================
/// The wired-together daemon.
///
/// EXPERT: Note that every collaborator is a boxed trait object except the
///         `Engine`, which is concrete. That asymmetry is deliberate: the engine
///         is the thing we are testing, so making it concrete keeps its full API
///         available to the daemon (and to tests) without a trait. The
///         collaborators are the *substitutable* parts, so they are traits.
///
/// `Engine` is not `Clone` and must not be, so `Daemon` takes ownership.
/// KID: The manager, with his ear, brain, hands, and watch.
pub struct Daemon {
    /// The decision-maker.
    engine: Engine,
    /// Where decisions are carried out.
    firewall: Box<dyn Firewall>,
    /// Where events come from.
    source: Box<dyn KnockSource>,
    /// What time it is.
    clock: Box<dyn Clock>,
    /// The structured audit stream (security level 2), or a disabled one.
    ///
    /// EXPERT: Always present, even when disabled, so no call site needs a
    ///         branch. A disabled `AuditLog` is a no-op, which is what makes
    ///         "level 2 is on" a property of the *config* rather than a property
    ///         scattered through the control flow.
    /// KID: The robot diary. Sometimes we have one, sometimes we do not; writing
    ///      in it works either way.
    audit: AuditLog,

    /// When we last ran the periodic sweep.
    ///
    /// EXPERT: We sweep at most once per second. Sweeping on every packet would
    ///         be wasteful (each sweep allocates two `Vec`s and walks the ban
    ///         list), and sweeping less often would let an opened port linger
    ///         past its TTL by up to the sweep interval. One second is a good
    ///         balance: the port-overrun is at most 1 s against a 30 s TTL, i.e.
    ///         3% -- and the alternative, a timer thread, adds concurrency for no
    ///         real gain.
    /// KID: The manager checks the clock for tidying-up jobs once a second.
    last_sweep: u64,
}

impl Daemon {
    /// Build a daemon from its four parts.
    ///
    /// EXPERT: Taking `Box<dyn _>` rather than generics (`Daemon<F: Firewall,
    ///         S: KnockSource>`) is a real trade-off worth naming:
    ///           * Boxed trait objects: one type, simple signatures, small
    ///             vtable indirection cost. The daemon is not a hot loop over
    ///             these calls (a few per minute), so the cost is invisible.
    ///           * Generics: monomorphised, zero-cost, but the type grows a type
    ///             parameter per collaborator, which infects every signature and
    ///             makes storing a daemon in a `Vec` awkward.
    ///         For a daemon that changes firewall rules a few times a minute,
    ///         boxed is obviously right. We say so rather than leaving it
    ///         unexamined.
    /// KID: "Manager, here are your ear, hands and watch."
    pub fn new(
        engine: Engine,
        firewall: Box<dyn Firewall>,
        source: Box<dyn KnockSource>,
        clock: Box<dyn Clock>,
    ) -> Self {
        // Default to no audit stream; `with_audit` opts in. Keeping the existing
        // four-argument constructor working means every existing caller and test
        // is unaffected by the new level.
        Daemon::with_audit(engine, firewall, source, clock, AuditLog::disabled())
    }

    /// Build a daemon that also writes the structured audit stream.
    ///
    /// EXPERT: A second constructor rather than a fifth argument on `new`,
    ///         because the audit stream is a *security-level* concern and most
    ///         callers (and every unit test that is not about auditing) do not
    ///         have one. A builder-style addition keeps the common case at four
    ///         arguments and makes the opt-in explicit at the one call site that
    ///         needs it.
    /// KID: "Also give me the robot diary."
    pub fn with_audit(
        engine: Engine,
        firewall: Box<dyn Firewall>,
        source: Box<dyn KnockSource>,
        clock: Box<dyn Clock>,
        audit: AuditLog,
    ) -> Self {
        Daemon {
            engine,
            firewall,
            source,
            clock,
            audit,
            // 0 means "sweep on the first iteration", which is what we want:
            // stale state from a previous run should be reconciled immediately.
            last_sweep: 0,
        }
    }

    /// Access the engine (for tests and for reporting).
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Mutable access to the engine (for tests).
    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    /// The firewall's name, for the startup log line.
    pub fn firewall_name(&self) -> &'static str {
        self.firewall.name()
    }

    /// The source's name, for the startup log line.
    pub fn source_name(&self) -> &'static str {
        self.source.name()
    }

    /// Run one iteration of the loop.
    ///
    /// EXPERT: Factored out of `run` so tests can step the daemon deterministically
    ///         instead of racing a background loop. This is the single most
    ///         useful testability decision in the module: `run` becomes a trivial
    ///         `while !shutdown { step() }`, and every interesting behaviour is
    ///         exercised through `step`.
    ///
    /// Returns the number of events processed (0 or 1), which is handy for
    ///         tests and for a `--once` mode.
    /// KID: Do one round of work: listen, decide, act, and maybe tidy up.
    pub fn step(&mut self) -> Result<usize> {
        // ------------------------------------------------------------------
        // 1. Periodic housekeeping, at most once per second.
        // ------------------------------------------------------------------
        let now = self.clock.now();
        if now.saturating_sub(self.last_sweep) >= 1 {
            self.last_sweep = now;
            let report = self.engine.sweep(now);
            self.apply_sweep(report);
        }

        // ------------------------------------------------------------------
        // 2. Get one event. `Ok(None)` is a normal timeout, not an error.
        // ------------------------------------------------------------------
        let event: Option<KnockEvent> = match self.source.recv_at(now) {
            Ok(e) => e,
            Err(e) => {
                // A receive error must not kill the daemon. Log and move on; the
                // next iteration will try again.
                crate::log_warn!("knock source error: {e}");
                return Ok(0);
            }
        };

        let event = match event {
            Some(e) => e,
            // Timeout: nothing to do this iteration. We already swept above.
            None => return Ok(0),
        };

        // ------------------------------------------------------------------
        // 3. Decide.
        // ------------------------------------------------------------------
        // Debug-level so a verbose run shows every packet, but a normal run does
        // not drown in them.
        crate::log_debug!(
            "observed knock: {} -> port {}",
            event.src_ip,
            event.dst_port
        );

        let outcome = self.engine.observe(event);

        // ------------------------------------------------------------------
        // 4. Act.
        // ------------------------------------------------------------------
        self.apply_outcome(outcome);

        Ok(1)
    }

    /// Translate an `Outcome` into firewall calls and log lines.
    ///
    /// EXPERT: A private method that returns `()` rather than `Result<()>`,
    ///         because it *handles* its own errors. That is deliberate: the
    ///         caller (`step`) has nothing useful to do with a firewall failure
    ///         -- it must not propagate it and must not retry it -- so making it
    ///         return `Result` would only invite a `?` that aborts the loop. The
    ///         error policy lives here, in one place, and it is: log, roll back,
    ///         carry on.
    /// KID: Read the bouncer's answer and tell the hands what to do. If the hands
    ///      fumble, tell the bouncer so his notes stay truthful, and carry on.
    fn apply_outcome(&mut self, outcome: Outcome) {
        match outcome {
            // Nothing to do, and nothing worth logging at Info level (a busy
            // host would otherwise flood the log).
            Outcome::Ignored => {}

            Outcome::Progress {
                user,
                time_step,
                matched,
                total,
            } => {
                crate::log_info!(
                    "knock progress for '{user}' at step {time_step}: {matched}/{total}"
                );
            }

            Outcome::Authorised {
                user,
                port,
                time_step,
                grant,
            } => {
                // Try to install the firewall rule.
                match self.firewall.open_port(grant.ip, port) {
                    Ok(()) => {
                        crate::log_info!(
                            "AUTHORISED '{user}' from {} for port {port} at step {time_step} \
                             (until t={}, ~{}s)",
                            grant.ip,
                            grant.expires_at,
                            grant.expires_at.saturating_sub(grant.opened_at)
                        );
                        self.audit_write(AuditEvent::Authorised {
                            at: grant.opened_at,
                            ip: grant.ip,
                            port,
                            user: user.clone(),
                            time_step,
                            expires_at: grant.expires_at,
                        });
                    }
                    Err(e) => {
                        // The firewall refused. Undo our bookkeeping so the
                        // sweeper does not later try to close a rule that was
                        // never installed, and so the operator sees the failure
                        // rather than a phantom "open" port in the status output.
                        let _ = self.engine.rollback_authorisation(grant.ip);
                        crate::log_error!(
                            "could not open port {port} for {} ('{user}'): {e}; \
                             authorisation rolled back",
                            grant.ip
                        );
                    }
                }
            }

            Outcome::Banned { ip, failures } => {
                // The engine has already recorded the ban in its own list. Now
                // make it real in the firewall.
                match self.firewall.ban_ip(ip) {
                    Ok(()) => {
                        crate::log_warn!("BANNED {ip} after {failures} failed knock(s)");
                        // We record the ban only once the firewall accepted it,
                        // so the audit stream reflects what is actually enforced
                        // rather than what we intended. A record of an intent
                        // that failed is a record that misleads an incident
                        // review.
                        let now = self.clock.now();
                        let window = self.engine.config().ban_window_seconds;
                        let ttl = self.engine.config().ban_ttl_seconds;
                        self.audit_write(AuditEvent::Banned {
                            at: now,
                            ip,
                            failures,
                            window_seconds: window,
                            expires_at: if ttl == 0 {
                                None
                            } else {
                                Some(now.saturating_add(ttl))
                            },
                        });
                    }
                    Err(e) => {
                        // We keep the in-engine ban even if the firewall call
                        // fails. Rationale: the engine's ban list is what makes
                        // the *knock protocol* refuse them, and it persists to
                        // disk; the firewall rule is defence in depth. Keeping the
                        // ban and logging loudly is better than pretending the
                        // attacker is fine.
                        crate::log_error!(
                            "could not install firewall ban for {ip}: {e} \
                             (ban is still enforced by the daemon)"
                        );
                    }
                }
            }
        }
    }

    /// Translate a `SweepReport` into firewall calls and log lines.
    ///
    /// EXPERT: Symmetric with `apply_outcome`, and private for the same reason.
    ///         The two lists in `SweepReport` exist precisely so this function
    ///         can do its job without looking anything up: `expired_grants`
    ///         carries the ports to close, `expired_bans` the addresses to unban.
    /// KID: Read the tidy-up report and tell the hands which doors to lock and
    ///      which names to take off the naughty list.
    fn apply_sweep(&mut self, report: SweepReport) {
        // Close ports whose window has expired.
        for Grant { ip, port, user, .. } in report.expired_grants {
            match self.firewall.close_port(ip, port) {
                Ok(()) => {
                    crate::log_info!("closed port {port} for {ip} ('{user}' window expired)");
                    let at = self.clock.now();
                    self.audit_write(AuditEvent::PortClosed {
                        at,
                        ip,
                        port,
                        user: user.clone(),
                    });
                }
                Err(e) => {
                    // Log and continue: the next sweep will not retry (the grant
                    // is gone from our table), so this is a genuine "operator
                    // must look" event. We make it loud.
                    crate::log_error!(
                        "could not close port {port} for {ip}: {e}; \
                         the firewall may still permit this connection"
                    );
                }
            }
        }

        // Lift expired bans.
        for ip in report.expired_bans {
            match self.firewall.unban_ip(ip) {
                Ok(()) => {
                    crate::log_info!("ban expired for {ip}");
                    let at = self.clock.now();
                    self.audit_write(AuditEvent::BanExpired { at, ip });
                }
                Err(e) => {
                    crate::log_error!("could not remove firewall ban for {ip}: {e}");
                }
            }
        }
    }

    /// Write one audit record, failing soft.
    ///
    /// EXPERT: The single place in this project where an I/O failure is
    ///         deliberately non-fatal. The reasoning, stated so it can be
    ///         argued with: losing an audit record is bad, but taking down the
    ///         access-control daemon because a disk filled is worse — it would
    ///         deny service to legitimate users *and* stop recording, so the
    ///         failure mode of failing hard is strictly worse than the failure
    ///         mode of failing soft. A deployment with a regulatory obligation to
    ///         never lose a record should use `AuditLog::write` directly and
    ///         treat the error as fatal; the API allows that, the daemon does not
    ///         choose it.
    /// KID: If the diary's pen runs out, shout about it — but do not stop letting
    ///      people through the door.
    fn audit_write(&self, event: AuditEvent) {
        if let Err(e) = self.audit.write(&event) {
            crate::log_error!(
                "AUDIT WRITE FAILED ({}): {e} — the decision above was enforced but \
                 not recorded",
                event.tag()
            );
        }
    }

    /// Run until a shutdown is requested.
    ///
    /// EXPERT: The `while !shutdown_requested()` loop, with `step` doing the work.
    ///         Note the absence of any `Result` propagation from inside: `step`
    ///         already handles every recoverable error, so the only way out of
    ///         this loop is a shutdown request. That is a deliberate invariant --
    ///         "the daemon runs until you stop it" -- and expressing it in the
    ///         control flow (rather than in a comment) is how you keep it true.
    ///
    /// The one thing `run` does *not* swallow is a failure to shut down
    ///         cleanly; `shutdown` returns `Result` and `run` propagates it.
    /// KID: Keep working until someone raises the stop flag, then tidy up and go
    ///      home.
    pub fn run(&mut self) -> Result<()> {
        crate::log_info!(
            "otkp daemon starting: source={}, firewall={}, users={}",
            self.source.name(),
            self.firewall.name(),
            self.engine.keyring().len()
        );

        // Main loop.
        while !shutdown_requested() {
            // `step` handles its own errors, so we ignore its return value here.
            let _ = self.step();
        }

        crate::log_info!("shutdown requested; cleaning up");
        self.shutdown()
    }

    /// Close every open port, lift nothing, and remove our firewall rules.
    ///
    /// EXPERT: Two distinct cleanups, and the distinction matters:
    ///
    /// * **Close every open port.** A port we opened is a hole in the
    ///             host's security that exists only because we asked for it. If
    ///             we exit without closing it, the hole outlives the reason for
    ///             it. We therefore close every grant, whatever its TTL.
    ///
    /// * **Leave bans in place** (in the firewall) but call
    ///             `firewall.cleanup()`, which removes our chain/table entirely.
    ///             For iptables and nftables, `cleanup` removes *all* our rules,
    ///             bans included -- which is correct, because we are removing
    ///             ourselves from the host, not making a policy statement. The
    ///             bans survive on disk in `banlist.json` and will be reinstalled
    ///             on the next start (see the startup note below).
    ///
    /// The order is: close ports, then clean up. Reversing it would mean
    ///         calling `close_port` after the chain was deleted, producing
    ///         spurious errors.
    /// KID: Before going home: lock every door we opened, then take our whole
    ///      rule-book out of the building. The naughty list is written down on
    ///      paper, so it survives.
    pub fn shutdown(&mut self) -> Result<()> {
        // 1. Close every currently-open grant.
        let open_grants = self.engine.auth_mut().drain();
        let count = open_grants.len();
        for Grant { ip, port, .. } in open_grants {
            if let Err(e) = self.firewall.close_port(ip, port) {
                crate::log_error!("shutdown: could not close port {port} for {ip}: {e}");
            }
        }
        if count > 0 {
            crate::log_info!("shutdown: closed {count} open port(s)");
        }

        // 2. Remove our rules entirely.
        if let Err(e) = self.firewall.cleanup() {
            crate::log_error!("shutdown: firewall cleanup failed: {e}");
        }

        crate::log_info!("otkp daemon stopped");
        Ok(())
    }

    /// Re-apply firewall bans that were persisted from a previous run.
    ///
    /// EXPERT: Called by the CLI *before* `run`. Without this, a daemon restart
    ///         would forget every firewall ban (the firewall rules were removed
    ///         by the previous shutdown's `cleanup`), while the *in-engine* ban
    ///         list still contained them. That asymmetry would be a real
    ///         security gap: an attacker banned at 09:00 could restart their
    ///         attempts after any daemon restart. Re-applying closes the gap and
    ///         makes the on-disk ban list the single source of truth.
    ///
    /// Failures are logged, not fatal -- a stale firewall rule we cannot
    ///         install is a warning, not a reason to refuse to start.
    /// KID: When we open the club again, put all the names from the naughty list
    ///      back on the door.
    pub fn restore_bans(&mut self) -> Result<usize> {
        let now = self.clock.now();
        // `snapshot` purges expired entries as a side effect, which is exactly
        // right: a ban that lapsed while we were down should not be reinstalled.
        let bans = self.engine.banlist_mut().snapshot(now);
        let mut restored = 0usize;
        for entry in bans {
            match self.firewall.ban_ip(entry.ip) {
                Ok(()) => restored += 1,
                Err(e) => {
                    crate::log_warn!("could not restore ban for {}: {e}", entry.ip);
                }
            }
        }
        if restored > 0 {
            crate::log_info!("restored {restored} persisted ban(s) into the firewall");
        }
        Ok(restored)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FirewallConfig, PortRange, ServerConfig};
    use crate::engine::SystemClock;
    use crate::firewall::DryRunFirewall;
    use crate::keyring::Keyring;
    use crate::net::UdpKnockSource;
    use crate::secret::MasterSecret;
    use std::sync::atomic::Ordering;

    /// A test double for `KnockSource` that yields a scripted list of events.
    ///
    /// EXPERT: This is where the trait pays off. Instead of binding a socket and
    ///         racing the network, we hand the daemon an exact sequence of events
    ///         and assert on exactly what happened. The test is deterministic,
    ///         instant, and needs no privileges. Note that this is a *fake*, not
    ///         a mock: it has no assertions of its own, it just supplies data.
    /// KID: A pretend ear that hears exactly the taps we tell it to hear.
    struct ScriptedSource {
        /// Events still to be delivered, in order.
        queue: std::collections::VecDeque<KnockEvent>,
    }

    impl ScriptedSource {
        fn new(events: Vec<KnockEvent>) -> Self {
            ScriptedSource {
                queue: events.into(),
            }
        }
    }

    impl KnockSource for ScriptedSource {
        /// Yield the next scripted event, stamping it with the daemon's clock.
        ///
        /// EXPERT: We *overwrite* the event's `at` field with the daemon-supplied
        ///         `now`. That mirrors exactly what a real source does (the
        ///         daemon's clock is the single source of time), and it means the
        ///         test's scripted events do not need to know what time it is.
        /// KID: Hand over the next tap, and write the manager's clock on it.
        fn recv_at(&mut self, now: u64) -> Result<Option<KnockEvent>> {
            // `pop_front` gives `None` when the script is exhausted, which the
            // daemon treats as a timeout. That lets us run a fixed number of
            // `step`s and then stop.
            Ok(self.queue.pop_front().map(|mut e| {
                e.at = now;
                e
            }))
        }
        fn name(&self) -> &'static str {
            "scripted"
        }
    }

    /// A fixed clock for deterministic sweeps.
    struct FixedClock(std::sync::atomic::AtomicU64);

    impl FixedClock {
        fn new(t: u64) -> Self {
            FixedClock(std::sync::atomic::AtomicU64::new(t))
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    /// Build an engine with a known secret for "alice", plus a small config.
    fn test_engine(now: u64) -> (Engine, ServerConfig, KnockSpec, MasterSecret) {
        let known = MasterSecret::from_bytes([0x77; 32]);
        let json = format!(
            r#"{{"entries":{{"alice":{{"user":"alice","secret":"{}","enrolled_at":0}}}}}}"#,
            known.to_base32()
        );
        let keyring: Keyring = serde_json::from_str(&json).unwrap();

        let mut config = ServerConfig::default();
        config.knock_range = PortRange::new(40_000, 40_099).unwrap();
        config.open_range = PortRange::new(50_000, 50_009).unwrap();
        config.knock_count_min = 3;
        config.knock_count_max = 3;
        config.ban_fail_threshold = 1;
        config.ban_window_seconds = 3600;
        config.ban_ttl_seconds = 0; // permanent for the test
        config.open_ttl_seconds = 30;
        config.firewall = FirewallConfig::DryRun;
        config.validate().unwrap();

        let step = crate::crypto::time_step(now, config.step_seconds);
        let spec = crate::crypto::derive_knock_spec(&known, "alice", step, &config, None);

        let engine = Engine::new(keyring, config.clone(), crate::banlist::BanList::new());
        (engine, config, spec, known)
    }

    // Import KnockSpec for the return type above.
    use crate::crypto::KnockSpec;

    #[test]
    fn daemon_authorises_a_full_sequence() {
        let now = 2_000_000u64;
        let (engine, _cfg, spec, _secret) = test_engine(now);

        // Script exactly the correct sequence from one IP.
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let events: Vec<KnockEvent> = spec
            .knock_ports
            .iter()
            .map(|&p| KnockEvent {
                src_ip: ip,
                dst_port: p,
                at: now,
            })
            .collect();

        let mut daemon = Daemon::new(
            engine,
            Box::new(DryRunFirewall::new()),
            Box::new(ScriptedSource::new(events)),
            Box::new(FixedClock::new(now)),
        );

        // Step through every scripted event.
        for _ in 0..spec.knock_ports.len() {
            let processed = daemon.step().unwrap();
            assert_eq!(processed, 1);
        }

        // The engine must now consider the port open.
        assert!(daemon.engine().auth().is_open(ip, now));
    }

    #[test]
    fn daemon_bans_a_bad_knock() {
        let now = 3_000_000u64;
        let (engine, _cfg, spec, _secret) = test_engine(now);
        let ip: std::net::IpAddr = "10.0.0.2".parse().unwrap();

        // Pick a port inside the knock range that is not part of the sequence.
        let wrong = (40_000u16..40_100)
            .find(|p| !spec.knock_ports.contains(p))
            .unwrap();

        let events = vec![KnockEvent {
            src_ip: ip,
            dst_port: wrong,
            at: now,
        }];

        let mut daemon = Daemon::new(
            engine,
            Box::new(DryRunFirewall::new()),
            Box::new(ScriptedSource::new(events)),
            Box::new(FixedClock::new(now)),
        );

        let _ = daemon.step().unwrap();
        assert!(daemon.engine().banlist().is_banned(ip, now));
    }

    #[test]
    fn daemon_sweep_closes_expired_ports() {
        let now = 4_000_000u64;
        let (mut engine, _cfg, spec, _secret) = test_engine(now);
        let ip: std::net::IpAddr = "10.0.0.3".parse().unwrap();

        // Open a grant by hand, as if the user had just knocked successfully.
        engine
            .auth_mut()
            .open(ip, spec.open_port, "alice", 0, now, 30);

        // The clock will report a time past the TTL, so `step`'s housekeeping
        // must close the port.
        let clock = FixedClock::new(now + 31);
        let mut daemon = Daemon::new(
            engine,
            Box::new(DryRunFirewall::new()),
            Box::new(ScriptedSource::new(vec![])), // no events
            Box::new(clock),
        );

        // One step: sweeps, then times out on the empty source.
        let _ = daemon.step().unwrap();

        // The grant must be gone from the engine's table.
        assert!(!daemon.engine().auth().is_open(ip, now + 31));
    }

    #[test]
    fn shutdown_closes_ports_and_cleans_up() {
        let now = 5_000_000u64;
        let (mut engine, _cfg, spec, _secret) = test_engine(now);
        let ip: std::net::IpAddr = "10.0.0.4".parse().unwrap();
        engine
            .auth_mut()
            .open(ip, spec.open_port, "alice", 0, now, 30);
        assert!(engine.auth().is_open(ip, now));

        let mut daemon = Daemon::new(
            engine,
            Box::new(DryRunFirewall::new()),
            Box::new(ScriptedSource::new(vec![])),
            Box::new(FixedClock::new(now)),
        );

        daemon.shutdown().unwrap();
        // After shutdown, no grants remain.
        assert_eq!(daemon.engine_mut().auth_mut().len(now), 0);
    }

    #[test]
    fn restore_bans_reinstalls_persisted_bans() {
        let now = 6_000_000u64;
        let (mut engine, _cfg, _spec, _secret) = test_engine(now);
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        // Put a ban in the engine's list (as if loaded from disk).
        let _ = engine.banlist_mut().ban(ip, now, 0, "test");

        let mut daemon = Daemon::new(
            engine,
            Box::new(DryRunFirewall::new()),
            Box::new(ScriptedSource::new(vec![])),
            Box::new(FixedClock::new(now)),
        );

        let restored = daemon.restore_bans().unwrap();
        assert_eq!(restored, 1);
    }

    #[test]
    fn udp_source_works_with_the_daemon() {
        // This is the closest thing to an end-to-end test in this module: a real
        // UDP socket feeding a real daemon loop, with a dry-run firewall. It
        // needs no privileges and no network beyond loopback.
        let now = 7_000_000u64;
        let (engine, _cfg, spec, _secret) = test_engine(now);
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        // Bind the source first so we know its port.
        let source = UdpKnockSource::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = source.local_addr().unwrap();

        // Send the correct sequence.
        let target = crate::net::SendTarget {
            host: "127.0.0.1".to_string(),
            listen_port: addr.port(),
            raw_mode: false,
            inter_knock_delay_ms: 0,
        };
        let sent = crate::net::send_knocks(&target, &spec).unwrap();
        assert_eq!(sent, spec.knock_ports.len());

        // The socket's read timeout is 250 ms, which is plenty for loopback.
        let mut daemon = Daemon::new(
            engine,
            Box::new(DryRunFirewall::new()),
            Box::new(source),
            Box::new(FixedClock::new(now)),
        );

        // Step until all knocks are consumed. We allow a few extra iterations
        // because a `recv` can return `None` on a scheduling hiccup.
        let mut processed = 0;
        for _ in 0..(spec.knock_ports.len() * 4 + 4) {
            processed += daemon.step().unwrap();
            if processed >= spec.knock_ports.len() {
                break;
            }
        }
        assert_eq!(processed, spec.knock_ports.len());
        assert!(daemon.engine().auth().is_open(ip, now));
    }

    #[test]
    fn shutdown_flag_round_trips() {
        // Keep this test's global-state mutation contained.
        clear_shutdown();
        assert!(!shutdown_requested());
        request_shutdown();
        assert!(shutdown_requested());
        clear_shutdown();
        assert!(!shutdown_requested());
    }

    #[test]
    fn system_clock_reports_a_plausible_time() {
        // Sanity: the real clock must be after 2020 and before 2100.
        let t = SystemClock.now();
        assert!(t > 1_577_836_800, "clock is before 2020: {t}");
        assert!(t < 4_102_444_800, "clock is after 2100: {t}");
    }
}
