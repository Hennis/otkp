// ============================================================================
//  src/engine.rs  --  THE HEART: the per-IP knock state machine
// ============================================================================
//
//  EXPERT VIEW:
//    This module answers exactly one question, many times a second: *given that
//    a packet just arrived from some IP to some port, what should happen?*
//    There are four possible answers, and `Outcome` names them:
//
//      * `Ignored`     -- this packet is none of our business.
//      * `Progress`    -- it is the next expected knock for someone; keep going.
//      * `Authorised`  -- a full sequence just completed; open a port.
//      * `Banned`      -- it fits nobody's sequence; the sender is now banned.
//
//    Everything else in this file exists to compute those answers efficiently
//    and testably. Three design decisions are worth stating explicitly, because
//    they are the ones a reviewer should challenge:
//
//    1. **The engine does no I/O.** It does not touch the firewall, the disk, or
//       the network. It takes an event and returns a verdict. That is what makes
//       it possible to test the entire security logic with plain function calls
//       and no root, no sockets, no timing. The daemon is the only thing that
//       turns verdicts into side effects.
//
//    2. **Specs are cached per time step.** Deriving a spec means an HMAC per
//       user, and we must consider `2 * skew + 1` steps. Doing that per *packet*
//       would be wasteful; doing it per *time step* is trivial. The cache is
//       keyed by step and is invalidated naturally as steps fall out of range.
//
//    3. **Per-IP state is a small map, pruned aggressively.** An attacker can
//       send packets from a spoofed source, so per-IP state is attacker-
//       influenceable and must not grow without bound. We prune candidates
//       outside the skew window on every observation, and drop the whole entry
//       when it has neither candidates nor failures.
//
//  KID VIEW:
//    This is the bouncer at the door with a clipboard. Every time someone taps
//    on a door, the bouncer checks: "Is this person on the naughty list? Is
//    their door already open? Does this tap match the *next* tap of anyone's
//    secret knock?" If it is the last tap of somebody's knock, the bouncer
//    unlocks their door. If it matches nobody at all, the bouncer crosses their
//    name off the guest list on the spot.
//
//    The bouncer never leaves his chair: he does not unlock doors himself, he
//    just writes a note ("open Bob's door") and someone else does it. That way
//    we can test the bouncer's brain without a real door.
// ============================================================================

use crate::auth::{AuthTable, Grant};
use crate::banlist::BanList;
use crate::config::ServerConfig;
use crate::crypto::KnockSpec;
use crate::keyring::Keyring;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

// ===========================================================================
//  Clock -- the dependency-injected "what time is it?"
// ===========================================================================
/// Anything that can tell you the current Unix time.
///
/// EXPERT: Why a trait and not a plain call to `SystemTime::now()`? Because the
///         engine's behaviour is *entirely* a function of time, and a test that
///         cannot control time cannot test expiry, ban windows, or time-step
///         rotation without sleeping. Injecting the clock turns a slow, flaky,
///         timing-dependent test into a fast, deterministic one. This is the
///         single highest-leverage seam in the project.
/// KID: A watch. In real life it is a real watch; in our tests it is a toy watch
///      whose hands we can move whenever we like.
pub trait Clock: Send + Sync {
    /// The current Unix time, in whole seconds.
    fn now(&self) -> u64;
}

/// The real clock, backed by the operating system.
///
/// EXPERT: `Send + Sync` (declared on the trait) means an implementor can be
///         shared across threads. That matters because the daemon's sweeper and
///         its packet loop both need the clock.
/// KID: A normal watch that tells the real time.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        // Delegate to the single place in the library that reads the wall clock.
        crate::crypto::unix_now()
    }
}

/// A clock whose hands you can move. Used only in tests.
///
/// EXPERT: `#[cfg(test)]` keeps this out of the shipped binary entirely, so it
///         costs nothing in production and cannot be accidentally used there.
///         Note the `Cell<u64>`: it lets `now(&self)` mutate the stored time
///         even though the trait takes `&self`. `Cell` is the right primitive
///         for a single-threaded, interior-mutability counter -- no atomics, no
///         locks. (The trait requires `Sync`, and `Cell` is not `Sync`; so we
///         would need a `Mutex` if this were shared across threads. In tests it
///         is not, but the compiler still checks the bound -- so we use an
///         `AtomicU64`, which is both `Sync` and lock-free.)
/// KID: A toy watch with a knob. Tests turn the knob to make time pass instantly.
#[cfg(test)]
#[derive(Debug)]
pub struct ManualClock {
    /// Current time, stored atomically so the type satisfies `Send + Sync`.
    now: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl ManualClock {
    /// Start the clock at `start`.
    pub fn new(start: u64) -> Self {
        ManualClock {
            now: std::sync::atomic::AtomicU64::new(start),
        }
    }

    /// Move the clock to `t`. (Time can also go backwards, which is worth
    /// testing: an NTP correction can do exactly that.)
    pub fn set(&self, t: u64) {
        self.now.store(t, std::sync::atomic::Ordering::Relaxed);
    }

    /// Advance the clock by `delta` seconds.
    pub fn advance(&self, delta: u64) {
        // `fetch_add` returns the *previous* value; we ignore it.
        let _ = self
            .now
            .fetch_add(delta, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::Relaxed)
    }
}

// ===========================================================================
//  KnockEvent -- what the engine is told happened
// ===========================================================================
/// One observed connection attempt.
///
/// EXPERT: Deliberately tiny and transport-agnostic. Both the UDP listener and
///         the AF_PACKET sniffer produce this exact struct, which is why the
///         interesting logic needs to be written and tested only once. Adding a
///         field here (say, the IP TTL, for OS fingerprinting) would automatically
///         become available to every transport -- that is the payoff of a narrow
///         canonical event type.
/// KID: A note the bouncer receives: "Someone at this address tapped door number
///      41231, at this time."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnockEvent {
    /// Who is knocking.
    ///
    /// EXPERT: For UDP this comes from `recvfrom`. For AF_PACKET it comes from
    ///         the IPv4 header. In both cases it is *unauthenticated* -- an
    ///         attacker can spoof it. That is fine: the security comes from the
    ///         secret sequence, not from trusting the source address. Spoofing
    ///         the source merely means you get someone *else* authorised (a
    ///         "TCP-ACK-style" reflection), which is why the opened port should
    ///         additionally require the real service's own authentication. This
    ///         caveat is in the README; it is a property of port knocking in
    ///         general, not of our implementation.
    pub src_ip: IpAddr,

    /// Which port they knocked on.
    pub dst_port: u16,

    /// Unix seconds when the packet was observed.
    ///
    /// EXPERT: Stamped by the caller (using a `Clock`), not read inside the
    ///         engine. That keeps `observe` a pure function of its arguments,
    ///         which is what makes deterministic tests possible.
    pub at: u64,
}

// ===========================================================================
//  Outcome -- the verdict
// ===========================================================================
/// What the engine decided about an event.
///
/// EXPERT: A four-variant enum where each variant carries exactly the data the
///         caller needs to act. In particular `Authorised` carries the `port`
///         and `Grant` so the daemon can call the firewall without re-deriving
///         anything, and `Banned` carries the failure count so the log line can
///         say "banned after 1 failure" rather than just "banned". Designing the
///         verdict around the caller's next action is the same principle used in
///         `AuthTable::purge_expired` and `BanList::purge_expired`.
/// KID: The bouncer's four possible answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The packet is not our business (outside the knock range, from a banned
    /// IP, or from an IP that already has a door open).
    Ignored,

    /// The packet was the next expected knock for at least one candidate.
    ///
    /// Carries the best (furthest-along) candidate purely for logging.
    Progress {
        /// The user whose sequence advanced furthest.
        user: String,
        /// The time step of that sequence.
        time_step: u64,
        /// How many knocks have now matched for that candidate.
        matched: usize,
        /// The total length of that candidate's sequence.
        total: usize,
    },

    /// A complete sequence was matched. The caller should open the port.
    Authorised {
        /// The user who authenticated.
        user: String,
        /// The port to open.
        port: u16,
        /// The time step that authorised it.
        time_step: u64,
        /// The full grant record (so the caller can log expiry etc).
        grant: Grant,
    },

    /// The packet matched no live sequence and the IP has now been banned.
    Banned {
        /// The banned address.
        ip: IpAddr,
        /// How many failures accumulated inside the rolling window (>= the
        /// configured threshold).
        failures: u32,
    },
}

// ===========================================================================
//  Per-IP bookkeeping
// ===========================================================================
/// The engine's memory about one source address.
///
/// EXPERT: Private type. Two maps and a counter:
///         * `candidates` maps "which sequence is this IP part-way through" to
///           "how many knocks have matched". The key is `(user, time_step)`.
///         * `failures` counts non-matching packets inside the knock range.
///         * `last_seen` is used by the idle-pruning heuristic.
/// KID: The bouncer's scribbled notes about one visitor: "they are 2 taps into
///      Bob's knock, and they have made no mistakes yet."
#[derive(Debug, Default)]
struct IpState {
    /// Progress through each candidate sequence.
    ///
    /// EXPERT: The key is `(String, u64)` -- owned user name plus time step. An
    ///         owned `String` in a hot map key is normally something to avoid,
    ///         but the number of live candidates per IP is at most
    ///         `users * (2*skew+1)`, typically single digits, and building the
    ///         key involves a short string clone at most once per packet. Using
    ///         `&str` keys would tie the map's lifetime to the keyring and make
    ///         the struct generic, which is a real complexity cost for no
    ///         measurable gain at these sizes.
    candidates: HashMap<(String, u64), usize>,

    /// Timestamps of recent failed knocks, oldest first.
    ///
    /// EXPERT: A ring (well, a `VecDeque` we push to and pop from the front) of
    ///         failure times, which implements the *rolling* window. We store
    ///         times rather than a counter because a counter cannot answer "how
    ///         many failures in the last hour?" without a periodic reset, and a
    ///         periodic reset is exactly the predictable boundary an attacker
    ///         times their bursts around.
    ///
    /// Bounded growth: we only ever keep entries newer than the window,
    ///         and we cap the length at the threshold plus a little slack, since
    ///         anything beyond the threshold has already triggered a ban and the
    ///         state is discarded. So this cannot grow without bound even under a
    ///         flood.
    failures: std::collections::VecDeque<u64>,

    /// Last time we saw a packet from this IP.
    last_seen: u64,
}

impl IpState {
    /// Is there nothing worth remembering about this IP?
    ///
    /// EXPERT: Used to prune the outer map. An entry with no candidates and no
    ///         failures carries no information, so keeping it would be a slow
    ///         memory leak driven by spoofed source addresses.
    /// KID: "Do I have any notes about this person? No? Then forget them."
    fn is_empty(&self) -> bool {
        self.candidates.is_empty() && self.failures.is_empty()
    }

    /// Drop failures older than the window, then return how many remain.
    ///
    /// EXPERT: This is the whole mechanism of the rolling window. Called before
    ///         every read of the failure count, so the count is always
    ///         "failures in the last `window` seconds" and never needs a
    ///         separate timer. The `VecDeque` is ordered by construction (we
    ///         always push a monotonically non-decreasing `now`), so we can pop
    ///         from the front while the oldest entry is too old -- O(k) where k
    ///         is the number of expired entries, not O(n) over the whole deque.
    ///
    /// Note `now.saturating_sub(window)`: if the clock jumped backwards
    ///         (an NTP correction can do this), `now - window` could underflow.
    ///         Saturating at 0 means "everything is in the window", which is the
    ///         conservative direction for a *rate limiter* -- it may delay
    ///         forgiveness, but it never forgives early.
    /// KID: Forget the mistakes you made longer ago than the window, then count
    ///      what is left.
    fn prune_failures(&mut self, now: u64, window: u64) -> usize {
        let cutoff = now.saturating_sub(window);
        // Pop from the front while the oldest entry is strictly older than the
        // window. `>=` would drop an entry exactly `window` seconds old; we want
        // "within the last `window` seconds" to *include* that boundary, hence
        // the strict `<`.
        while let Some(&oldest) = self.failures.front() {
            if oldest < cutoff {
                let _ = self.failures.pop_front();
            } else {
                break;
            }
        }
        self.failures.len()
    }

    /// Record one failure at time `now`, returning the count inside the window.
    ///
    /// EXPERT: Prunes first (so the count we return is the windowed count), then
    ///         pushes. We also bound the stored length: once it exceeds the
    ///         threshold the caller bans and drops the whole `IpState`, so
    ///         storing more than `threshold + 1` entries is pointless. The cap
    ///         matters because an attacker could otherwise make us allocate one
    ///         `u64` per packet for the length of the window.
    /// KID: Write down this mistake, then tell me how many mistakes are still on
    ///      the list.
    fn record_failure(&mut self, now: u64, window: u64, cap: usize) -> usize {
        // Prune old entries so the count reflects only the live window.
        let _ = self.prune_failures(now, window);
        self.failures.push_back(now);
        // Enforce the cap. Popping from the front keeps the *newest* entries,
        // which is the right direction: recent failures are the ones that matter
        // for deciding to ban.
        while self.failures.len() > cap {
            let _ = self.failures.pop_front();
        }
        self.failures.len()
    }
}

// ===========================================================================
//  SweepReport -- what the periodic sweep found
// ===========================================================================
/// The work the periodic sweep produced, for the caller to apply.
///
/// EXPERT: A struct rather than a tuple because two `Vec`s of different types
///         would be easy to swap at a call site, and because we may add a third
///         list later (e.g. "grants about to expire, warn now") without changing
///         any signature. Named fields at the boundary of a module are cheap
///         insurance.
/// KID: The bouncer's tidy-up report: "these doors must be locked again, and
///      these people are out of the naughty corner."
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Grants that have expired and whose ports must be closed.
    pub expired_grants: Vec<Grant>,
    /// Addresses whose bans have expired and whose firewall rules must go.
    pub expired_bans: Vec<IpAddr>,
}

// ===========================================================================
//  Engine
// ===========================================================================
/// The knock state machine.
///
/// EXPERT: Owns the keyring, config, ban list, auth table, and the per-IP state.
///         It does NOT own a firewall or a socket; see the module header for
///         why. `Debug` is safe because none of these fields leak secrets
///         (`Keyring`'s `Debug` is redacted, `MasterSecret`'s is redacted).
/// KID: The bouncer, his clipboard, the guest list, the naughty list, and the
///      set of fridge notes -- all in one person.
#[derive(Debug)]
pub struct Engine {
    /// Who is allowed to knock.
    keyring: Keyring,
    /// The operator's policy.
    config: ServerConfig,
    /// Who is locked out.
    banlist: BanList,
    /// Who currently has a door open.
    auth: AuthTable,
    /// Per-IP progress notes.
    states: HashMap<IpAddr, IpState>,
    /// Cache of derived specs, keyed by time step.
    ///
    /// EXPERT: `Vec<(String, KnockSpec)>` per step, holding every enrolled user's
    ///         spec for that step. Rebuilt whenever a step we have not seen is
    ///         requested, and pruned when steps leave the skew window. Bounded by
    ///         `(2*skew+1)` entries regardless of traffic volume, so this cannot
    ///         be grown by an attacker.
    spec_cache: HashMap<u64, Vec<(String, KnockSpec)>>,
}

impl Engine {
    /// Build an engine from its collaborators.
    ///
    /// EXPERT: Takes ownership of all three. `&self`-borrowing versions would
    ///         force the caller to keep them alive in exactly the right places,
    ///         and the daemon genuinely owns all three for its whole life. Taking
    ///         ownership is the honest signature.
    /// KID: "Bouncer, here is the guest list, the rulebook, and the naughty list.
    ///      They are yours now."
    pub fn new(keyring: Keyring, config: ServerConfig, banlist: BanList) -> Self {
        Engine {
            keyring,
            config,
            banlist,
            auth: AuthTable::new(),
            states: HashMap::new(),
            spec_cache: HashMap::new(),
        }
    }

    /// Read-only access to the config.
    ///
    /// EXPERT: A getter, so the daemon can read the knock range for its sniffer
    ///         filter without owning the config separately. Returning `&` keeps
    ///         `ServerConfig`'s invariants under this engine's control.
    /// KID: "Bouncer, what are the rules again?"
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Read-only access to the keyring (for reporting).
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// Read-only access to the auth table.
    ///
    /// EXPERT: `&self` (not `&mut`) even though `AuthTable::snapshot` wants
    ///         `&mut` to purge. We offer the read-only accessor for queries that
    ///         do not purge (`is_open`, `get`), and let the daemon call
    ///         `auth_mut()` when it genuinely wants a purging snapshot.
    /// KID: "Who has a door open?"
    pub fn auth(&self) -> &AuthTable {
        &self.auth
    }

    /// Mutable access to the auth table, for the purging/reporting paths.
    ///
    /// EXPERT: Exposing `&mut` to a field is a small encapsulation compromise.
    ///         The alternative -- mirroring every `AuthTable` method on `Engine`
    ///         -- is a lot of boilerplate for no safety gain, because
    ///         `AuthTable`'s own API is already the invariant boundary. We take
    ///         the pragmatic option and document it.
    /// KID: The bouncer hands you the fridge notes so you can tidy them.
    pub fn auth_mut(&mut self) -> &mut AuthTable {
        &mut self.auth
    }

    /// Mutable access to the ban list, for the CLI's `unban` and reporting.
    pub fn banlist_mut(&mut self) -> &mut BanList {
        &mut self.banlist
    }

    /// Read-only access to the ban list (non-purging queries only).
    pub fn banlist(&self) -> &BanList {
        &self.banlist
    }

    // -----------------------------------------------------------------------
    // Spec cache
    // -----------------------------------------------------------------------
    /// The candidate steps we consider for a given "now": `now-skew ..= now+skew`.
    ///
    /// EXPERT: Returned as a `Vec<u64>` (not a range) because the lower bound can
    ///         be negative for small `now`, and `RangeInclusive<u64>` cannot go
    ///         below zero. `saturating_sub` clamps at 0, which is the right
    ///         behaviour: there is no time step before the epoch to tolerate.
    /// KID: "Which pages of the recipe book might you be reading? The one before
    ///      this one, this one, and the next one -- in case your watch is off."
    fn candidate_steps(&self, now: u64) -> Vec<u64> {
        let now_step = crate::crypto::time_step(now, self.config.step_seconds);
        // `saturating_sub` clamps at 0 instead of wrapping to a huge number.
        let lo = now_step.saturating_sub(self.config.step_skew);
        let hi = now_step + self.config.step_skew;
        (lo..=hi).collect()
    }

    /// Get (deriving if necessary) every user's spec for a time step.
    ///
    /// EXPERT: The cache is the reason the engine can afford to consider
    ///         `users * (2*skew+1)` candidates per packet. Without it, each
    ///         packet would cost that many HMACs; with it, the cost is paid once
    ///         per time step. The `entry` API is used to avoid a double lookup.
    /// KID: "Have I already worked out everyone's taps for this page? If yes,
    ///      use my notes; if no, work them out once and write them down."
    fn specs_for_step(&mut self, step: u64) -> &[(String, KnockSpec)] {
        // `entry(step)` gives us a slot we can fill only if it is vacant.
        let entry = self.spec_cache.entry(step);
        // `or_insert_with` computes the value lazily -- only if absent.
        let list = entry.or_insert_with(|| {
            // Derive for every user, in a stable order.
            self.keyring
                .iter_sorted()
                .into_iter()
                .map(|(name, enrollment)| {
                    (
                        name.to_string(),
                        crate::crypto::derive_knock_spec(
                            &enrollment.secret,
                            name,
                            step,
                            &self.config,
                        ),
                    )
                })
                .collect()
        });
        // Return a slice. The borrow of `self.spec_cache` lasts as long as the
        // returned slice, which the caller uses immediately.
        list.as_slice()
    }

    /// Drop cache entries for steps outside the current window.
    ///
    /// EXPERT: Called from `observe` so the cache stays bounded at
    ///         `2*skew+1` entries. Without this, a long-running daemon would
    ///         accumulate one entry per 30-second window forever -- a slow leak
    ///         proportional to uptime, which is exactly the kind of bug that only
    ///         shows up after a month in production.
    /// KID: Throw away recipe pages we no longer need, so the notebook does not
    ///      fill up.
    fn prune_spec_cache(&mut self, now: u64) {
        let keep = self.candidate_steps(now);
        // `retain` keeps entries whose closure returns true.
        self.spec_cache.retain(|step, _| keep.contains(step));
    }

    // -----------------------------------------------------------------------
    // The main entry point
    // -----------------------------------------------------------------------
    /// Observe one packet and return the verdict.
    ///
    /// EXPERT: The whole security policy, in one readable function. The order of
    ///         the early returns is a security decision, not a style choice:
    ///
    /// 1. Port-range check FIRST, so scanning port 80 never reaches the
    ///              ban logic. (Otherwise the ban list would fill with the entire
    ///              internet, and an attacker could ban *your* address by sending
    ///              one packet from a spoofed source.)
    ///           2. Banned check, so a banned IP cannot advance any candidate.
    ///           3. Already-open check, so an authorised IP's legitimate traffic
    ///              to the opened port is not mistaken for a knock.
    ///           4. Then, and only then, matching.
    ///
    /// Getting this order wrong is how you turn a security feature into a
    ///         denial-of-service tool. It is commented because it is load-bearing.
    /// KID: The bouncer's checklist, in the right order.
    pub fn observe(&mut self, event: KnockEvent) -> Outcome {
        // ------------------------------------------------------------------
        // Step 0: housekeeping. Keep the cache bounded.
        // ------------------------------------------------------------------
        self.prune_spec_cache(event.at);

        // ------------------------------------------------------------------
        // Step 1: is this even a knock? A packet to a port outside the knock
        // range is somebody scanning or using the machine normally. We must
        // ignore it completely -- NOT count it as a failure.
        // ------------------------------------------------------------------
        if !self.config.knock_range.contains(event.dst_port) {
            return Outcome::Ignored;
        }

        // ------------------------------------------------------------------
        // Step 2: banned IPs get nothing. Not even a log line per packet, or a
        // flood would be a log-flooding DoS.
        // ------------------------------------------------------------------
        if self.banlist.is_banned(event.src_ip, event.at) {
            return Outcome::Ignored;
        }

        // ------------------------------------------------------------------
        // Step 3: an IP that already has a door open is not knocking; it is
        // probably connecting to the port we just opened (if the open range
        // overlapped the knock range -- it does not, but a user could also be
        // re-knocking while their door is open, and we should ignore that
        // rather than treat it as a failure).
        // ------------------------------------------------------------------
        if self.auth.is_open(event.src_ip, event.at) {
            return Outcome::Ignored;
        }

        // ------------------------------------------------------------------
        // Step 4: try to match against every live candidate.
        // ------------------------------------------------------------------
        // Collect the (user, step, expected-port-at-position) triples we need.
        // We build this as a small Vec so the borrow of `spec_cache` ends before
        // we mutate `states`.
        let steps = self.candidate_steps(event.at);

        // `completed` holds the first full match found, if any.
        let mut completed: Option<(String, u64, u16)> = None;
        // `advanced` counts how many candidates this packet moved forward.
        let mut advanced = 0usize;
        // `best` tracks the furthest-along candidate, for the log line.
        let mut best: Option<(String, u64, usize, usize)> = None;

        for step in steps {
            // Snapshot the specs for this step. We clone the *minimum* we need:
            // the user name and the expected port. Cloning the whole `KnockSpec`
            // would be wasteful, and holding a borrow would conflict with the
            // `states` mutation below.
            //
            // EXPERT: `specs_for_step` takes `&mut self`, so we cannot hold its
            //         result across a `self.states` mutation. We therefore read
            //         what we need into a local Vec first. This is the borrow
            //         checker forcing a design that is also *faster*: one small
            //         allocation instead of repeated map lookups.
            let specs: Vec<(String, Vec<u16>, u16)> = self
                .specs_for_step(step)
                .iter()
                .map(|(user, spec)| (user.clone(), spec.knock_ports.clone(), spec.open_port))
                .collect();

            for (user, ports, open_port) in specs {
                let key = (user.clone(), step);
                // How far is this IP through this candidate? Default 0.
                let done = self
                    .states
                    .get(&event.src_ip)
                    .and_then(|s| s.candidates.get(&key))
                    .copied()
                    .unwrap_or(0);

                // If they already finished this candidate, skip it.
                if done >= ports.len() {
                    continue;
                }

                // Does the observed port match the next expected knock?
                if ports[done] == event.dst_port {
                    let next = done + 1;
                    // Record progress. `entry(..).or_default()` creates the
                    // `IpState` if this IP is new.
                    let state = self.states.entry(event.src_ip).or_default();
                    let _ = state.candidates.insert(key, next);
                    state.last_seen = event.at;

                    advanced += 1;

                    // Track the furthest-along candidate for logging.
                    let is_better = best.as_ref().map(|(_, _, m, _)| next > *m).unwrap_or(true);
                    if is_better {
                        best = Some((user.clone(), step, next, ports.len()));
                    }

                    // Did that complete the sequence? Record the FIRST one only:
                    // two users cannot share a sequence in practice, and if they
                    // somehow did, opening the port once is correct.
                    if next == ports.len() && completed.is_none() {
                        completed = Some((user, step, open_port));
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // Step 5a: a sequence completed. Authorise.
        // ------------------------------------------------------------------
        if let Some((user, step, port)) = completed {
            // Open the port in our own bookkeeping. The *caller* applies the
            // firewall rule; see the module header.
            let grant = self.auth.open(
                event.src_ip,
                port,
                &user,
                step,
                event.at,
                self.config.open_ttl_seconds,
            );

            // Clear this IP's candidate progress and failure count: their
            // business is concluded. Leaving the candidates would make a second,
            // later knock from the same IP ambiguous.
            if let Some(state) = self.states.get_mut(&event.src_ip) {
                state.candidates.clear();
                state.failures.clear();
                state.last_seen = event.at;
            }

            return Outcome::Authorised {
                user,
                port,
                time_step: step,
                grant,
            };
        }

        // ------------------------------------------------------------------
        // Step 5b: some candidate advanced but none completed. Wait for more.
        // ------------------------------------------------------------------
        if advanced > 0 {
            // `best` is `Some` whenever `advanced > 0`, so this branch is
            // exhaustive; we still handle the `None` case defensively by
            // falling through to the failure path, which is the safe direction.
            if let Some((user, step, matched, total)) = best {
                return Outcome::Progress {
                    user,
                    time_step: step,
                    matched,
                    total,
                };
            }
        }

        // ------------------------------------------------------------------
        // Step 5c: nothing matched. This is a FAILED KNOCK.
        //
        // We only reach here for packets that targeted a port inside the knock
        // range from an IP that is neither banned nor authorised.
        //
        // The failure is counted against a *rolling window* (see
        // `ban_window_seconds`), not a one-strike rule. This is the fix for the
        // spoofed-source denial of service: with a one-strike rule, a single
        // packet bearing a victim's address was enough to get that victim
        // banned. Now an attacker must spend `ban_fail_threshold` packets per
        // window per victim, which makes the attack unattractive.
        //
        // We keep the counter capped at `threshold` entries so a flood cannot
        // make us allocate without bound (see `record_failure`).
        // ------------------------------------------------------------------
        let window = self.config.ban_window_seconds;
        let threshold = self.config.ban_fail_threshold;
        // The cap is `threshold` -- we never need to remember more than the
        // number that triggers a ban, because reaching it ends the state's life.
        let cap = threshold as usize;

        let state = self.states.entry(event.src_ip).or_default();
        state.last_seen = event.at;
        let failures = state.record_failure(event.at, window, cap);

        if failures >= threshold as usize {
            // Ban them, with a reason an operator can act on. The reason names
            // the window and the count so the log line answers "why?" without a
            // second lookup.
            let reason = format!(
                "failed port knock: packet to port {} matched no live sequence \
                 ({} failure(s) in the last {}s)",
                event.dst_port, failures, window
            );
            let _ = self
                .banlist
                .ban(event.src_ip, event.at, self.config.ban_ttl_seconds, &reason);

            // Forget everything else we knew about them: they are banned now,
            // and the candidates would be stale when the ban lifts. Dropping the
            // state also drops the failure ring, which is correct -- the ban is
            // now the record, and the ban list is where an operator looks.
            let _ = self.states.remove(&event.src_ip);

            return Outcome::Banned {
                ip: event.src_ip,
                failures: failures as u32,
            };
        }

        // Below the threshold: the failure is recorded and we wait. The caller
        // sees `Ignored` because nothing observable happened -- there is no
        // `Outcome::Failed` variant, deliberately: a failure below the threshold
        // is an implementation detail of the rate limiter, not an event the
        // daemon needs to act on. (If we later add alerting on near-threshold
        // behaviour, this is the place to add a variant.)
        Outcome::Ignored
    }

    // -----------------------------------------------------------------------
    // Periodic sweep
    // -----------------------------------------------------------------------
    /// Expire grants and bans. Call this periodically from the daemon loop.
    ///
    /// EXPERT: Two responsibilities, both time-driven:
    ///         * Close ports whose `open_ttl_seconds` has elapsed. Returning the
    ///           full `Grant`s lets the daemon remove the exact firewall rule.
    ///         * Lift bans whose `ban_ttl_seconds` has elapsed, returning the IPs
    ///           so the daemon can remove the block rule.
    ///
    /// We also prune idle per-IP state here, which is the only place it
    ///         happens for IPs that are *not* sending packets. Without it, an IP
    ///         that made one failed knock and then went quiet would leave an entry
    ///         in `states` forever -- and with the rolling failure window, an
    ///         attacker can create such entries cheaply by sending a single
    ///         spoofed packet per address. That makes this pruning a security
    ///         control, not just tidiness: it bounds the memory a spoofing flood
    ///         can pin.
    /// KID: The bouncer's tidy-up round: lock expired doors, let people out of
    ///      the naughty corner, and throw away old scribbled notes.
    pub fn sweep(&mut self, now: u64) -> SweepReport {
        // Expire open grants.
        let expired_grants = self.auth.purge_expired(now);

        // Expire bans. `purge_expired` already returns exactly the IPs removed.
        let expired_bans = self.banlist.purge_expired(now);

        // Prune idle per-IP state.
        //
        // The heuristic: drop an entry if it has no candidates, no failures, and
        // has not been seen for longer than a generous multiple of the time step.
        // We use `open_ttl + step * (2*skew+2)` as "long enough that any live
        // candidate would have expired anyway".
        let idle_limit = self.config.open_ttl_seconds.saturating_add(
            self.config
                .step_seconds
                .saturating_mul(2 * self.config.step_skew + 2),
        );
        // `retain` on the outer map: drop entries that are both empty and stale.
        self.states.retain(|_ip, st| {
            if st.is_empty() {
                // An empty entry is droppable as soon as it is stale.
                now.saturating_sub(st.last_seen) <= idle_limit
            } else {
                // A non-empty entry is kept regardless of age here; its
                // candidates are pruned by `prune_candidates` below.
                true
            }
        });

        // Prune stale *candidates* inside surviving entries. A candidate for a
        // time step outside the skew window can never be completed, so keeping
        // it would let an attacker park an IP at "2 knocks into Bob's sequence
        // for a step that has passed" and hold memory.
        let live_steps = self.candidate_steps(now);
        for state in self.states.values_mut() {
            state
                .candidates
                .retain(|(_user, step), _| live_steps.contains(step));
        }
        // And drop any entry that just became empty.
        self.states.retain(|_ip, st| !st.is_empty());

        // Persist the ban list if it has a path. Failure to persist is logged
        // but NOT fatal: losing the ban list on disk is bad, but crashing the
        // daemon (and thereby closing every port and dropping every ban in
        // memory) is worse. Fail soft on persistence, fail closed on auth.
        if let Err(e) = self.banlist.save() {
            crate::log_warn!("could not persist ban list: {e}");
        }

        SweepReport {
            expired_grants,
            expired_bans,
        }
    }

    /// Roll back an authorisation whose firewall rule failed to install.
    ///
    /// EXPERT: The daemon calls this when `firewall.open_port` returns an error.
    ///         Without the rollback, our bookkeeping would claim a port is open
    ///         when it is not, and the sweeper would later try to close a rule
    ///         that never existed (a confusing log line, and possibly an error
    ///         that masks a real one). See the module header's note on the auth
    ///         table being the source of truth for *intent*.
    /// KID: If we could not actually unlock the door, tear up the fridge note so
    ///      we do not get confused later.
    pub fn rollback_authorisation(&mut self, ip: IpAddr) -> Option<Grant> {
        self.auth.take(ip)
    }

    /// How many IPs we currently hold state for. For diagnostics and tests.
    ///
    /// EXPERT: Exposed so a test can assert that pruning actually prunes. A
    ///         memory-growth bug in a security daemon is a slow, invisible
    ///         failure, so being able to assert on this number is worth the
    ///         small API surface.
    /// KID: How many scribbled notes the bouncer is holding.
    pub fn tracked_ips(&self) -> usize {
        self.states.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PortRange, ServerConfig};
    use crate::keyring::Keyring;
    use std::net::Ipv4Addr;

    /// A convenient test fixture: an engine with one user, a fixed clock time,
    /// and a small deterministic config.
    ///
    /// EXPERT: Building the fixture in one place means every test states only
    ///         what makes it different. Tests that share a fixture are also
    ///         easier to keep honest: if the config changes, all of them change
    ///         together, which is usually what you want.
    /// KID: Set up the bouncer with one guest and a simple rulebook.
    struct Fixture {
        engine: Engine,
        config: ServerConfig,
        /// The spec for user "alice" at the chosen time step.
        spec: KnockSpec,
        /// The time the test pretends it is.
        now: u64,
        /// The time step derived from `now`.
        step: u64,
    }

    /// The known secret every engine test uses.
    ///
    /// EXPERT: `enroll()` generates a random secret, which is correct in
    ///         production but useless in a test: we need to know the secret so we
    ///         can derive the *right* sequence to knock with. So the fixture
    ///         builds its keyring by deserialising a JSON document with a fixed
    ///         base32 secret. That has a pleasant side effect -- it exercises the
    ///         exact `Deserialize` path a real keyring file takes, so the fixture
    ///         cannot drift from the production format.
    /// KID: We write down a pretend handshake we already know, so we can knock
    ///      correctly on purpose.
    const KNOWN_SECRET: [u8; 32] = [0x5a; 32];

    /// Build a keyring containing only "alice", holding `KNOWN_SECRET`.
    fn test_keyring() -> Keyring {
        let known = crate::secret::MasterSecret::from_bytes(KNOWN_SECRET);
        let json = format!(
            r#"{{"entries":{{"alice":{{"user":"alice","secret":"{}","enrolled_at":0}}}}}}"#,
            known.to_base32()
        );
        serde_json::from_str(&json).expect("test keyring must parse")
    }

    fn fixture() -> Fixture {
        let known = crate::secret::MasterSecret::from_bytes(KNOWN_SECRET);
        let keyring = test_keyring();

        // A small config so the ranges are easy to reason about.
        let mut config = ServerConfig::default();
        config.knock_range = PortRange::new(40_000, 40_099).unwrap();
        config.open_range = PortRange::new(50_000, 50_009).unwrap();
        config.step_seconds = 30;
        config.step_skew = 1;
        config.knock_count_min = 3;
        config.knock_count_max = 3; // fixed length: simpler assertions
                                    // The fixture uses threshold 1 so the existing single-failure tests stay
                                    // meaningful. Threshold 1 is still *supported* -- it is just no longer
                                    // the default (see `ban_fail_threshold`). The rolling-window behaviour
                                    // has its own tests, below.
        config.ban_fail_threshold = 1;
        config.ban_window_seconds = 3600;
        config.ban_ttl_seconds = 0; // permanent, so tests do not race the clock
        config.open_ttl_seconds = 30;
        config.validate().expect("fixture config must be valid");

        // Pick a "now" that sits in the middle of a time step, so a ±1 second
        // wobble in the test cannot change the step.
        let now = 1_000_000u64; // step = 33333 (since 1_000_000 / 30 = 33333.33)
        let step = crate::crypto::time_step(now, config.step_seconds);
        let spec = crate::crypto::derive_knock_spec(&known, "alice", step, &config);

        let banlist = BanList::new(); // no persistence path: nothing touches disk
        let engine = Engine::new(keyring, config.clone(), banlist);

        Fixture {
            engine,
            config,
            spec,
            now,
            step,
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Send a knock for `port` from `addr` at `at`.
    ///
    /// EXPERT: This takes `&mut Engine` rather than `&mut Fixture` on purpose.
    ///         Passing the whole fixture while also reading `f.now` for the
    ///         timestamp would be two overlapping borrows of `f` (one mutable for
    ///         the engine, one shared for the clock), which the borrow checker
    ///         correctly rejects. Narrowing the helper to the engine it actually
    ///         needs is the idiomatic fix -- and it is the right API anyway: the
    ///         helper has no business knowing about the spec or the config.
    /// KID: Give the bouncer the tap, not the whole office.
    fn knock(engine: &mut Engine, addr: IpAddr, port: u16, at: u64) -> Outcome {
        engine.observe(KnockEvent {
            src_ip: addr,
            dst_port: port,
            at,
        })
    }

    #[test]
    fn full_correct_sequence_authorises() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 1);
        let ports = f.spec.knock_ports.clone();
        assert_eq!(ports.len(), 3);

        // First two knocks: progress, not yet authorised.
        for (i, &p) in ports.iter().enumerate().take(2) {
            match knock(&mut f.engine, addr, p, f.now) {
                Outcome::Progress { matched, total, .. } => {
                    assert_eq!(matched, i + 1);
                    assert_eq!(total, 3);
                }
                other => panic!("expected Progress at knock {i}, got {other:?}"),
            }
        }

        // Third knock: authorised.
        let last = ports[2];
        match knock(&mut f.engine, addr, last, f.now) {
            Outcome::Authorised {
                user, port, grant, ..
            } => {
                assert_eq!(user, "alice");
                assert_eq!(port, f.spec.open_port);
                assert_eq!(grant.port, f.spec.open_port);
                assert_eq!(grant.expires_at, f.now + 30);
            }
            other => panic!("expected Authorised, got {other:?}"),
        }

        // The port is now open for that IP.
        assert!(f.engine.auth().is_open(addr, f.now));
    }

    #[test]
    fn wrong_first_knock_bans_immediately() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 2);
        // Find a port inside the knock range that is NOT the first expected port.
        let wrong = (40_000u16..40_100)
            .find(|p| !f.spec.knock_ports.contains(p))
            .expect("there must be an unused port in a 100-port range");

        match knock(&mut f.engine, addr, wrong, f.now) {
            Outcome::Banned { ip, failures } => {
                assert_eq!(ip, addr);
                assert_eq!(failures, 1); // threshold is 1
            }
            other => panic!("expected Banned, got {other:?}"),
        }
        assert!(f.engine.banlist().is_banned(addr, f.now));
    }

    #[test]
    fn out_of_range_port_is_ignored_not_banned() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 3);
        // Port 80 is nowhere near the knock range.
        let outcome = knock(&mut f.engine, addr, 80, f.now);
        assert_eq!(outcome, Outcome::Ignored);
        // Crucially: NOT banned. This is the property that stops the ban list
        // from filling with the entire internet.
        assert!(!f.engine.banlist().is_banned(addr, f.now));
        assert_eq!(f.engine.tracked_ips(), 0);
    }

    #[test]
    fn banned_ip_is_ignored_even_with_correct_knocks() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 4);
        // Ban them directly.
        let _ = f.engine.banlist_mut().ban(addr, f.now, 0, "test");

        // Now even a perfect sequence must do nothing.
        let ports = f.spec.knock_ports.clone();
        for &p in &ports {
            assert_eq!(knock(&mut f.engine, addr, p, f.now), Outcome::Ignored);
        }
        assert!(!f.engine.auth().is_open(addr, f.now));
    }

    #[test]
    fn open_ip_is_ignored_while_door_is_open() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 5);
        let ports = f.spec.knock_ports.clone();
        for &p in &ports {
            let _ = knock(&mut f.engine, addr, p, f.now);
        }
        assert!(f.engine.auth().is_open(addr, f.now));

        // A further knock from the same IP must be ignored, not counted as a
        // failure (which would ban the very user we just let in!).
        assert_eq!(
            knock(&mut f.engine, addr, ports[0], f.now),
            Outcome::Ignored
        );
        assert!(!f.engine.banlist().is_banned(addr, f.now));
    }

    #[test]
    fn knock_at_wrong_position_restarts_progress() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 6);
        let ports = f.spec.knock_ports.clone();

        // First knock is correct.
        assert!(matches!(
            knock(&mut f.engine, addr, ports[0], f.now),
            Outcome::Progress { .. }
        ));

        // Second knock sends the *third* port instead of the second. That is a
        // failure, and with threshold 1 it bans.
        let outcome = knock(&mut f.engine, addr, ports[2], f.now);
        assert!(matches!(outcome, Outcome::Banned { .. }), "got {outcome:?}");
    }

    #[test]
    fn clock_skew_tolerance_accepts_neighbouring_step() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 7);

        // Derive the spec for the NEXT time step (as if the client's clock is
        // one window ahead).
        let next_step = f.step + 1;
        let known = crate::secret::MasterSecret::from_bytes([0x5a; 32]);
        let next_spec = crate::crypto::derive_knock_spec(&known, "alice", next_step, &f.config);

        // Knocking that sequence now must still work, because step_skew = 1.
        for &p in &next_spec.knock_ports {
            let _ = knock(&mut f.engine, addr, p, f.now);
        }
        match f.engine.auth().get(addr, f.now) {
            Some(grant) => assert_eq!(grant.port, next_spec.open_port),
            None => panic!("skew tolerance should have authorised the neighbour step"),
        }
    }

    #[test]
    fn outside_skew_window_is_rejected() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 8);

        // Two steps ahead is outside the ±1 window.
        let far_step = f.step + 2;
        let known = crate::secret::MasterSecret::from_bytes([0x5a; 32]);
        let far_spec = crate::crypto::derive_knock_spec(&known, "alice", far_step, &f.config);

        // The first knock should not match anything -> banned.
        let outcome = knock(&mut f.engine, addr, far_spec.knock_ports[0], f.now);
        assert!(
            matches!(outcome, Outcome::Banned { .. }),
            "a sequence from too far in the future must not be accepted, got {outcome:?}"
        );
    }

    #[test]
    fn sweep_closes_expired_grants() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 9);
        let ports = f.spec.knock_ports.clone();
        for &p in &ports {
            let _ = knock(&mut f.engine, addr, p, f.now);
        }
        assert!(f.engine.auth().is_open(addr, f.now));

        // Before expiry: nothing to sweep.
        let early = f.engine.sweep(f.now + 10);
        assert!(early.expired_grants.is_empty());

        // After expiry: exactly one grant, carrying the port to close.
        let late = f.engine.sweep(f.now + 31);
        assert_eq!(late.expired_grants.len(), 1);
        assert_eq!(late.expired_grants[0].port, f.spec.open_port);
        assert_eq!(late.expired_grants[0].ip, addr);
    }

    #[test]
    fn sweep_expires_bans_and_reports_them() {
        // Reconfigure for a finite ban TTL.
        let mut config = ServerConfig::default();
        config.knock_range = PortRange::new(40_000, 40_099).unwrap();
        config.open_range = PortRange::new(50_000, 50_009).unwrap();
        config.knock_count_min = 3;
        config.knock_count_max = 3;
        config.ban_fail_threshold = 1;
        config.ban_window_seconds = 3600;
        config.ban_ttl_seconds = 100;
        let keyring = test_keyring();
        let mut engine = Engine::new(keyring, config.clone(), BanList::new());

        let addr = ip(10, 0, 0, 10);
        // Pick a port inside the knock range that is NOT the first expected
        // knock. Deriving the spec first is the only reliable way to find one.
        let spec = crate::crypto::derive_knock_spec(
            &crate::secret::MasterSecret::from_bytes(KNOWN_SECRET),
            "alice",
            crate::crypto::time_step(1_000_000, 30),
            &config,
        );
        let wrong = (40_000u16..40_100)
            .find(|p| !spec.knock_ports.contains(p))
            .unwrap();

        let _ = engine.observe(KnockEvent {
            src_ip: addr,
            dst_port: wrong,
            at: 1_000_000,
        });
        assert!(engine.banlist().is_banned(addr, 1_000_000));

        // At t + 100 the ban must expire and be reported.
        let report = engine.sweep(1_000_100);
        assert_eq!(report.expired_bans, vec![addr]);
        assert!(!engine.banlist().is_banned(addr, 1_000_100));
    }

    #[test]
    fn spec_cache_stays_bounded() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 11);
        // Observe packets across many time steps. The cache must not grow with
        // the number of steps seen.
        for i in 0..200u64 {
            let at = f.now + i * 30; // one new step per iteration
                                     // A port outside the knock range: cheap, and still exercises pruning.
            let _ = knock(&mut f.engine, addr, 80, at);
        }
        // Internally the cache holds at most 2*skew+1 = 3 entries. We cannot
        // read it directly, but `tracked_ips` must also stay tiny because every
        // packet was out of range.
        assert!(f.engine.tracked_ips() <= 1);
    }

    #[test]
    fn rollback_removes_the_grant() {
        let mut f = fixture();
        let addr = ip(10, 0, 0, 12);
        let ports = f.spec.knock_ports.clone();
        for &p in &ports {
            let _ = knock(&mut f.engine, addr, p, f.now);
        }
        assert!(f.engine.auth().is_open(addr, f.now));

        // Simulate a firewall failure.
        let rolled = f.engine.rollback_authorisation(addr);
        assert!(rolled.is_some());
        assert!(!f.engine.auth().is_open(addr, f.now));
    }

    #[test]
    fn raising_the_threshold_requires_multiple_failures() {
        // Rebuild with threshold 3.
        let mut config = ServerConfig::default();
        config.knock_range = PortRange::new(40_000, 40_099).unwrap();
        config.open_range = PortRange::new(50_000, 50_009).unwrap();
        config.knock_count_min = 3;
        config.knock_count_max = 3;
        config.ban_fail_threshold = 3;
        config.ban_window_seconds = 3600;
        let keyring = test_keyring();
        let mut engine = Engine::new(keyring, config.clone(), BanList::new());

        let addr = ip(10, 0, 0, 13);
        let spec = crate::crypto::derive_knock_spec(
            &crate::secret::MasterSecret::from_bytes(KNOWN_SECRET),
            "alice",
            crate::crypto::time_step(1_000_000, 30),
            &config,
        );
        let wrong = (40_000u16..40_100)
            .find(|p| !spec.knock_ports.contains(p))
            .unwrap();

        // First two failures: ignored, not banned.
        for _ in 0..2 {
            let o = engine.observe(KnockEvent {
                src_ip: addr,
                dst_port: wrong,
                at: 1_000_000,
            });
            assert_eq!(o, Outcome::Ignored);
        }
        assert!(!engine.banlist().is_banned(addr, 1_000_000));

        // Third failure: banned.
        let o = engine.observe(KnockEvent {
            src_ip: addr,
            dst_port: wrong,
            at: 1_000_000,
        });
        match o {
            Outcome::Banned { failures, .. } => assert_eq!(failures, 3),
            other => panic!("expected Banned, got {other:?}"),
        }
    }

    #[test]
    fn manual_clock_is_controllable() {
        // A test of the test infrastructure itself -- worth having, because a
        // broken clock would make every timing test meaningless.
        let clock = ManualClock::new(1000);
        assert_eq!(clock.now(), 1000);
        clock.advance(30);
        assert_eq!(clock.now(), 1030);
        clock.set(5);
        assert_eq!(clock.now(), 5);
    }

    // =======================================================================
    // Rolling-window failure rate limiting
    //
    // These are the tests for the fix to the spoofed-source denial of service.
    // The property under test: a *single* spoofed packet can no longer ban an
    // address; it takes `ban_fail_threshold` packets inside `ban_window_seconds`.
    // =======================================================================

    /// Build an engine with a given threshold and window, plus the "wrong" port
    /// for the fixture's current step (a port in the knock range that is not part
    /// of alice's sequence).
    fn engine_with_rate_limit(threshold: u32, window: u64) -> (Engine, u16, u64) {
        let mut config = ServerConfig::default();
        config.knock_range = PortRange::new(40_000, 40_099).unwrap();
        config.open_range = PortRange::new(50_000, 50_009).unwrap();
        config.knock_count_min = 3;
        config.knock_count_max = 3;
        config.ban_fail_threshold = threshold;
        config.ban_window_seconds = window;
        config.ban_ttl_seconds = 0; // permanent, so tests do not race a TTL
        config.validate().expect("rate-limit config must be valid");

        let now = 1_000_000u64;
        let step = crate::crypto::time_step(now, config.step_seconds);
        let spec = crate::crypto::derive_knock_spec(
            &crate::secret::MasterSecret::from_bytes(KNOWN_SECRET),
            "alice",
            step,
            &config,
        );
        let wrong = (40_000u16..40_100)
            .find(|p| !spec.knock_ports.contains(p))
            .expect("there must be an unused port in a 100-port range");

        let engine = Engine::new(test_keyring(), config, BanList::new());
        (engine, wrong, now)
    }

    /// THE regression test for the spoofing DoS.
    ///
    /// EXPERT: Before the rate limit, one packet from a spoofed source banned
    ///         that source. An off-path attacker could therefore ban any address
    ///         they liked -- a censorship tool, not a security feature. This test
    ///         asserts the fixed property: one packet is not enough.
    /// KID: One prank tap with someone else's name on it must not get them
    ///      thrown out.
    #[test]
    fn one_spoofed_packet_cannot_ban() {
        let (mut engine, wrong, now) = engine_with_rate_limit(5, 3600);
        let victim = ip(198, 51, 100, 7);

        // A single packet bearing the victim's (spoofed) address.
        let outcome = engine.observe(KnockEvent {
            src_ip: victim,
            dst_port: wrong,
            at: now,
        });

        // It must NOT ban. This is the whole point of the fix.
        assert_eq!(outcome, Outcome::Ignored);
        assert!(
            !engine.banlist().is_banned(victim, now),
            "a single spoofed packet must not ban the victim"
        );
    }

    /// Reaching the threshold inside the window does ban.
    #[test]
    fn threshold_failures_within_window_ban() {
        let (mut engine, wrong, now) = engine_with_rate_limit(5, 3600);
        let attacker = ip(198, 51, 100, 8);

        // The first four failures are below the threshold.
        for i in 0..4u64 {
            let outcome = engine.observe(KnockEvent {
                src_ip: attacker,
                dst_port: wrong,
                // Spread them inside the window.
                at: now + i * 10,
            });
            assert_eq!(
                outcome,
                Outcome::Ignored,
                "failure {} must not ban yet",
                i + 1
            );
            assert!(!engine.banlist().is_banned(attacker, now + i * 10));
        }

        // The fifth reaches the threshold.
        let outcome = engine.observe(KnockEvent {
            src_ip: attacker,
            dst_port: wrong,
            at: now + 40,
        });
        match outcome {
            Outcome::Banned {
                ip: banned,
                failures,
            } => {
                assert_eq!(banned, attacker);
                assert_eq!(failures, 5);
            }
            other => panic!("expected Banned on the 5th failure, got {other:?}"),
        }
        assert!(engine.banlist().is_banned(attacker, now + 40));
    }

    /// THE rolling-window test: failures older than the window do not count.
    ///
    /// EXPERT: This is what distinguishes a rolling window from a fixed bucket.
    ///         A bucket would still hold these failures if they fell in the same
    ///         calendar period; a rolling window forgets them because they are
    ///         older than `window` seconds relative to *now*.
    /// KID: Mistakes you made ages ago do not count against you any more.
    #[test]
    fn failures_age_out_of_the_window() {
        let (mut engine, wrong, now) = engine_with_rate_limit(5, 100);
        let addr = ip(198, 51, 100, 9);

        // Four failures at t=0.
        for _ in 0..4 {
            let _ = engine.observe(KnockEvent {
                src_ip: addr,
                dst_port: wrong,
                at: now,
            });
        }
        assert!(!engine.banlist().is_banned(addr, now));

        // Wait out the window, then one more failure. If the old four counted,
        // this would be the fifth and would ban. They must have aged out, so it
        // is the *first* failure of a fresh window.
        let later = now + 101; // strictly past the 100s window
        let outcome = engine.observe(KnockEvent {
            src_ip: addr,
            dst_port: wrong,
            at: later,
        });
        assert_eq!(
            outcome,
            Outcome::Ignored,
            "failures older than the window must not count"
        );
        assert!(
            !engine.banlist().is_banned(addr, later),
            "the aged-out failures must not have triggered a ban"
        );
    }

    /// A burst spread across the window boundary must not accumulate.
    ///
    /// EXPERT: This is the attack the rolling window exists to defeat: send
    ///         `threshold - 1` failures just before the boundary and
    ///         `threshold - 1` just after, hoping a fixed bucket resets and
    ///         effectively grants `2 * (threshold - 1)`. With a rolling window,
    ///         by the time the second burst arrives the first has aged out, so
    ///         the count never reaches the threshold.
    /// KID: You cannot get extra tries by waiting for the clock to tick over.
    #[test]
    fn burst_across_the_boundary_does_not_accumulate() {
        let window = 100u64;
        let (mut engine, wrong, now) = engine_with_rate_limit(5, window);
        let addr = ip(198, 51, 100, 10);

        // Four failures, as late as possible while still in the first window.
        for i in 0..4u64 {
            let _ = engine.observe(KnockEvent {
                src_ip: addr,
                dst_port: wrong,
                at: now + i,
            });
        }
        assert!(!engine.banlist().is_banned(addr, now));

        // Four more, after the first four have aged out.
        let base = now + window + 1;
        for i in 0..4u64 {
            let at = base + i;
            let outcome = engine.observe(KnockEvent {
                src_ip: addr,
                dst_port: wrong,
                at,
            });
            assert_eq!(
                outcome,
                Outcome::Ignored,
                "the second burst must start a fresh count, not continue the old one"
            );
        }
        assert!(!engine.banlist().is_banned(addr, base + 3));
    }

    /// The failure ring must not grow without bound under a flood.
    ///
    /// EXPERT: A memory-growth bug in a security daemon is a slow, invisible
    ///         failure, and the failure ring is attacker-influenceable (one entry
    ///         per spoofed packet). `record_failure` caps the stored length at
    ///         the threshold, so this asserts the cap holds even when we feed it
    ///         far more failures than the threshold *without* letting it ban
    ///         (by using a threshold high enough that the test stays below it).
    /// KID: Even if someone taps a thousand wrong doors, our notepad does not
    ///      get a thousand lines longer.
    #[test]
    fn failure_ring_is_bounded() {
        // A high threshold so the flood does not trigger a ban and clear state.
        let (mut engine, wrong, now) = engine_with_rate_limit(1000, 3600);
        let addr = ip(198, 51, 100, 11);

        // 500 failures, all inside the window.
        for i in 0..500u64 {
            let _ = engine.observe(KnockEvent {
                src_ip: addr,
                dst_port: wrong,
                at: now + i,
            });
        }
        // No ban (we are below the threshold of 1000)...
        assert!(!engine.banlist().is_banned(addr, now + 499));

        // ...and the stored ring must be capped at the threshold, not 500.
        let stored = engine
            .states
            .get(&addr)
            .map(|s| s.failures.len())
            .unwrap_or(0);
        assert!(
            stored <= 1000,
            "the failure ring must be capped at the threshold, found {stored}"
        );
    }

    /// The failure count must be per-IP, not global.
    ///
    /// EXPERT: A shared counter would let one attacker exhaust the allowance for
    ///         every other address -- a trivial way to lock out the world, and
    ///         the mirror image of the bug we just fixed.
    /// KID: Your mistakes are your own. Nobody else's taps get you thrown out.
    #[test]
    fn failure_counting_is_per_ip() {
        let (mut engine, wrong, now) = engine_with_rate_limit(5, 3600);
        let a = ip(198, 51, 100, 12);
        let b = ip(198, 51, 100, 13);

        // Four failures from A, four from B -- interleaved.
        for i in 0..4u64 {
            let _ = engine.observe(KnockEvent {
                src_ip: a,
                dst_port: wrong,
                at: now + i,
            });
            let _ = engine.observe(KnockEvent {
                src_ip: b,
                dst_port: wrong,
                at: now + i,
            });
        }
        // Neither has reached five.
        assert!(!engine.banlist().is_banned(a, now));
        assert!(!engine.banlist().is_banned(b, now));

        // A's fifth bans A only.
        let outcome = engine.observe(KnockEvent {
            src_ip: a,
            dst_port: wrong,
            at: now + 4,
        });
        assert!(matches!(outcome, Outcome::Banned { .. }));
        assert!(engine.banlist().is_banned(a, now + 4));
        assert!(
            !engine.banlist().is_banned(b, now + 4),
            "B must not be banned by A's failures"
        );
    }

    /// A correct knock must still work with the rate limit in place.
    ///
    /// EXPERT: The obvious regression risk of touching the failure path is
    ///         breaking the success path. This test is the guard.
    #[test]
    fn correct_knock_still_authorises_under_rate_limiting() {
        let (mut engine, _wrong, now) = engine_with_rate_limit(5, 3600);
        let addr = ip(198, 51, 100, 14);

        let cfg = engine.config().clone();
        let spec = crate::crypto::derive_knock_spec(
            &crate::secret::MasterSecret::from_bytes(KNOWN_SECRET),
            "alice",
            crate::crypto::time_step(now, cfg.step_seconds),
            &cfg,
        );
        for &p in &spec.knock_ports {
            let _ = engine.observe(KnockEvent {
                src_ip: addr,
                dst_port: p,
                at: now,
            });
        }
        assert!(engine.auth().is_open(addr, now));
    }

    /// A failure *below* the threshold must not leave the IP banned later.
    ///
    /// EXPERT: Guards against a class of bug where the state is updated but a
    ///         later read misinterprets it. Cheap to assert, catches a whole
    ///         family of mistakes.
    #[test]
    fn sub_threshold_failures_leave_no_ban() {
        let (mut engine, wrong, now) = engine_with_rate_limit(5, 3600);
        let addr = ip(198, 51, 100, 15);
        for _ in 0..4 {
            let _ = engine.observe(KnockEvent {
                src_ip: addr,
                dst_port: wrong,
                at: now,
            });
        }
        // Check well after the observation, and at a later time.
        assert!(!engine.banlist().is_banned(addr, now));
        assert!(!engine.banlist().is_banned(addr, now + 10_000));
    }
}
