// ============================================================================
//  src/config.rs  --  everything the operator chooses
// ============================================================================
//
//  EXPERT VIEW:
//    Configuration is data, and data wants to be a struct with `serde`
//    derives so it round-trips through JSON for free. The design principle here
//    is *no magic numbers buried in logic*: every threshold, every range, every
//    timeout lives in this file, so an operator can audit the security posture
//    by reading exactly one document.
//
//    We split config into two types that are deliberately NOT the same:
//      * `ServerConfig` -- the daemon's view (ranges, listener, ban policy).
//      * `ClientConfig` -- the client's view (server address, mode, secret).
//    Sharing one struct would force every client to carry firewall settings and
//    every server to carry a user secret. Bad coupling. Two types, one file,
//    because they are two halves of one conversation.
//
//    `PortRange` is the interesting little type. It exists to make an invalid
//    range *unrepresentable*: you cannot construct one with `lo > hi`, because
//    the only constructors validate. This is the "parse, don't validate" idea
//    from Alexis King's famous essay -- turn a fuzzy thing into a precise thing
//    once, at the boundary, and every later use is total.
//
//  KID VIEW:
//    This file is the settings page of a video game. Before you play, you pick
//    how many taps count as the secret knock, which doors can be tapped, how
//    long the door stays open, and how quickly we kick out someone who taps
//    wrong. The `PortRange` bit is a safety lock that refuses to save a setting
//    like "doors 5000 to 3000", because that sentence means nothing.
// ============================================================================

use crate::error::{OtkpError, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::PathBuf;

// ===========================================================================
//  PortRange -- an inclusive range of ports that is always valid
// ===========================================================================
/// An inclusive `u16` port range, e.g. `40000..=50000`.
///
/// EXPERT: A newtype wrapper (a struct with one field) around the bounds. We
///         could have used `RangeInclusive<u16>` directly, but that type lets
///         `lo > hi` exist, which would silently produce empty ranges and
///         off-by-one bugs. Wrapping it means the invariant "lo <= hi" is
///         enforced at construction and can be relied on everywhere else.
/// KID: A box with two numbers on it. The box refuses to close if the first
///      number is bigger than the second, so you can never end up with a
///      backwards range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    /// The lowest port in the range (inclusive).
    pub lo: u16,
    /// The highest port in the range (inclusive).
    pub hi: u16,
}

impl PortRange {
    /// Build a validated `PortRange`.
    ///
    /// EXPERT: Returns `Result` rather than panicking, because the values come
    ///         from a config file and a config typo must be a *message*, not a
    ///         crash loop under systemd. The two checks (order, non-zero) are
    ///         the entire invariant of this type.
    /// KID: "Please make me a range, and if the numbers are silly, say so
    ///      politely instead of exploding."
    pub fn new(lo: u16, hi: u16) -> Result<Self> {
        // Port 0 is not a usable destination port; it means "any port" to some
        // APIs, which would be dangerously surprising in a firewall rule.
        if lo == 0 {
            return Err(OtkpError::config("port range lower bound must not be 0"));
        }
        // A backwards range is almost certainly a typo, and it would make every
        // `contains` check return false, silently disabling the feature.
        if lo > hi {
            return Err(OtkpError::config(format!(
                "port range lower bound {lo} is greater than upper bound {hi}"
            )));
        }
        Ok(PortRange { lo, hi })
    }

    /// Is `port` inside the range (inclusive on both ends)?
    ///
    /// EXPERT: `&self` borrows rather than consumes, so `range.contains(p)` can
    ///         be called repeatedly on a field without moving it. `PortRange` is
    ///         `Copy`, so it would also work by value -- but taking `&self` is
    ///         the idiomatic default and keeps call sites unchanged if the type
    ///         later stops being `Copy`.
    /// KID: "Is this number inside the box?"
    pub fn contains(&self, port: u16) -> bool {
        // Note the `=` on both comparisons: inclusive.
        port >= self.lo && port <= self.hi
    }

    /// How many ports the range covers, as a `u32` to avoid overflow.
    ///
    /// EXPERT: `hi - lo + 1` can be 65535 (for 1..=65535), which fits in `u16`,
    ///         but we widen to `u32` *before* the arithmetic so the subtraction
    ///         can never wrap. Widening first is the habit that prevents the
    ///         classic "subtract two u16s and wrap around" bug.
    /// KID: How many doors are in the box.
    pub fn count(&self) -> u32 {
        // `as u32` widens; it does not truncate, because u32 is bigger.
        (self.hi as u32) - (self.lo as u32) + 1
    }

    /// The number of ports as an inclusive `RangeInclusive`, for iterating.
    ///
    /// EXPERT: A convenience adapter so callers can write `for p in range.iter()`
    ///         or `range.iter().map(..)` without knowing the field names.
    /// KID: Turn the box into a list you can walk through.
    pub fn iter(&self) -> RangeInclusive<u16> {
        self.lo..=self.hi
    }
}

// ===========================================================================
//  FirewallConfig -- which backend to drive, and how
// ===========================================================================
/// Which firewall backend the daemon should use, plus backend-specific options.
///
/// EXPERT: Modelled as a *tagged* enum via serde's `#[serde(tag = "backend")]`.
///         On the wire that means:
///             { "backend": "Iptables", "chain": "OTKP" }
///         instead of the default externally-tagged form
///             { "Iptables": { "chain": "OTKP" } }
///         The tagged form is far friendlier to read and hand-edit, which
///         matters for an operator-facing config file.
/// KID: A multiple-choice question: "How should I open the door? With the
///      iptables tool, the nft tool, my own script, or just pretend?"
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend")]
pub enum FirewallConfig {
    /// Do not touch the firewall at all; log what *would* happen.
    ///
    /// EXPERT: This is the single most important backend for adoption: an
    ///         operator can run the daemon on a production host for a week,
    ///         see the exact rules it would have installed, and gain confidence
    ///         before giving it the ability to change anything. Safe defaults
    ///         are a feature.
    /// KID: "Practice mode." We say what we *would* do but change nothing.
    DryRun,

    /// Drive `iptables` (IPv4) and/or `ip6tables` (IPv6) with a dedicated chain.
    Iptables {
        /// Name of the chain we create and jump to from INPUT.
        ///
        /// EXPERT: A dedicated chain means every rule we own is in one place.
        ///         We never insert into `INPUT` itself beyond a single `-j OTKP`
        ///         jump, so `iptables -F OTKP` cleanly removes everything we did.
        /// KID: We keep all our own rules in our own drawer, not mixed into the
        ///      family's drawer.
        chain: String,
    },

    /// Drive `nft` (nftables), the modern Linux packet-filter.
    Nftables {
        /// Name of the nft table we create.
        table: String,
        /// Name of the set (a named collection of IP addresses) we add to.
        ///
        /// EXPERT: nftables sets are the natural fit: we create one set for
        ///         "authorised IPs", one for "banned IPs", and the rules simply
        ///         test `ip saddr @otkp_authorised`. Adding an IP is then an
        ///         O(1) set insertion instead of appending a rule, and removal
        ///         is a set deletion rather than a rule-index hunt.
        /// KID: Two guest lists on the door: "allowed in" and "banned".
        set: String,
    },

    /// Run an operator-supplied shell command with `{ip}`, `{port}`, `{action}`.
    ///
    /// EXPERT: The escape hatch. Some environments (BSD `pf`, cloud security
    ///         groups, a custom controller) have no iptables at all. Rather than
    ///         grow N backends, we expose one templating backend and document
    ///         the substitution rules. The security caveat is written large in
    ///         the code: the command is run *without* a shell, so `{ip}` cannot
    ///         inject shell metacharacters.
    /// KID: "If you have a special door-locking machine, tell me the magic
    ///      words to say to it, and I will say them for you."
    Command {
        /// The program to run, e.g. `/usr/local/bin/my-fw`.
        ///
        /// EXPERT: Stored as the first argv element, NOT as a shell string. We
        ///         pass it to `Command::new` directly.
        program: String,
        /// Fixed arguments, in order. May contain the placeholders below.
        args: Vec<String>,
    },
}

impl Default for FirewallConfig {
    /// The default backend is [`FirewallConfig::DryRun`].
    ///
    /// EXPERT: Choosing the *safe* option as `Default` means a config file that
    ///         omits the firewall section cannot accidentally start rewriting
    ///         the host's firewall. Security-sensitive defaults must fail safe.
    /// KID: If you do not say how to open the door, we do not open any door.
    fn default() -> Self {
        FirewallConfig::DryRun
    }
}

// ===========================================================================
//  ServerConfig -- the daemon's settings
// ===========================================================================
/// Everything `otkp serve` needs to know.
///
/// EXPERT: All fields are public because this is a plain data record (a "DTO").
///         Behaviour lives in methods and in other modules. The rule of thumb:
///         public fields for pure data, private fields + methods for types with
///         invariants. `ServerConfig` has no invariants beyond what `PortRange`
///         already enforces, so public fields are honest and convenient.
/// KID: The whole settings sheet the server reads before it starts work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Where to listen for knocks in `udp` mode. Ignored in `raw` mode.
    ///
    /// EXPERT: `SocketAddr` serialises to `"0.0.0.0:62201"`, which is readable.
    ///         We default to all interfaces because a knock listener should be
    ///         reachable from wherever the user is; the *security* comes from
    ///         the sequence, not from binding to a private address.
    /// KID: The one door we keep slightly ajar so we can hear taps on it.
    pub listen_addr: SocketAddr,

    /// Which ports a knock may target.
    pub knock_range: PortRange,

    /// Which ports a successful knock may open.
    ///
    /// EXPERT: Kept separate from `knock_range` on purpose. If they overlapped,
    ///         an opened port would itself be a valid knock target, and the
    ///         state machine would have to disambiguate "is this packet a knock
    ///         or an attempt to use a port I just opened?". Disjoint ranges make
    ///         that question impossible to ask.
    /// KID: Doors you *tap* are in a different part of the house from doors you
    ///      *walk through*. Keeps things tidy.
    pub open_range: PortRange,

    /// Seconds per time window.
    ///
    /// EXPERT: Serialised as `step_seconds` in JSON. See
    ///         [`crate::DEFAULT_STEP_SECONDS`] for why 30.
    /// KID: How often the secret handshake changes.
    pub step_seconds: u64,

    /// How many time windows of clock skew to tolerate, in each direction.
    ///
    /// EXPERT: `1` means we try steps `{now-1, now, now+1}`. This costs a
    ///         constant factor of `2*skew+1` in derivation work per packet, and
    ///         it buys tolerance for a client whose clock is off by up to one
    ///         window. Raising it trades CPU and a slightly larger replay window
    ///         for robustness. Do not raise it without understanding that.
    /// KID: We forgive you if your watch is a little bit wrong.
    pub step_skew: u64,

    /// Minimum number of knocks in a sequence.
    pub knock_count_min: u8,

    /// Maximum number of knocks in a sequence.
    pub knock_count_max: u8,

    /// How many *wrong* knocks, **within a rolling window**, before we ban.
    ///
    /// EXPERT: This is a *rate limit*, not a one-strike rule, and the change is a
    ///         security fix rather than a tuning preference. With the old
    ///         `ban_threshold = 1` (ban on the first failure), an off-path
    ///         attacker could ban an arbitrary address by sending a single packet
    ///         with a spoofed source -- a trivial denial of service against any
    ///         address they chose. Requiring N failures inside
    ///         [`Self::ban_window_seconds`] raises the cost from one packet to N
    ///         packets per window per victim, which makes the attack unattractive.
    ///
    /// It does NOT eliminate spoofing (see the README roadmap): the
    ///         remaining fix is to only count a failure after the source has made
    ///         some correct progress, or after a MAC-valid attempt has failed.
    ///
    /// Why a `u32`: an operator may want a generous limit for a noisy
    ///         environment, and `u32` removes any overflow anxiety.
    /// KID: How many wrong taps you get in one hour before the guard throws you
    ///      out. Not "one mistake and you are gone" -- that would let a prankster
    ///      get you thrown out by tapping a wrong door once while pretending to
    ///      be you.
    pub ban_fail_threshold: u32,

    /// The length of the rolling failure window, in seconds.
    ///
    /// EXPERT: A *rolling* window, not a fixed bucket. With a fixed bucket (say
    ///         "failures since the top of the hour"), an attacker simply waits
    ///         for the boundary and gets a fresh allowance; worse, the allowance
    ///         resets on a schedule they can predict. A rolling window means the
    ///         count is "failures in the last N seconds", so bursts cannot be
    ///         timed around a reset. Implementation: a small ring of recent
    ///         failure timestamps per IP, pruned on every observation.
    ///
    /// Default 3600 (one hour), matching the agreed policy.
    /// KID: How far back we look when counting your mistakes: the last hour,
    ///      sliding along with the clock.
    pub ban_window_seconds: u64,

    /// How long a ban lasts, in seconds. `0` means forever.
    ///
    /// EXPERT: `0`-as-forever is a common Unix idiom (`O_NONBLOCK` excepted).
    ///         We document it loudly because "I set the timeout to 0 and it
    ///         banned my office forever" is a support ticket waiting to happen.
    ///
    /// Note the interaction with `ban_window_seconds`: the window decides
    ///         how failures *accumulate*, and this decides how long the
    ///         consequence *lasts*. They are independent knobs and are
    ///         deliberately not derived from each other.
    /// KID: How long you sit in the naughty corner. Zero means "forever".
    pub ban_ttl_seconds: u64,

    /// How long an opened port stays open, in seconds.
    pub open_ttl_seconds: u64,

    /// Delay between knocks the *server* recommends to clients, in ms.
    ///
    /// EXPERT: The server does not enforce this; it is published in the
    ///         enrolment URI so clients can space their packets. Putting it in
    ///         the server config means one place to tune it for a whole fleet.
    /// KID: "Wait about this long between taps so I can count them properly."
    pub inter_knock_delay_ms: u64,

    /// Which firewall backend to drive.
    pub firewall: FirewallConfig,

    /// Optional explicit path to the ban list file.
    ///
    /// EXPERT: `Option<PathBuf>` because the CLI's `--dir` supplies a default
    ///         (`<dir>/banlist.json`). Explicit `Option` beats a magic empty
    ///         string, and `PathBuf` (rather than `String`) means we never have
    ///         to think about non-UTF-8 paths.
    /// KID: Where we keep the naughty list. Blank means "put it in the usual
    ///      place".
    pub banlist_path: Option<PathBuf>,
}

impl Default for ServerConfig {
    /// Sensible, safe defaults for a first run.
    ///
    /// EXPERT: Notice the deliberate disjointness of `knock_range` (40000-49999)
    ///         and `open_range` (60000-60999), and that `firewall` defaults to
    ///         `DryRun`. Both are examples of encoding operational safety into
    ///         the type system's default rather than into documentation.
    /// KID: The starting settings a brand-new game gives you: sensible, and
    ///      nothing dangerous turned on.
    fn default() -> Self {
        ServerConfig {
            // Port 62201 is in the IANA "unassigned" range and above 49152, so
            // it will not collide with an ephemeral client port by accident.
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 62201),
            knock_range: PortRange {
                lo: 40_000,
                hi: 49_999,
            },
            open_range: PortRange {
                lo: 60_000,
                hi: 60_999,
            },
            step_seconds: crate::DEFAULT_STEP_SECONDS,
            step_skew: 1,
            knock_count_min: 3,
            knock_count_max: 5,
            // Five failures inside one hour -> a one-hour ban. See the field
            // docs for why this replaced "ban on the first failure".
            ban_fail_threshold: 5,
            ban_window_seconds: 3600,
            ban_ttl_seconds: 3600,
            open_ttl_seconds: 30,
            inter_knock_delay_ms: 80,
            firewall: FirewallConfig::default(),
            banlist_path: None,
        }
    }
}

impl ServerConfig {
    /// Check cross-field invariants that `serde` alone cannot express.
    ///
    /// EXPERT: `serde` validates *shape* (right types, right fields) but not
    ///         *sense*. This method is the "semantic validation" pass, called
    ///         immediately after deserialisation and before the daemon starts.
    ///         Doing it here rather than in `Deserialize::deserialize` keeps the
    ///         error type clean (our `OtkpError`, not serde's) and lets us report
    ///         *all* problems rather than the first one serde trips over.
    /// KID: After reading the settings sheet, check that it makes sense: "you
    ///      said the shortest knock is 7 taps but the longest is 3 -- that is
    ///      impossible, please fix it."
    pub fn validate(&self) -> Result<()> {
        if self.knock_count_min == 0 {
            return Err(OtkpError::config("knock_count_min must be at least 1"));
        }
        if self.knock_count_min > self.knock_count_max {
            return Err(OtkpError::config(format!(
                "knock_count_min ({}) is greater than knock_count_max ({})",
                self.knock_count_min, self.knock_count_max
            )));
        }
        // The HMAC digest is 32 bytes, and we read it as big-endian u16 pairs.
        // Layout: byte 0 is the knock count; knock `i` uses bytes `1+2i` and
        // `2+2i`; the open port uses bytes `1+2*count` and `2+2*count`.
        // The last byte touched is therefore `2 + 2*count`, which must be <= 31,
        // giving `count <= 14`. (An earlier version of this comment said 15,
        // which was off by one -- the test below caught it, which is exactly why
        // the boundary deserves its own test.)
        if self.knock_count_max > 14 {
            return Err(OtkpError::config(
                "knock_count_max must be <= 14 (the 32-byte HMAC digest only has that many u16 slots)",
            ));
        }
        if self.step_seconds == 0 {
            return Err(OtkpError::config("step_seconds must not be 0"));
        }
        if self.step_skew > 10 {
            return Err(OtkpError::config(
                "step_skew above 10 would accept sequences from up to 11 windows in each direction; that is a policy decision, not a default",
            ));
        }
        if self.ban_fail_threshold == 0 {
            return Err(OtkpError::config(
                "ban_fail_threshold must be at least 1 (0 would mean 'never ban')",
            ));
        }
        if self.ban_window_seconds == 0 {
            return Err(OtkpError::config(
                "ban_window_seconds must be at least 1 (a zero-length window could never accumulate failures)",
            ));
        }
        if self.open_ttl_seconds == 0 {
            return Err(OtkpError::config(
                "open_ttl_seconds must be at least 1 (0 would open the port forever)",
            ));
        }
        // Ranges must not overlap. See the field docs for why.
        if ranges_overlap(self.knock_range, self.open_range) {
            return Err(OtkpError::config(
                "knock_range and open_range must not overlap",
            ));
        }
        // A knock must not target a port we would open, and vice versa. The
        // overlap check above already guarantees this, but an explicit check on
        // the listen port catches a subtler mistake: listening for UDP knocks on
        // a port inside the knock range means the listener itself could be
        // mistaken for a knock target in `raw` mode.
        if self.knock_range.contains(self.listen_addr.port()) {
            return Err(OtkpError::config(
                "listen_addr port must not be inside knock_range",
            ));
        }
        Ok(())
    }
}

/// Do two inclusive port ranges share at least one port?
///
/// EXPERT: Free function rather than a method because it is a symmetric
///         relation between two values of the same type -- `a.overlaps(b)`
///         reads fine, but so does `ranges_overlap(a, b)`, and the latter is
///         easier to unit-test in isolation without constructing anything.
/// KID: "Do these two boxes of numbers share a number?"
fn ranges_overlap(a: PortRange, b: PortRange) -> bool {
    // Two inclusive ranges overlap iff each starts at or before the other ends.
    a.lo <= b.hi && b.lo <= a.hi
}

// ===========================================================================
//  ClientConfig -- the client's settings
// ===========================================================================
/// Everything `otkp knock` needs to know.
///
/// EXPERT: Note the absence of `ban_threshold`, `firewall`, etc. The client has
///         no business knowing the server's policy; it needs only "where, how,
///         who, and with what secret". A narrower type is a stronger statement
///         about what the client is allowed to care about.
/// KID: The little card in your pocket that says which house to visit and what
///      the secret handshake is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    /// The server's hostname or IP, as typed by the user.
    ///
    /// EXPERT: Kept as a `String`, not a resolved `IpAddr`, because DNS must be
    ///         resolved at knock time (the server may move) and because printing
    ///         back what the user typed is friendlier than printing an IP.
    /// KID: The address of the house you are visiting.
    pub server: String,

    /// The UDP port to send knocks *to* in `udp` mode.
    pub port: u16,

    /// The user name whose secret we hold.
    pub user: String,

    /// The shared secret (base32 or hex text).
    ///
    /// EXPERT: Stored as text in the config file because that is what the user
    ///         pastes. It is parsed into a zeroising `MasterSecret` at startup.
    ///         A production client would read this from the OS keychain instead;
    ///         see the roadmap.
    /// KID: The secret handshake itself, written down.
    pub secret: String,

    /// Seconds per window. Must match the server.
    pub step_seconds: u64,

    /// `"udp"` or `"raw"`. Must match the server's `--source`.
    pub mode: String,

    /// Milliseconds to wait between knocks.
    pub inter_knock_delay_ms: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            server: "127.0.0.1".to_string(),
            port: 62201,
            user: String::new(),
            secret: String::new(),
            step_seconds: crate::DEFAULT_STEP_SECONDS,
            mode: "udp".to_string(),
            inter_knock_delay_ms: 80,
        }
    }
}

impl ClientConfig {
    /// Validate the fields that `serde` cannot.
    ///
    /// EXPERT: Note that we do NOT validate the secret here -- that is
    ///         [`crate::secret::MasterSecret::from_text`]'s job, and duplicating
    ///         it would mean two places to fix when the encoding changes. Each
    ///         check has exactly one home.
    /// KID: "You forgot to write your name" -- the simple things.
    pub fn validate(&self) -> Result<()> {
        if self.server.trim().is_empty() {
            return Err(OtkpError::config("client 'server' must not be empty"));
        }
        if self.user.trim().is_empty() {
            return Err(OtkpError::config("client 'user' must not be empty"));
        }
        if self.port == 0 {
            return Err(OtkpError::config("client 'port' must not be 0"));
        }
        if self.step_seconds == 0 {
            return Err(OtkpError::config("client 'step_seconds' must not be 0"));
        }
        // Only two transport modes exist; reject anything else loudly rather
        // than silently defaulting, which would be a confusing failure later.
        if self.mode != "udp" && self.mode != "raw" {
            return Err(OtkpError::config(format!(
                "client 'mode' must be \"udp\" or \"raw\", got \"{}\"",
                self.mode
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_range_rejects_backwards() {
        assert!(PortRange::new(5000, 4000).is_err());
        assert!(PortRange::new(0, 100).is_err());
        assert!(PortRange::new(4000, 4000).is_ok()); // single-port range is fine
    }

    #[test]
    fn port_range_contains_is_inclusive() {
        let r = PortRange::new(10, 20).unwrap();
        assert!(r.contains(10)); // lower bound is inside
        assert!(r.contains(20)); // upper bound is inside
        assert!(!r.contains(9));
        assert!(!r.contains(21));
    }

    #[test]
    fn port_range_count_is_exact() {
        // 10..=20 covers 11 ports, not 10. This is THE off-by-one to get right.
        assert_eq!(PortRange::new(10, 20).unwrap().count(), 11);
        // The widest legal range must not overflow.
        assert_eq!(PortRange::new(1, 65_535).unwrap().count(), 65_535);
    }

    #[test]
    fn overlap_detection() {
        let a = PortRange::new(100, 200).unwrap();
        let b = PortRange::new(200, 300).unwrap(); // touches at exactly 200
        let c = PortRange::new(201, 300).unwrap(); // just past
        assert!(ranges_overlap(a, b));
        assert!(!ranges_overlap(a, c));
        // Overlap must be symmetric.
        assert_eq!(ranges_overlap(a, b), ranges_overlap(b, a));
    }

    #[test]
    fn default_config_is_valid_and_disjoint() {
        let cfg = ServerConfig::default();
        cfg.validate().expect("default config must be valid");
        assert!(!ranges_overlap(cfg.knock_range, cfg.open_range));
        // The safe default must be DryRun, not a live firewall.
        assert_eq!(cfg.firewall, FirewallConfig::DryRun);
    }

    #[test]
    fn validate_catches_overlapping_ranges() {
        let mut cfg = ServerConfig::default();
        cfg.open_range = PortRange {
            lo: 45_000,
            hi: 46_000,
        }; // inside knock_range
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("must not overlap"));
    }

    #[test]
    fn validate_catches_impossible_knock_count() {
        let mut cfg = ServerConfig::default();
        cfg.knock_count_min = 9;
        cfg.knock_count_max = 3;
        assert!(cfg.validate().is_err());

        let mut cfg2 = ServerConfig::default();
        cfg2.knock_count_max = 15; // beyond the HMAC digest budget (max is 14)
        assert!(cfg2.validate().is_err());
    }

    #[test]
    fn server_config_json_round_trips() {
        let cfg = ServerConfig::default();
        let text = serde_json::to_string(&cfg).unwrap();
        let back: ServerConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(cfg, back);
        // The tagged enum form must appear, not the externally-tagged one.
        assert!(text.contains("\"backend\":\"DryRun\""), "got {text}");
    }

    #[test]
    fn client_config_rejects_bad_mode() {
        let mut c = ClientConfig::default();
        c.user = "alice".into();
        c.secret = "AAAA".into();
        c.mode = "carrier-pigeon".into();
        assert!(c.validate().is_err());
    }
}
