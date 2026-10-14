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
//  SecurityLevel -- the ratchet
// ===========================================================================
/// How much assurance this deployment has bought, from 0 upward.
///
/// EXPERT: The design principle is *ratcheting*, and the ordering is the point:
///
/// * **Level 0 must be the default**, must work anywhere, and must
///             deliver the largest gain for the least effort. A security tool
///             whose default is hard to deploy gets deployed at zero, or not at
///             all. A tool whose default is easy and whose steps are *legible*
///             gets deployed at zero and then climbed.
///           * **Every step above must add a named assurance at a named cost.**
///             An operator climbs because their threat model or their regulator
///             says so — never because the documentation shamed them into it.
///
/// Encoding the level as an enum rather than a bare integer means the
///         config file reads `"security_level": "replay_resistant"`, which is a
///         thing a human can look up. A number in a config file is a number
///         nobody understands six months later.
///
/// `Ord` is derived from declaration order, so `level >=
///         SecurityLevel::ReplayResistant` means what it looks like it means.
///         That is load-bearing for every check below.
/// KID: A ladder. The first rung is easy and already helps a lot. Each rung above
///      does one more good thing and costs one more thing. You climb as far as
///      you need to, not as far as you can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    /// **Level 0 — concealment.** The default.
    ///
    /// There is nothing to scan, and failed knocks are rate-limited rather than
    /// instantly banned.
    Basic,

    /// **Level 1 — replay-resistant.** Adds source-address binding.
    ///
    /// A captured sequence matches only when replayed from the same address,
    /// which closes both passive replay and the active race.
    ReplayResistant,

    /// **Level 2 — auditable.** Adds a structured, machine-readable event stream.
    ///
    /// Every authorisation, ban and expiry is written as one JSON object per
    /// line, so a SIEM or a person can answer "who accessed what, when" without
    /// parsing log prose.
    Auditable,
}

impl SecurityLevel {
    /// The level as a small integer, for display and comparison in prose.
    ///
    /// EXPERT: A method rather than a cast, because `as u8` on an enum is a
    ///         promise about the discriminant that nothing enforces. This
    ///         function is exhaustive, so adding a variant is a compile error
    ///         rather than a silent off-by-one.
    /// KID: Which rung of the ladder this is.
    pub const fn number(self) -> u8 {
        match self {
            SecurityLevel::Basic => 0,
            SecurityLevel::ReplayResistant => 1,
            SecurityLevel::Auditable => 2,
        }
    }

    /// The canonical lowercase name, matching the config file spelling.
    ///
    /// EXPERT: Kept in sync with `#[serde(rename_all = "snake_case")]` by the
    ///         test `names_match_serde_spelling`, because a mismatch would mean
    ///         the daemon logged a name an operator could not put in their
    ///         config.
    /// KID: The name of this rung.
    pub const fn name(self) -> &'static str {
        match self {
            SecurityLevel::Basic => "basic",
            SecurityLevel::ReplayResistant => "replay_resistant",
            SecurityLevel::Auditable => "auditable",
        }
    }

    /// What this level buys, in one line. Used in the startup log.
    ///
    /// EXPERT: The pairs (`buys`, `costs`) are deliberately adjacent in the code
    ///         so that adding a level forces you to write both. A security level
    ///         documented only by its benefit is marketing, not engineering.
    /// KID: The good thing you get.
    pub const fn buys(self) -> &'static str {
        match self {
            SecurityLevel::Basic => {
                "nothing to scan; failed knocks are rate-limited, not one-strike banned"
            }
            SecurityLevel::ReplayResistant => {
                "a captured sequence is replayable only from the same address \
                 (closes replay and the active race)"
            }
            SecurityLevel::Auditable => {
                "a machine-readable record of every authorisation, ban and expiry"
            }
        }
    }

    /// What this level costs, in one line. Used in the startup log.
    ///
    /// KID: The annoying thing you pay.
    pub const fn costs(self) -> &'static str {
        match self {
            SecurityLevel::Basic => "none — works behind NAT and on mobile clients",
            SecurityLevel::ReplayResistant => {
                "breaks NAT and mobility: the client must be told the egress \
                 address the server will see (--bind-ip)"
            }
            SecurityLevel::Auditable => "an audit file to manage, rotate and protect",
        }
    }

    /// Every level, lowest first. Used to print the ladder.
    ///
    /// EXPERT: Returning an array rather than a slice of a static, so the
    ///         compiler enforces that we listed them all — if a variant is added
    ///         and not listed here, the array length is wrong and it will not
    ///         build.
    /// KID: The whole ladder, bottom to top.
    pub const fn all() -> [SecurityLevel; 3] {
        [
            SecurityLevel::Basic,
            SecurityLevel::ReplayResistant,
            SecurityLevel::Auditable,
        ]
    }

    /// Parse a level from the CLI or a config string.
    ///
    /// EXPERT: Accepts both the number and the name, plus the hyphenated spelling
    ///         people type by habit, because an operator who writes `--security-
    ///         level 1` and one who writes `--security-level replay-resistant`
    ///         both mean the same thing and neither should be told they are
    ///         wrong. The error message lists the valid forms rather than just
    ///         rejecting.
    /// KID: Understand the number or the name, whichever you typed.
    pub fn parse(s: &str) -> Result<Self> {
        let t = s.trim().to_ascii_lowercase();
        match t.as_str() {
            "0" | "basic" | "concealment" => Ok(SecurityLevel::Basic),
            "1" | "replay-resistant" | "replay_resistant" | "replay" => {
                Ok(SecurityLevel::ReplayResistant)
            }
            "2" | "auditable" | "audit" => Ok(SecurityLevel::Auditable),
            other => Err(OtkpError::config(format!(
                "unknown security level '{other}'; expected 0/basic, \
                 1/replay-resistant, or 2/auditable"
            ))),
        }
    }
}

impl Default for SecurityLevel {
    /// Level 0.
    ///
    /// EXPERT: The safe-and-easy default. Note this is *not* the most secure
    ///         level — it is the level that gets deployed. The README says so
    ///         explicitly, and the daemon prints the ladder at startup so an
    ///         operator always knows which rung they are on and what the next
    ///         one buys.
    /// KID: Start on the bottom rung, where everyone can reach.
    fn default() -> Self {
        SecurityLevel::Basic
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

    /// Make each derived sequence single-use: once it has authorised anyone, it
    /// is dead for the rest of its window.
    ///
    /// EXPERT: This is the "burn", and it is the **roaming-friendly** replay
    ///         defence. Because it does not touch the derivation, a client can
    ///         knock from any address; the first use consumes the sequence, so a
    ///         replay from somewhere else finds it already spent.
    ///
    /// It is the complement of `bind_to_source_ip`, not an alternative:
    ///
    /// * the **burn** stops replay, but an on-path attacker who injects
    ///             *before* the legitimate knock wins the race;
    ///           * **binding** stops the race too, because a replay from another
    ///             address derives a different expectation and matches nothing.
    ///
    /// **The burn key follows the binding mode**, and this is
    ///         load-bearing. Unbound, the sequence is the same for every address,
    ///         so the key is `(user, window)` and one knock per window per user
    ///         is permitted — a second device in the same window looks exactly
    ///         like a replay, because it *is* one. Bound, each address has its own
    ///         sequence, so the key is `(user, window, address)` and multi-device
    ///         works.
    ///
    /// So: with binding off, the burn costs you multi-device. With
    ///         binding on, it costs nothing. See the design note §5.2.
    /// KID: Once a secret knock has opened the door, it is used up. Knocking the
    ///      same one again does not open the door twice — which is how we know a
    ///      copycat is knocking.
    #[serde(default = "default_true")]
    pub single_use_sequences: bool,

    /// Bind each derived sequence to the source IP address.
    ///
    /// EXPERT: When `true`, the observed source address is an input to the HMAC,
    ///         so a sequence captured on the wire matches only when replayed
    ///         *from the same address*. This defeats both passive replay and the
    ///         active race (an on-path attacker injecting a captured sequence
    ///         from their own address derives a different expectation and matches
    ///         nothing).
    ///
    /// **The cost is real: this breaks NAT and mobility.** The client must
    ///         know the address the server will observe, and behind NAT that is
    ///         not the client's local address. So a client on a NATed network
    ///         cannot use this mode without being told its egress address
    ///         explicitly. This is why the default is `false` and why the daemon
    ///         warns loudly when it is off.
    ///
    /// The trade is exactly the classic one: security against replay, at
    ///         the price of address agility. Choose deliberately.
    /// KID: When this is on, the secret knock only works if you knock from your
    ///      own front door. Someone who copies your knock and tries it from their
    ///      house gets a completely different knock back and is told "no".
    pub bind_to_source_ip: bool,

    /// Which rung of the security ladder this deployment is on.
    ///
    /// EXPERT: `#[serde(default)]` so a config written before this field existed
    ///         still loads, landing on level 0 — which is exactly the behaviour
    ///         that config had. Backwards compatibility that is also semantically
    ///         correct, rather than merely non-crashing.
    ///
    /// The level *asserts* requirements rather than merely describing
    ///         them: `validate` refuses a config whose level claims more than its
    ///         settings deliver. See `apply_security_level` for the other
    ///         direction — setting the level also sets what it requires.
    /// KID: Which rung of the ladder we are standing on.
    #[serde(default)]
    pub security_level: SecurityLevel,

    /// Where to append the structured audit stream, if level 2 is in use.
    ///
    /// EXPERT: One JSON object per line (JSON Lines), append-only, created
    ///         `0600`. JSON Lines rather than a JSON array because appending to
    ///         an array requires rewriting the closing bracket, which is not
    ///         atomic and corrupts the file on a crash; appending a line is a
    ///         single `write` and is atomic for small records.
    /// KID: The diary where we write down every decision we made.
    #[serde(default)]
    pub audit_log_path: Option<PathBuf>,

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
            // On by default: the burn costs nothing when binding is on, and at
            // level 0 it costs multi-device, which is documented rather than
            // hidden.
            single_use_sequences: true,
            // Off by default: see the field docs -- enabling it breaks NAT and
            // mobility, so it must be a deliberate operator choice.
            bind_to_source_ip: false,
            // Level 0: the rung that works anywhere. See `SecurityLevel`.
            security_level: SecurityLevel::default(),
            audit_log_path: None,
            open_ttl_seconds: 30,
            inter_knock_delay_ms: 80,
            firewall: FirewallConfig::default(),
            banlist_path: None,
        }
    }
}

impl ServerConfig {
    /// Set the security level **and everything it requires**.
    ///
    /// EXPERT: This is the ratchet's mechanism. Raising the level does not merely
    ///         record an intention — it turns on the settings that level depends
    ///         on, so an operator cannot end up claiming level 1 while silently
    ///         running level 0. `validate` then checks the same invariants from
    ///         the other direction, so a hand-edited config file is caught too.
    ///
    /// Note what it does *not* do: it never *lowers* a setting. Calling
    ///         this with level 0 leaves `bind_to_source_ip` alone, so an operator
    ///         who enabled binding by hand and then declares level 0 does not
    ///         silently lose it. Raising is automatic; lowering is deliberate.
    /// KID: When you climb a rung, we flip the switches that rung needs. But we
    ///      never flip a switch back off behind your back.
    pub fn apply_security_level(&mut self, level: SecurityLevel) {
        self.security_level = level;
        if level >= SecurityLevel::ReplayResistant {
            self.bind_to_source_ip = true;
        }
        // Level 2 additionally needs an `audit_log_path`. We deliberately do not
        // invent one here, because choosing *where* a security log lives is an
        // operational decision (which filesystem, which retention, which
        // backup). The CLI supplies a sensible default; a hand-edited config
        // must name one, and `validate` says so.
    }

    /// The next rung up, or `None` if already at the top.
    ///
    /// EXPERT: Used by the startup log to tell an operator exactly what the next
    ///         step would buy and cost. A ratchet nobody knows how to climb is a
    ///         ratchet nobody climbs, so the tool has to advertise the next rung
    ///         at the moment the operator is looking at the config.
    /// KID: "You are on rung 1. Rung 2 would give you this, and cost you that."
    pub fn next_security_level(&self) -> Option<SecurityLevel> {
        match self.security_level {
            SecurityLevel::Basic => Some(SecurityLevel::ReplayResistant),
            SecurityLevel::ReplayResistant => Some(SecurityLevel::Auditable),
            SecurityLevel::Auditable => None,
        }
    }

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
        // --- Security level consistency -------------------------------------
        // The level is an assertion about what this config delivers, so we
        // refuse a config that asserts more than it delivers. Without this, an
        // operator could set `"security_level": "replay_resistant"` in the file,
        // forget `bind_to_source_ip`, and run level 0 while every log line and
        // every auditor's note says level 1. A security claim the tool does not
        // enforce is worse than no claim at all.
        if self.security_level >= SecurityLevel::ReplayResistant && !self.bind_to_source_ip {
            return Err(OtkpError::config(
                "security_level 'replay_resistant' requires bind_to_source_ip = true \
                 (use `--security-level 1`, which sets it for you)",
            ));
        }
        if self.security_level >= SecurityLevel::Auditable && self.audit_log_path.is_none() {
            return Err(OtkpError::config(
                "security_level 'auditable' requires audit_log_path to be set \
                 (use `--security-level 2`, which defaults it into the data directory)",
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

/// A `serde` default of `true`.
///
/// EXPERT: `#[serde(default)]` on a `bool` yields `false`, which is the wrong
///         default for a field whose whole purpose is to be on. A named helper
///         makes the intent explicit and gives a config written before this
///         field existed the secure behaviour rather than the insecure one.
/// KID: If an old settings sheet does not mention this switch, we assume it is
///      ON, because ON is the safe way round.
fn default_true() -> bool {
    true
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

    // -----------------------------------------------------------------------
    // The security-level ratchet
    // -----------------------------------------------------------------------

    #[test]
    fn default_level_is_the_easy_one() {
        // The whole ratchet argument rests on the default being the rung that
        // gets deployed. If this ever changes to a higher level, the reasoning in
        // `SecurityLevel`'s docs needs revisiting.
        assert_eq!(SecurityLevel::default(), SecurityLevel::Basic);
        assert_eq!(ServerConfig::default().security_level, SecurityLevel::Basic);
    }

    #[test]
    fn level_numbers_and_names_are_ordered_and_stable() {
        let all = SecurityLevel::all();
        assert_eq!(all.len(), 3);
        for (i, level) in all.iter().enumerate() {
            assert_eq!(
                level.number() as usize,
                i,
                "levels must be numbered in order"
            );
        }
        // `Ord` must follow declaration order, because every `>=` check in
        // `validate` and `apply_security_level` depends on it.
        assert!(SecurityLevel::Basic < SecurityLevel::ReplayResistant);
        assert!(SecurityLevel::ReplayResistant < SecurityLevel::Auditable);
    }

    #[test]
    fn names_match_the_serde_spelling() {
        // If these disagree, the daemon logs a level name that an operator cannot
        // put in their config file.
        for level in SecurityLevel::all() {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, format!("\"{}\"", level.name()), "for {level:?}");
            // And it must parse back.
            let back: SecurityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }
    }

    #[test]
    fn level_parses_by_number_name_and_habit() {
        for (input, want) in [
            ("0", SecurityLevel::Basic),
            ("basic", SecurityLevel::Basic),
            ("BASIC", SecurityLevel::Basic),
            ("1", SecurityLevel::ReplayResistant),
            ("replay-resistant", SecurityLevel::ReplayResistant),
            ("replay_resistant", SecurityLevel::ReplayResistant),
            ("replay", SecurityLevel::ReplayResistant),
            ("2", SecurityLevel::Auditable),
            ("auditable", SecurityLevel::Auditable),
            (" 2 ", SecurityLevel::Auditable),
        ] {
            assert_eq!(SecurityLevel::parse(input).unwrap(), want, "for '{input}'");
        }
        let err = SecurityLevel::parse("3").unwrap_err().to_string();
        assert!(err.contains("unknown security level"), "got {err}");
        assert!(
            err.contains("auditable"),
            "the error should list the valid forms"
        );
    }

    #[test]
    fn applying_a_level_sets_what_it_requires() {
        // Level 1 must turn on binding, or the level is a label without a
        // mechanism.
        let mut cfg = ServerConfig::default();
        assert!(!cfg.bind_to_source_ip);
        cfg.apply_security_level(SecurityLevel::ReplayResistant);
        assert!(
            cfg.bind_to_source_ip,
            "level 1 must enable source-IP binding"
        );
        cfg.validate().expect("level 1 config must be valid");
    }

    #[test]
    fn applying_a_lower_level_does_not_undo_a_setting() {
        // Raising is automatic; lowering is deliberate. An operator who enabled
        // binding by hand and then declares level 0 must not silently lose it.
        let mut cfg = ServerConfig::default();
        cfg.bind_to_source_ip = true;
        cfg.apply_security_level(SecurityLevel::Basic);
        assert!(
            cfg.bind_to_source_ip,
            "declaring a lower level must not switch off a manual setting"
        );
    }

    #[test]
    fn level_one_without_binding_is_rejected() {
        // The level is an assertion about what this config delivers. A config
        // that asserts level 1 while running level 0 is worse than no claim.
        let mut cfg = ServerConfig::default();
        cfg.security_level = SecurityLevel::ReplayResistant; // claim, without setting
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("requires bind_to_source_ip"), "got {err}");
    }

    #[test]
    fn level_two_without_an_audit_path_is_rejected() {
        let mut cfg = ServerConfig::default();
        cfg.bind_to_source_ip = true;
        cfg.security_level = SecurityLevel::Auditable;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("requires audit_log_path"), "got {err}");

        // With a path, it is valid.
        cfg.audit_log_path = Some(PathBuf::from("/tmp/audit.jsonl"));
        cfg.validate().expect("level 2 with a path must be valid");
    }

    #[test]
    fn next_level_advances_then_stops() {
        let mut cfg = ServerConfig::default();
        assert_eq!(
            cfg.next_security_level(),
            Some(SecurityLevel::ReplayResistant)
        );
        cfg.apply_security_level(SecurityLevel::ReplayResistant);
        assert_eq!(cfg.next_security_level(), Some(SecurityLevel::Auditable));
        cfg.apply_security_level(SecurityLevel::Auditable);
        assert_eq!(cfg.next_security_level(), None, "the ladder must end");
    }

    #[test]
    fn every_level_documents_both_a_benefit_and_a_cost() {
        // A level documented only by its benefit is marketing. This asserts the
        // pairing exists and is non-empty for every rung, so adding a level
        // without writing its cost fails the build's tests.
        for level in SecurityLevel::all() {
            assert!(
                !level.buys().is_empty(),
                "level {level:?} has no stated benefit"
            );
            assert!(
                !level.costs().is_empty(),
                "level {level:?} has no stated cost"
            );
            assert!(!level.name().is_empty());
        }
    }

    #[test]
    fn security_level_defaults_when_absent_from_config() {
        // An old config file with no `security_level` must load and land on level
        // 0 — the behaviour it actually had.
        let old = r#"{
            "listen_addr": "0.0.0.0:62201",
            "knock_range": {"lo": 40000, "hi": 49999},
            "open_range": {"lo": 60000, "hi": 60999},
            "step_seconds": 30, "step_skew": 1,
            "knock_count_min": 3, "knock_count_max": 5,
            "ban_fail_threshold": 5, "ban_window_seconds": 3600,
            "ban_ttl_seconds": 3600, "bind_to_source_ip": false,
            "open_ttl_seconds": 30, "inter_knock_delay_ms": 80,
            "firewall": {"backend": "DryRun"}
        }"#;
        let cfg: ServerConfig = serde_json::from_str(old).expect("old config must still load");
        assert_eq!(cfg.security_level, SecurityLevel::Basic);
        assert!(cfg.audit_log_path.is_none());
        cfg.validate().expect("and it must still be valid");
    }
}
