// ============================================================================
//  src/crypto.rs  --  the derivation: secret + clock  ->  one-time knock
// ============================================================================
//
//  EXPERT VIEW:
//    This is the smallest amount of code in the project that carries the most
//    weight. Two functions live here:
//
//      * `hmac_sha256` / `hotp`  -- the OTP heritage. RFC 2104 and RFC 4226.
//      * `derive_knock_spec`     -- our own construction, specified in
//                                   docs/PROTOCOL.md.
//
//    The design principle is "derive, never transmit". The secret never moves;
//    only values computed from it do. Both sides run the same deterministic
//    function over the same inputs and therefore agree without a handshake, a
//    nonce exchange, or any network round-trip before the first knock. That is
//    the entire elegance of TOTP-style protocols, and we inherit it.
//
//    The output of the derivation is a `KnockSpec`: how many knocks, which
//    ports, and which port to open. It is a plain data struct, deliberately
//    separate from the *decision* to allow a connection (which is `engine`'s
//    job). Derivation is pure; policy is separate. Keeping "what the numbers
//    are" apart from "what we do about them" is what makes each half testable.
//
//  KID VIEW:
//    You and your friend both have the same magic recipe book (the secret).
//    Every 30 seconds, the clock on the wall tells you which page to turn to.
//    You both read the same page and get the same list of secret knocks -- even
//    though you never talked to each other! Nobody listening at the door learns
//    anything, because you never *said* the recipe out loud; you only tapped the
//    knocks it produced.
// ============================================================================

use crate::config::ServerConfig;
use crate::error::{OtkpError, Result};
use crate::secret::MasterSecret;
use crate::{DEFAULT_STEP_SECONDS, PROTOCOL_LABEL};
use hmac::{Hmac, Mac}; // `Hmac` is generic over the hash; `Mac` is the trait with update/finalize.
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;

/// `Hmac<Sha256>` is a mouthful; this alias makes signatures readable.
///
/// EXPERT: `Hmac<Sha256>` is HMAC keyed with SHA-256 -- the exact construction
///         used by TOTP, AWS SigV4, and most JWT signatures. There is
///         nothing novel or experimental here, which is the point: a novel
///         protocol should be built from boring, well-analysed primitives.
/// KID: A short nickname for the maths machine we use.
type HmacSha256 = Hmac<Sha256>;

/// `Hmac<Sha1>`: the RFC 4226 HOTP construction, kept for interoperability only.
///
/// EXPERT: See the note in Cargo.toml. This is used solely by [`hotp`], which
///         exists so `otkp enroll` can print a value any authenticator app will
///         agree with. The knock derivation uses SHA-256 exclusively.
/// KID: A second maths machine, for the phone-app number only.
type HmacSha1 = Hmac<Sha1>;

// ===========================================================================
//  Step 1: the raw HMAC-SHA256 primitive
// ===========================================================================
/// Compute `HMAC-SHA256(key, message)` and return the 32-byte tag.
///
/// EXPERT: HMAC is defined as
///             H((K' xor opad) || H((K' xor ipad) || message))
///         where `K'` is the key zero-padded (or hashed, if too long) to the
///         hash's block size, and `ipad`/`opad` are the constants 0x36/0x5c
///         repeated. We do not implement that -- the `hmac` crate does, in
///         constant time and with the length-extension protections HMAC is
///         famous for. Using the crate rather than hand-rolling is the correct
///         engineering call: it is audited and we are not.
/// KID: Mix the secret with the message through the maths machine, and get a
///      32-byte fingerprint that only someone with the secret could produce.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // `new_from_slice` can fail if the key length is invalid for the algorithm.
    // HMAC accepts any key length, so this never fails in practice -- but we
    // still avoid `expect()` in a security path (a panic is a DoS), so we fall
    // back to an all-zero tag. A zero tag will never match a real derivation, so
    // the failure mode is "authentication fails closed", which is what we want.
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return [0u8; 32],
    };
    // Feed the message. `update` may be called repeatedly to stream data.
    mac.update(message);
    // `finalize` consumes the MAC and returns a `CtOutput`. `into_bytes` gives a
    // `GenericArray<u8, 32>`; `into()` converts it to a plain `[u8; 32]`.
    let out = mac.finalize().into_bytes();
    // `out` is a `GenericArray`. `into()` needs a target type; the function
    // return type tells Rust it is `[u8; 32]`.
    out.into()
}

// ===========================================================================
//  Step 2: HOTP -- the OTP heritage, kept for interoperability and sanity checks
// ===========================================================================
/// Compute an HOTP value (RFC 4226) for a given counter.
///
/// EXPERT: This is *not* used to knock. It exists so that `otkp enroll` can
///         print a value the user can compare against Google Authenticator or
///         `oathtool`, which is how you convince yourself you copied the secret
///         correctly before you are locked out by a protocol you cannot easily
///         debug. Interop with the existing ecosystem is a feature, and RFC 4226
///         is the lingua franca.
///
/// RFC 4226 mandates HMAC-SHA1 specifically -- so unlike the rest of the
///         protocol (which uses SHA-256), this function uses SHA-1. Matching the
///         RFC exactly is the entire point of the function; a "better" hash here
///         would make the printed code disagree with every authenticator app and
///         defeat its purpose. This is a good example of a deliberate, narrow
///         exception, documented at the point where it is made.
///
/// The algorithm is "dynamic truncation": take the low nibble of byte 19
///         of the 20-byte HMAC-SHA1 output as an offset, read four bytes from
///         there, mask the top bit (to stay positive), then reduce modulo 10^digits.
/// KID: The familiar six-number code from your phone app. We keep it so you can
///      check your secret is right by comparing against your normal app.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    // HOTP always uses the counter as a big-endian 8-byte message.
    let message = counter.to_be_bytes();

    // HMAC-SHA1 specifically (see the note above).
    let mut mac = match HmacSha1::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return 0,
    };
    mac.update(&message);
    let digest = mac.finalize().into_bytes(); // 20 bytes

    // Dynamic truncation: the low nibble of the LAST byte selects the offset.
    // For SHA-1 the output is 20 bytes, so byte 19 is the last one -- exactly as
    // RFC 4226 specifies.
    let offset = (digest[19] & 0x0f) as usize;

    // Assemble a 31-bit big-endian integer from four bytes.
    // `0x7f` on the first byte clears the sign bit, which keeps the value
    // positive in languages with signed ints (a legacy of the original Java
    // reference implementation, but part of the RFC, so we match it exactly).
    let binary: u32 = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);

    // Reduce to the requested number of digits. `10u32.pow(digits)` could
    // overflow for large digits, so we clamp to the sensible range. RFC 4226
    // mandates at least 6 digits; we support 6-9.
    let digits = digits.clamp(6, 9);
    let modulus = 10u32.pow(digits);
    binary % modulus
}

/// The counter HOTP uses for a given time: `unix_seconds / step_seconds`.
///
/// EXPERT: This is the only line that turns HOTP into TOTP. TOTP is *literally*
///         HOTP with the counter derived from the clock. Worth internalising:
///         most "time-based" OTP systems are a counter-based system plus a
///         division. See RFC 6238 section 4.
/// KID: The clock picks which number of the recipe book to use.
pub fn time_step(unix_seconds: u64, step_seconds: u64) -> u64 {
    // Guard against division by zero at the lowest level. Callers validate this,
    // but a pure function should be total (never panic) on any input.
    if step_seconds == 0 {
        return 0;
    }
    unix_seconds / step_seconds
}

/// The current Unix time in whole seconds.
///
/// EXPERT: This is the one place the library reads the wall clock directly. The
///         daemon does NOT call this in its hot path -- it goes through the
///         `Clock` trait (see `engine`) so tests can inject a fake clock. This
///         function is for the CLI's convenience paths.
/// KID: "What time is it right now?"
pub fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // If the clock is before 1970 we return 0 rather than panicking. The
    // consequence is a wrong time step, i.e. a failed knock, which is a safe
    // failure -- never a crash.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ===========================================================================
//  Step 3: the knock specification
// ===========================================================================
/// Everything the two sides agree on for one time window, for one user.
///
/// EXPERT: A pure data record ("DTO"). It carries no behaviour because there is
///         no invariant to protect beyond the types themselves. Being `Clone` is
///         fine here: none of this is secret (the ports are derived *from* the
///         secret, but knowing the ports for a window you can no longer use is
///         worthless, and if you could see them you could also see the knock).
/// KID: The shopping list for one handshake: "tap these four doors, in this
///      order, and then the front door number 27488 will open for you."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnockSpec {
    /// The user this spec belongs to. Carried for logging and for the state
    /// machine, which must remember *whose* sequence an IP is progressing
    /// through.
    pub user: String,

    /// The time step this spec was derived for.
    ///
    /// EXPERT: Storing it makes the spec self-describing: the engine can compare
    ///         `spec.time_step` against the current step to decide staleness, and
    ///         logs can say exactly which window a sequence belonged to. A spec
    ///         without its window is ambiguous, and ambiguity in a security
    ///         decision is a bug waiting to happen.
    /// KID: Which page of the recipe book this list came from.
    pub time_step: u64,

    /// The ordered ports to knock, in the order they must be knocked.
    pub knock_ports: Vec<u16>,

    /// The port that opens if the whole sequence is knocked correctly.
    pub open_port: u16,
}

impl KnockSpec {
    /// How many knocks are in this sequence.
    ///
    /// EXPERT: `len()` on a `Vec` is O(1) (it reads a stored length), so calling
    ///         it in the hot loop costs nothing.
    /// KID: How many taps.
    pub fn len(&self) -> usize {
        self.knock_ports.len()
    }

    /// Is the sequence empty? Always false for a valid spec, but clippy insists
    /// that a type with `len()` also has `is_empty()`.
    ///
    /// EXPERT: `clippy::len_without_is_empty` is a lint that fires when you add
    ///         `len()` without `is_empty()`. The lint exists because a caller
    ///         writing `if spec.len() == 0` is a sign the API is awkward; giving
    ///         them `is_empty()` is the fix. Even though our answer is always
    ///         `false`, satisfying the convention keeps the crate lint-clean.
    /// KID: "Is the list empty?" It never is, but the checker wants us to say so.
    pub fn is_empty(&self) -> bool {
        self.knock_ports.is_empty()
    }
}

// ===========================================================================
//  Step 4: our derivation
// ===========================================================================
/// The exact message that goes into the HMAC for a `(user, time_step)` pair.
///
/// EXPERT: Factored out as its own function because *this byte string is the
///         protocol*. Having it in one place means a test can assert on it
///         directly, and a second implementation in another language has an
///         unambiguous reference. The `0x00` separators are load-bearing: without
///         them, `("alice", "bob")` and `("aliceb", "ob")` would hash identically.
/// KID: The exact envelope we put the name and the page number on, so two
///      different people's letters can never get swapped.
pub fn knock_message(user: &str, step: u64) -> Vec<u8> {
    // Pre-size: label + NUL + user + NUL + 8 bytes.
    let mut msg = Vec::with_capacity(PROTOCOL_LABEL.len() + 1 + user.len() + 1 + 8);
    // `extend_from_slice` appends raw bytes (not a Rust string).
    msg.extend_from_slice(PROTOCOL_LABEL);
    msg.push(0x00); // separator
    msg.extend_from_slice(user.as_bytes());
    msg.push(0x00); // separator
    msg.extend_from_slice(&step.to_be_bytes()); // 8-byte big-endian
    msg
}

/// Map a raw `u16` into an inclusive range, without modulo bias worries.
///
/// EXPERT: `lo + (v mod span)` where `span = hi - lo + 1`. There IS a tiny
///         modulo bias (65536 is not always a multiple of `span`), but the bias
///         is on the order of `span / 65536` and the value being mapped is
///         already a uniformly random HMAC output. For a knock *port* -- one of
///         tens of thousands -- this is not a meaningful weakness. The honest
///         thing is to say so rather than pretend we implemented rejection
///         sampling.
/// KID: Squash a big number down so it fits inside our box of door numbers.
fn map_to_range(value: u16, lo: u16, hi: u16) -> u16 {
    // Widen to u32 *before* arithmetic so nothing can wrap.
    let span = (hi as u32) - (lo as u32) + 1;
    let mapped = (value as u32) % span;
    (lo as u32 + mapped) as u16
}

/// Read a big-endian `u16` from `digest` at byte index `i`.
///
/// EXPERT: We index with `i` and `i + 1` directly. This would panic if `i + 1`
///         were out of bounds, so the caller must guarantee `i + 1 < 32`. That
///         guarantee comes from `ServerConfig::validate`, which caps
///         `knock_count_max` at 15 -- and there is a test asserting the
///         boundary. Using a slice + `try_into` here would be defensive but
///         would also hide the invariant; a documented precondition plus a test
///         is the more honest trade.
/// KID: Pick two neighbouring numbers out of the big bag and glue them into one.
fn be16(digest: &[u8; 32], i: usize) -> u16 {
    ((digest[i] as u16) << 8) | (digest[i + 1] as u16)
}

/// Derive the knock specification for a user at a given time step.
///
/// EXPERT: The whole protocol in one function. It is *pure*: same inputs always
///         give the same outputs, it touches no globals, does no I/O, and reads
///         no clock. Purity is what makes the protocol testable with fixed
///         vectors and what lets the client and server agree without talking.
/// KID: Read the recipe book page for this person, and write out the taps.
pub fn derive_knock_spec(
    secret: &MasterSecret,
    user: &str,
    step: u64,
    cfg: &ServerConfig,
) -> KnockSpec {
    // Step 1: the keyed digest. `as_bytes` gives `&[u8; 32]`.
    let digest = hmac_sha256(secret.as_bytes(), &knock_message(user, step));

    // Step 2: how many knocks? One byte of the digest, folded into the allowed
    // count range. Using `digest[0]` for this keeps the count independent of the
    // ports (which start at byte 1), so two windows with the same count still
    // have unrelated ports.
    let count_span = (cfg.knock_count_max - cfg.knock_count_min) as u16 + 1;
    let count = cfg.knock_count_min as usize + (digest[0] as usize % count_span as usize);

    // Step 3: the ports, read from consecutive byte pairs.
    let mut knock_ports: Vec<u16> = Vec::with_capacity(count);
    for i in 0..count {
        // Byte index 1 + 2*i, so knock 0 uses bytes 1-2, knock 1 uses 3-4, ...
        let raw = be16(&digest, 1 + 2 * i);
        let mut port = map_to_range(raw, cfg.knock_range.lo, cfg.knock_range.hi);

        // Avoid two identical ports in a row. A repeated port would make the
        // sequence ambiguous to count: "tap 5000 twice" and "tap 5000 once" look
        // the same to a state machine that only sees packets, not pauses.
        // EXPERT: This is a real correctness fix, not a nicety. Without it the
        //         protocol is not merely weaker, it is *wrong*, because a
        //         sequence with an adjacent duplicate cannot be reliably matched.
        if i > 0 && port == knock_ports[i - 1] {
            // Bump by one, wrapping to the bottom of the range at the top.
            port = if port >= cfg.knock_range.hi {
                cfg.knock_range.lo
            } else {
                port + 1
            };
        }
        knock_ports.push(port);
    }

    // Step 4: the port to open, from the byte pair *after* the last knock port.
    let open_raw = be16(&digest, 1 + 2 * count);
    let open_port = map_to_range(open_raw, cfg.open_range.lo, cfg.open_range.hi);

    KnockSpec {
        user: user.to_string(),
        time_step: step,
        knock_ports,
        open_port,
    }
}

/// Derive a spec and also the HOTP for the same window.
///
/// EXPERT: Used by `otkp enroll` (which prints the HOTP so the user can verify
///         their secret against a standard authenticator app) and by
///         `otkp verify`. Returning both from one function guarantees they are
///         computed for the *same* window, which is exactly the kind of thing
///         that goes wrong when two call sites each compute the time themselves.
/// KID: Give me both the taps and the familiar phone-app number for right now.
pub fn derive_with_hotp(
    secret: &MasterSecret,
    user: &str,
    step: u64,
    cfg: &ServerConfig,
) -> (KnockSpec, u32) {
    let spec = derive_knock_spec(secret, user, step, cfg);
    // HOTP's counter is the same integer as our time step -- the whole reason
    // HOTP and TOTP interoperate.
    let code = hotp(secret.as_bytes(), step, 6);
    (spec, code)
}

/// Convenience: derive the spec for "now" using the default step.
///
/// EXPERT: A thin wrapper so the CLI does not have to spell out
///         `time_step(unix_now(), cfg.step_seconds)` everywhere. Note it takes
///         the step from the config, not from `DEFAULT_STEP_SECONDS`, so a
///         non-default config is honoured.
/// KID: "What are the taps right this second?"
pub fn derive_now(secret: &MasterSecret, user: &str, cfg: &ServerConfig) -> KnockSpec {
    let step = time_step(unix_now(), cfg.step_seconds);
    derive_knock_spec(secret, user, step, cfg)
}

/// Parse a `--mode` / config string into a validated transport mode.
///
/// EXPERT: Kept here rather than in `config` because both the client and the
///         server need it and neither should own it. A tiny enum is better than
///         a `String` because the compiler then guarantees the daemon handles
///         every mode.
/// KID: "Did you say 'udp' or 'raw'? Those are the only two words I know."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Tiny UDP datagrams to a single listener; needs no privileges.
    Udp,
    /// Real packets to real (closed) ports, sniffed with AF_PACKET; needs root.
    Raw,
}

impl Mode {
    /// Parse a mode string, case-insensitively.
    pub fn parse(s: &str) -> Result<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(Mode::Udp),
            "raw" => Ok(Mode::Raw),
            other => Err(OtkpError::config(format!(
                "unknown mode '{other}' (expected \"udp\" or \"raw\")"
            ))),
        }
    }

    /// The canonical lowercase name, for config files and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Udp => "udp",
            Mode::Raw => "raw",
        }
    }
}

/// A tiny sanity helper used by the CLI: the default step, if none configured.
///
/// EXPERT: `Option<u64>::unwrap_or(DEFAULT_STEP_SECONDS)` would do this inline,
///         but a named function documents *why* the fallback exists: an old
///         config file written before `step_seconds` existed should still work.
/// KID: "If the settings sheet is too old to mention the time, use 30 seconds."
pub fn step_or_default(configured: Option<u64>) -> u64 {
    configured.unwrap_or(DEFAULT_STEP_SECONDS)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    /// A fixed secret and fixed config, so every test is deterministic.
    fn fixture() -> (MasterSecret, ServerConfig) {
        // `[0x2a; 32]` is 32 copies of the byte 0x2a.
        (
            MasterSecret::from_bytes([0x2a; 32]),
            ServerConfig::default(),
        )
    }

    // -----------------------------------------------------------------------
    // RFC 4226 Appendix D test vectors.
    // These are the *published* vectors for HOTP, and passing them is the
    // strongest possible evidence that our HMAC wiring is correct -- far better
    // than asserting against our own output, which would only prove we are
    // self-consistent.
    // -----------------------------------------------------------------------
    #[test]
    fn rfc4226_hotp_vectors() {
        let secret = b"12345678901234567890"; // the RFC's ASCII secret
        let expected = [
            755224u32, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(secret, counter as u64, 6);
            assert_eq!(got, *want, "counter {counter}");
        }
    }

    #[test]
    fn hmac_matches_known_vector() {
        // RFC 4231 test case 1: key = 20 bytes of 0x0b, data = "Hi There".
        let key = [0x0bu8; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(crate::secret::encode_hex(&tag), expected);
    }

    #[test]
    fn time_step_is_floor_division() {
        assert_eq!(time_step(0, 30), 0);
        assert_eq!(time_step(29, 30), 0);
        assert_eq!(time_step(30, 30), 1);
        assert_eq!(time_step(59, 30), 1);
        assert_eq!(time_step(60, 30), 2);
        // The divide-by-zero guard must return 0 rather than panic.
        assert_eq!(time_step(12345, 0), 0);
    }

    #[test]
    fn knock_message_has_domain_separation() {
        let a = knock_message("alice", 1);
        let b = knock_message("aliceb", 1);
        // The NUL separators must make these different byte strings.
        assert_ne!(a, b);
        // And the label must be at the front.
        assert!(a.starts_with(PROTOCOL_LABEL));
    }

    #[test]
    fn derivation_is_deterministic() {
        let (secret, cfg) = fixture();
        let a = derive_knock_spec(&secret, "alice", 42, &cfg);
        let b = derive_knock_spec(&secret, "alice", 42, &cfg);
        assert_eq!(a, b);
    }

    #[test]
    fn different_steps_give_different_sequences() {
        let (secret, cfg) = fixture();
        let a = derive_knock_spec(&secret, "alice", 42, &cfg);
        let b = derive_knock_spec(&secret, "alice", 43, &cfg);
        // It is *possible* (though astronomically unlikely with these ranges)
        // that two windows coincide. If this test ever fails, suspect the
        // derivation, not the RNG -- the probability is ~1/(10^4 * 10^4 ...).
        assert_ne!(a.knock_ports, b.knock_ports);
    }

    #[test]
    fn different_users_give_different_sequences() {
        let (secret, cfg) = fixture();
        let a = derive_knock_spec(&secret, "alice", 42, &cfg);
        let b = derive_knock_spec(&secret, "bob", 42, &cfg);
        assert_ne!(a.knock_ports, b.knock_ports);
    }

    #[test]
    fn different_secrets_give_different_sequences() {
        let cfg = ServerConfig::default();
        let a = derive_knock_spec(&MasterSecret::from_bytes([1; 32]), "alice", 42, &cfg);
        let b = derive_knock_spec(&MasterSecret::from_bytes([2; 32]), "alice", 42, &cfg);
        assert_ne!(a.knock_ports, b.knock_ports);
    }

    #[test]
    fn all_outputs_are_inside_configured_ranges() {
        let (secret, cfg) = fixture();
        // Sweep many windows so we exercise both extremes of the ranges.
        for step in 0..2_000u64 {
            let spec = derive_knock_spec(&secret, "alice", step, &cfg);
            assert!(
                spec.knock_ports.len() >= cfg.knock_count_min as usize
                    && spec.knock_ports.len() <= cfg.knock_count_max as usize,
                "step {step}: bad length {}",
                spec.knock_ports.len()
            );
            for p in &spec.knock_ports {
                assert!(
                    cfg.knock_range.contains(*p),
                    "step {step}: port {p} out of range"
                );
            }
            assert!(
                cfg.open_range.contains(spec.open_port),
                "step {step}: open port {} out of range",
                spec.open_port
            );
        }
    }

    #[test]
    fn no_adjacent_duplicate_ports() {
        // The anti-duplicate rule must hold for every window we test.
        let (secret, cfg) = fixture();
        for step in 0..2_000u64 {
            let spec = derive_knock_spec(&secret, "alice", step, &cfg);
            for pair in spec.knock_ports.windows(2) {
                assert_ne!(
                    pair[0], pair[1],
                    "step {step}: adjacent duplicate port {}",
                    pair[0]
                );
            }
        }
    }

    #[test]
    fn map_to_range_covers_endpoints() {
        // 0 maps to lo, span-1 maps to hi.
        assert_eq!(map_to_range(0, 100, 109), 100);
        assert_eq!(map_to_range(9, 100, 109), 109);
        assert_eq!(map_to_range(10, 100, 109), 100); // wraps
    }

    #[test]
    fn be16_is_big_endian() {
        let mut d = [0u8; 32];
        d[5] = 0x12;
        d[6] = 0x34;
        assert_eq!(be16(&d, 5), 0x1234);
    }

    #[test]
    fn max_knock_count_stays_inside_digest() {
        // This is the boundary the config validator protects. With count = 14,
        // the open port reads bytes 29 and 30, leaving byte 31 spare -- so
        // count <= 14 is the true limit. We assert that 14 works and that 15 is
        // rejected, which pins the boundary from both sides.
        let mut cfg = ServerConfig::default();
        cfg.knock_count_min = 14;
        cfg.knock_count_max = 14;
        cfg.validate().expect("count 14 must be allowed");
        let (secret, _) = fixture();
        let spec = derive_knock_spec(&secret, "alice", 1, &cfg);
        assert_eq!(spec.knock_ports.len(), 14);
        // If we had indexed out of bounds this call would have panicked, so
        // reaching here *is* the assertion.

        // One more must be rejected by the validator.
        let mut too_many = ServerConfig::default();
        too_many.knock_count_max = 15;
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(Mode::parse("UDP").unwrap(), Mode::Udp);
        assert_eq!(Mode::parse(" raw ").unwrap(), Mode::Raw);
        assert!(Mode::parse("tcp").is_err());
        assert_eq!(Mode::Udp.as_str(), "udp");
    }

    #[test]
    fn step_or_default_falls_back() {
        assert_eq!(step_or_default(None), DEFAULT_STEP_SECONDS);
        assert_eq!(step_or_default(Some(15)), 15);
    }

    #[test]
    fn derive_with_hotp_uses_same_window() {
        let (secret, cfg) = fixture();
        let (spec, code) = derive_with_hotp(&secret, "alice", 7, &cfg);
        assert_eq!(spec.time_step, 7);
        // The code must equal a direct HOTP call for the same counter.
        assert_eq!(code, hotp(secret.as_bytes(), 7, 6));
    }
}
