// ============================================================================
//  src/secret.rs  --  the per-user key, and the text formats it travels in
// ============================================================================
//
//  EXPERT VIEW:
//    A `MasterSecret` is 32 bytes of uniformly random data. Everything else in
//    the protocol is derived from it. That makes this file the smallest and most
//    security-critical type in the project, so it gets three unusual properties:
//
//      1. **Zeroising on drop.** When the value goes out of scope, its bytes are
//         overwritten with zeros before the memory is released. Without this, a
//         freed heap block can still contain the key, and a core dump, a
//         `/proc/<pid>/mem` read, or a use-after-free bug would leak it.
//      2. **Constant-time equality.** Comparing secrets with the normal `==`
//         short-circuits at the first differing byte. An attacker who can time
//         your comparisons can recover the secret one byte at a time. Our
//         `ct_eq` always reads every byte.
//      3. **No `Debug` that prints the bytes.** We implement `Debug` by hand to
//         print `<secret:32 bytes>`. Otherwise a stray `{:?}` in a log line
//         would put the key in syslog forever.
//
//    We also own the two text encodings a secret travels in: base32 (for humans
//    to type, and for the enrolment URI) and hex (for people who prefer it).
//
//  KID VIEW:
//    This is a little box that holds your secret handshake. Three rules about
//    the box:
//      1. When you throw the box away, we scribble over the handshake first, so
//         nobody who finds the box in the bin can read it.
//      2. When someone tries to guess the handshake, we never say "you got the
//         first letter right!" -- we just say "no". Guessing letter-by-letter is
//         how you crack a handshake, so we give nothing away.
//      3. If someone accidentally prints the box, it prints "there is a secret
//         in here" instead of the secret itself.
// ============================================================================

use crate::error::{OtkpError, Result};
use rand::rngs::OsRng; // OsRng reads randomness from the operating system.
use rand::RngCore; // `fill_bytes` comes from this trait.
use serde::{Deserialize, Serialize};
use std::fmt;
// `zeroize` is the crate that reliably overwrites memory. The compiler is
// allowed to optimise away a plain `for b in bytes { *b = 0 }` loop because it
// has no observable effect -- `zeroize` uses tricks (volatile writes, fences) to
// guarantee the wipe actually happens. This is why we take the dependency.
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The exact number of bytes in a master secret.
///
/// EXPERT: 32 bytes = 256 bits. HMAC-SHA256's security is capped at the hash's
///         256-bit output, so a longer key buys nothing; a shorter one would
///         reduce brute-force resistance below the hash's strength. 32 is the
///         exact right answer, and naming it as a constant means the number
///         appears in one place.
/// KID: The handshake is always exactly 32 magic beans long.
pub const SECRET_LEN: usize = 32;

// ===========================================================================
//  MasterSecret
// ===========================================================================
/// A 32-byte per-user key. Wiped from memory when dropped.
///
/// EXPERT: The `#[derive(Zeroize, ZeroizeOnDrop)]` macros generate the wipe
///         logic: `Zeroize` gives a `zeroize()` method, and `ZeroizeOnDrop`
///         generates a `Drop` impl that calls it on every field. Because the
///         only field is `[u8; 32]`, which implements `Zeroize`, this composes.
///
/// Note what we do NOT derive: `Clone`. Copying a secret multiplies the
///         number of places it must be wiped and makes lifetime reasoning
///         harder. Callers pass `&MasterSecret` instead. (The keyring stores its
///         own copy, deliberately, because it genuinely needs to own one.)
/// KID: A sealed envelope with the handshake inside. When you drop it in the
///      fire, the fire really does burn the paper (that is the `Zeroize` bit).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret {
    /// The raw key bytes. Private: the only ways out are `as_bytes()` (a borrow)
    /// and the text encoders below.
    bytes: [u8; SECRET_LEN],
}

impl MasterSecret {
    /// Build a secret from 32 bytes you already have.
    ///
    /// EXPERT: Takes `[u8; 32]` by value, which is `Copy`, so the caller's array
    ///         is not consumed. Useful for tests and for loading from a keyring
    ///         file. It is the caller's job to ensure the bytes are actually
    ///         random -- this constructor cannot tell random from `[0u8; 32]`.
    /// KID: "Here are 32 magic beans, put them in a box."
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        MasterSecret { bytes }
    }

    /// Generate a fresh secret from the operating system's CSPRNG.
    ///
    /// EXPERT: `OsRng` is backed by `getrandom(2)` on Linux, which draws from
    ///         the kernel's ChaCha20 CSPRNG seeded by the hardware RNG and
    ///         interrupt timing. It is the correct source for key material.
    ///         Never use a userspace PRNG (e.g. `rand::thread_rng` is fine too,
    ///         but `OsRng` is unambiguous about its provenance) for keys.
    /// KID: "Make me 32 brand-new magic beans that nobody has ever seen."
    pub fn generate() -> Self {
        // `[0u8; SECRET_LEN]` creates the array; `fill_bytes` overwrites it with
        // random data in place.
        let mut bytes = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut bytes);
        MasterSecret { bytes }
    }

    /// Borrow the raw bytes.
    ///
    /// EXPERT: Returning `&[u8; 32]` rather than `&[u8]` preserves the length in
    ///         the type, so callers can index without a bounds check and HMAC
    ///         gets the exact type it wants. The borrow cannot outlive `self`,
    ///         so the bytes cannot be stashed somewhere that outlives the wipe.
    /// KID: "Let me look at the beans, but I promise to give them right back."
    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.bytes
    }

    /// Parse a secret from user-supplied text: base32 or hex.
    ///
    /// EXPERT: We auto-detect the encoding rather than making the user say which
    ///         one they pasted. The heuristic is sound because the alphabets are
    ///         disjoint enough: hex uses only `0-9a-f`, while base32 uses `A-Z`
    ///         and `2-7`. A string containing only hex characters is *also* valid
    ///         base32 (since hex digits are a subset of base32's alphabet), so we
    ///         must decide deterministically. Our rule: strip separators, and if
    ///         the result is exactly 64 hex characters, treat it as hex;
    ///         otherwise treat it as base32. 64 hex chars = 32 bytes, which is
    ///         the only hex length that could be a valid secret anyway.
    /// KID: "Did you write the handshake in letters-and-numbers code, or in
    ///      A-to-F code? I will figure it out from the shape of it."
    pub fn from_text(text: &str) -> Result<Self> {
        // Remove anything a human might add for readability: spaces, hyphens,
        // and the `=` padding that some base32 encoders emit.
        let cleaned: String = text
            .chars()
            // `filter` keeps only the characters whose closure returns true.
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .collect();

        if cleaned.is_empty() {
            return Err(OtkpError::secret("secret text is empty"));
        }

        // Is it exactly 64 hex digits? Then it is hex.
        if cleaned.len() == SECRET_LEN * 2 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes = decode_hex(&cleaned)?;
            // `try_into` converts `Vec<u8>` -> `[u8; 32]` and fails if the length
            // is wrong. We just checked the length, but using `try_into` means we
            // never rely on a check made in a different function.
            let arr: [u8; SECRET_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| OtkpError::secret("hex secret is not 32 bytes"))?;
            return Ok(MasterSecret { bytes: arr });
        }

        // Otherwise: base32. `decode_base32` returns a Vec because it does not
        // know the target length until it has decoded.
        let bytes = decode_base32(&cleaned)?;
        let arr: [u8; SECRET_LEN] = bytes.as_slice().try_into().map_err(|_| {
            OtkpError::secret(format!(
                "base32 secret decoded to {} bytes, expected {SECRET_LEN}",
                bytes.len()
            ))
        })?;
        Ok(MasterSecret { bytes: arr })
    }

    /// Render the secret as unpadded uppercase base32.
    ///
    /// EXPERT: Base32 is the right choice for human transcription because its
    ///         alphabet excludes visually confusable pairs (no `0`/`O`, no
    ///         `1`/`l`/`I`). That is exactly why TOTP secrets are base32.
    ///         We omit `=` padding because it carries no information once the
    ///         length is known, and it is one more thing to mistype.
    /// KID: Turn the beans into letters-and-numbers that are easy to copy by
    ///      hand without mixing up an "O" and a "zero".
    pub fn to_base32(&self) -> String {
        encode_base32(&self.bytes)
    }

    /// Render the secret as lowercase hex.
    ///
    /// EXPERT: Hex is denser (2 chars/byte vs base32's 1.6) and universally
    ///         understood by other tools, at the cost of being harder to read
    ///         aloud. We offer both because interop with existing systems is
    ///         worth more than purity.
    /// KID: The same beans, written in the other kind of code.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.bytes)
    }

    /// Compare two secrets without leaking *where* they differ.
    ///
    /// EXPERT: The constant-time comparison. The naive `a == b` for byte slices
    ///         compares from the front and returns `false` at the first mismatch,
    ///         so its running time reveals the length of the matching prefix.
    ///         An attacker who can measure that (even statistically, over many
    ///         attempts) can recover the secret. This version folds every byte
    ///         into an accumulator with bitwise OR, so it always reads all 32
    ///         bytes and always takes the same time.
    /// KID: Instead of reading the handshake left-to-right and saying "wrong!"
    ///      as soon as you see a mistake, we look at every single letter before
    ///      answering. That way nobody can learn the handshake by watching our
    ///      eyes.
    pub fn ct_eq(&self, other: &MasterSecret) -> bool {
        // XOR each pair of bytes. Equal bytes give 0; different bytes give a
        // non-zero value. OR all the results together.
        let mut diff: u8 = 0;
        // `..SECRET_LEN` is a range; `self.bytes[i]` is a bounds-checked index.
        // The compiler can elide the check because the loop bounds are constants.
        for i in 0..SECRET_LEN {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        // `diff == 0` means every byte pair matched. `subtle`'s crate does the
        // same thing with extra compiler barriers; for our threat model (a local
        // comparison, not a remote timing oracle) this is sufficient, and it is
        // honest about its limits.
        diff == 0
    }
}

// ---------------------------------------------------------------------------
// PartialEq / Eq: route `==` through the constant-time comparison
// ---------------------------------------------------------------------------
// EXPERT: Implementing `PartialEq` manually means `secret_a == secret_b` in
//         *any* code (including tests) uses `ct_eq` automatically. That is the
//         point: the safe thing must be the default thing, or someone will
//         forget and write the fast, leaky comparison.
// KID: We teach Rust that "==" on two secret boxes means "do the careful
//      comparison", so everyone gets the safe behaviour for free.
impl PartialEq for MasterSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

// `Eq` is a marker trait: it promises the comparison is reflexive, symmetric and
// transitive, which our byte comparison is. It has no methods.
impl Eq for MasterSecret {}

// ---------------------------------------------------------------------------
// Debug: never print the bytes
// ---------------------------------------------------------------------------
// EXPERT: This is a small but high-value guardrail. `#[derive(Debug)]` would
//         print the key as a list of decimal numbers, which ends up in logs,
//         panic messages, and bug reports. Printing a placeholder makes the
//         failure mode "slightly annoying" instead of "catastrophic".
// KID: If someone accidentally prints the box, it says "there is a secret in
//      here!" instead of showing the secret. Oops-proof.
impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `write!` into the formatter; `SECRET_LEN` is interpolated inline.
        write!(f, "MasterSecret(<{SECRET_LEN} bytes, redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Serialize: write the text form; Deserialize: parse the text form
// ---------------------------------------------------------------------------
// EXPERT: We implement these by hand rather than deriving, because a derived
//         impl would serialise a `[u8; 32]` as a JSON array of 32 numbers --
//         valid, but ugly in a keyring file and awkward to copy out. Serialising
//         as base32 text means the keyring is greppable and pasteable.
//
//         SECURITY NOTE, STATED PLAINLY: the keyring file therefore contains
//         the secrets in the clear. It must be `chmod 600` and owned by root.
//         `otkp init` does exactly that; see cli/init.rs.
// KID: When we save the box to the shelf, we write the handshake in the
//      easy-to-read letters-and-numbers code.
impl Serialize for MasterSecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        // `S: Serializer` is a generic bound: "any serialiser serde hands us".
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base32())
    }
}

impl<'de> Deserialize<'de> for MasterSecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // First read a `String`, then reuse the exact same parser the CLI uses.
        // One parser means one set of accepted formats everywhere.
        let text = String::deserialize(deserializer)?;
        MasterSecret::from_text(&text).map_err(serde::de::Error::custom)
    }
}

// ===========================================================================
//  Base32 (RFC 4648, standard alphabet, no padding)
// ===========================================================================
/// The 32 symbols of the RFC 4648 base32 alphabet, in value order 0..31.
///
/// EXPERT: `A`=0 ... `Z`=25, then `2`=26 ... `7`=31. The digits `0`, `1`, `8`
///         and `9` are deliberately absent, which is what makes the encoding
///         resistant to transcription errors.
/// KID: The alphabet we use to write the beans: A to Z, then the numbers 2
///      through 7. No confusing letters.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode bytes as unpadded base32.
///
/// EXPERT: The algorithm processes the input in 5-byte groups and emits 8
///         characters per group (5 bytes = 40 bits = 8 * 5 bits). A trailing
///         partial group is handled by accumulating bits into a `u64` buffer and
///         emitting characters whenever 5 or more bits are available. Writing it
///         this way (rather than the classic table-driven form) makes the
///         bit-shuffling explicit and is easier to get right and to read.
/// KID: We chop the beans into groups of 5, and each group turns into 8 letters.
///      If the last group is short, we still turn it into as many letters as we
///      can and just stop.
pub fn encode_base32(data: &[u8]) -> String {
    // Pre-allocate the exact output size so we do not reallocate while building.
    // ceil(len * 8 / 5) characters are needed; for 32 bytes that is 52 chars.
    let capacity = (data.len() * 8).div_ceil(5);
    let mut out = String::with_capacity(capacity);

    // `buffer` holds bits not yet emitted; `bits` counts how many are valid.
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        // Shift the accumulator left by 8 and drop the new byte in the low end.
        buffer = (buffer << 8) | (byte as u32);
        bits += 8;
        // While we have at least 5 bits, emit one character.
        while bits >= 5 {
            bits -= 5;
            // Extract the top 5 bits of the valid region.
            let index = ((buffer >> bits) & 0b1_1111) as usize;
            // `push` a char; we look up the alphabet byte and cast to char.
            out.push(BASE32_ALPHABET[index] as char);
        }
    }

    // Leftover bits: pad with zeros on the right to make a final 5-bit group.
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0b1_1111) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }

    out
}

/// Decode unpadded (or padded) base32 back to bytes.
///
/// EXPERT: The inverse bit dance. We accumulate 5 bits per character into the
///         same kind of buffer and emit a byte whenever 8 bits are available.
///         Padding characters are skipped so both padded and unpadded input
///         work, which matters because different tools disagree about padding.
///         Case-insensitive, because humans type lowercase.
/// KID: Turn the letters back into beans, in the same grouping.
pub fn decode_base32(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for (pos, ch) in text.chars().enumerate() {
        // Skip padding and any separator a human added.
        if ch == '=' || ch == '-' || ch.is_whitespace() {
            continue;
        }
        // `to_ascii_uppercase` makes us case-insensitive.
        let upper = ch.to_ascii_uppercase();
        // Find the symbol's value. `position` scans the alphabet; 32 entries is
        // small enough that a linear scan beats building a lookup table.
        let value = BASE32_ALPHABET
            .iter()
            .position(|&c| c == upper as u8)
            // `ok_or_else` turns the `Option` into a `Result` with a message.
            .ok_or_else(|| {
                OtkpError::secret(format!("invalid base32 character '{ch}' at position {pos}"))
            })? as u32;

        buffer = (buffer << 5) | value;
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }

    // Any leftover bits must be zero-padding, otherwise the input was truncated
    // mid-character and we would silently drop real data.
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(OtkpError::secret(
            "base32 input has non-zero trailing bits (truncated?)",
        ));
    }

    Ok(out)
}

// ===========================================================================
//  Hex
// ===========================================================================
/// Lowercase hex encode.
///
/// EXPERT: `{:02x}` formats a byte as exactly two lowercase hex digits. This is
///         so common that hand-rolling it would be silly; `format!` is fine.
/// KID: Write each bean as two code characters.
pub fn encode_hex(data: &[u8]) -> String {
    // Pre-size the string: 2 characters per byte.
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        // `write!` into a String returns a Result that is infallible for String
        // (writing to a String never fails). We still handle it with `let _ =`
        // rather than `unwrap()` to keep the "no panics" rule.
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode hex (case-insensitive, separators allowed).
///
/// EXPERT: We parse two characters at a time with `to_digit(16)`, which handles
///         both cases and rejects anything outside 0-9a-fA-F for free.
/// KID: Read the code back into beans, two characters at a time.
pub fn decode_hex(text: &str) -> Result<Vec<u8>> {
    // Keep only hex digits so separators like ':' or ' ' do not break us.
    let cleaned: Vec<char> = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-' && *c != '=')
        .collect();

    if cleaned.len() % 2 != 0 {
        return Err(OtkpError::secret(
            "hex input has an odd number of digits (one byte = two digits)",
        ));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    // `chunks(2)` yields overlapping-free pairs: [c0,c1], [c2,c3], ...
    for pair in cleaned.chunks(2) {
        // Each pair is guaranteed to have exactly 2 elements by the length check.
        let hi = pair[0]
            .to_digit(16)
            .ok_or_else(|| OtkpError::secret(format!("invalid hex digit '{}'", pair[0])))?;
        let lo = pair[1]
            .to_digit(16)
            .ok_or_else(|| OtkpError::secret(format!("invalid hex digit '{}'", pair[1])))?;
        // Combine the two nibbles into one byte.
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_different_secrets() {
        // Two fresh secrets being equal would mean the RNG is broken. The
        // probability of a false failure is 2^-256, i.e. never.
        let a = MasterSecret::generate();
        let b = MasterSecret::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn base32_known_vector() {
        // RFC 4648 section 10 test vector: "foobar" -> "MZXW6YTBOI".
        // (The RFC shows "MZXW6YTBOI======" with padding; we omit padding.)
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
        // And the reverse.
        assert_eq!(decode_base32("MZXW6YTBOI").unwrap(), b"foobar".to_vec());
        // Lowercase and padding must both be accepted.
        assert_eq!(
            decode_base32("mzxw6ytboi======").unwrap(),
            b"foobar".to_vec()
        );
    }

    #[test]
    fn base32_round_trips_for_every_length() {
        // The partial-final-group logic is where base32 bugs live, so test every
        // remainder length from 1 to 16 bytes.
        for len in 1..=16usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = encode_base32(&data);
            let decoded = decode_base32(&encoded).unwrap();
            assert_eq!(data, decoded, "failed at len {len}");
        }
    }

    #[test]
    fn base32_rejects_bad_character() {
        // '1' is not in the alphabet (that is the whole point of base32).
        assert!(decode_base32("MZXW1YTBOI").is_err());
    }

    #[test]
    fn hex_round_trips() {
        let data = [0x00u8, 0x0f, 0xf0, 0xff, 0x42];
        assert_eq!(encode_hex(&data), "000ff0ff42");
        assert_eq!(decode_hex("000ff0ff42").unwrap(), data.to_vec());
        // Uppercase and separators are tolerated.
        assert_eq!(decode_hex("00:0F-F0 ff42").unwrap(), data.to_vec());
    }

    #[test]
    fn hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn secret_text_round_trip_base32() {
        let s = MasterSecret::generate();
        let text = s.to_base32();
        // 32 bytes -> ceil(256/5) = 52 base32 characters.
        assert_eq!(text.len(), 52);
        let back = MasterSecret::from_text(&text).unwrap();
        assert!(s.ct_eq(&back));
    }

    #[test]
    fn secret_text_round_trip_hex() {
        let s = MasterSecret::generate();
        let text = s.to_hex();
        assert_eq!(text.len(), 64);
        let back = MasterSecret::from_text(&text).unwrap();
        assert!(s.ct_eq(&back));
    }

    #[test]
    fn secret_text_accepts_human_separators() {
        let s = MasterSecret::generate();
        let spaced = s
            .to_base32()
            .chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let back = MasterSecret::from_text(&spaced).unwrap();
        assert!(s.ct_eq(&back));
    }

    #[test]
    fn debug_does_not_leak() {
        let s = MasterSecret::from_bytes([0xAB; 32]);
        let printed = format!("{s:?}");
        assert!(printed.contains("redacted"));
        // The hex of the key must not appear in the debug output.
        assert!(!printed.contains(&s.to_hex()));
        assert!(!printed.contains("171")); // 0xAB as decimal
    }

    #[test]
    fn json_round_trip_uses_base32() {
        let s = MasterSecret::generate();
        let json = serde_json::to_string(&s).unwrap();
        // Serialised as a quoted string, not an array of numbers.
        assert!(json.starts_with('"') && json.ends_with('"'));
        let back: MasterSecret = serde_json::from_str(&json).unwrap();
        assert!(s.ct_eq(&back));
    }

    #[test]
    fn ct_eq_agrees_with_normal_eq() {
        // Constant-time equality must give the same *answers* as the fast one.
        let a = MasterSecret::from_bytes([1; 32]);
        let b = MasterSecret::from_bytes([1; 32]);
        let c = MasterSecret::from_bytes([2; 32]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert_eq!(a == b, a.ct_eq(&b));
    }

    #[test]
    fn from_text_rejects_wrong_length() {
        // Valid base32, but only 4 bytes' worth.
        assert!(MasterSecret::from_text("MZXW6YTBOI").is_err());
        assert!(MasterSecret::from_text("").is_err());
    }
}
