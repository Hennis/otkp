// ============================================================================
//  tests/protocol.rs  --  protocol conformance tests
// ============================================================================
//
//  EXPERT VIEW:
//    Integration tests live in `tests/` and are compiled as a *separate crate*
//    that links against our library. That separation matters: these tests can
//    only use the public API, so they double as a check that our public surface
//    is actually sufficient. If a test here needs a private item, that is
//    usually a sign the API is wrong, not that the test is unreasonable.
//
//    What this file tests, and why each category earns its place:
//
//      * **Published test vectors** (RFC 4226, RFC 4231). These are the only
//        tests whose expected values come from *outside* our code. Passing them
//        is the difference between "self-consistent" and "correct".
//      * **The wire format** (`knock_message`). A byte-exact assertion, because
//        this byte string IS the protocol. A second implementation in another
//        language would need to reproduce it exactly.
//      * **Cross-checking two paths** (client derivation vs server keyring).
//        The single worst bug this project could have is the client and server
//        disagreeing, so we test that they agree from two independent directions.
//      * **Property-style sweeps**. Thousands of time steps, asserting invariants
//        that must hold for *all* inputs rather than for one example.
//
//  KID VIEW:
//    The exam paper. Some answers we already know from the official textbook
//    (the published test vectors), and some we check by doing the same sum two
//    different ways and seeing if we get the same answer.
// ============================================================================

// See `src/lib.rs` for why these two lints are allowed crate-wide. Test crates
// do not inherit the library's configuration, so the allows are repeated here.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::field_reassign_with_default)]

use otkp::config::{PortRange, ServerConfig};
use otkp::crypto::{derive_knock_spec, derive_with_hotp, hotp, knock_message, time_step};
use otkp::keyring::Keyring;
use otkp::secret::MasterSecret;
use otkp::{DEFAULT_STEP_SECONDS, PROTOCOL_LABEL};

// ---------------------------------------------------------------------------
// 1. Published test vectors
// ---------------------------------------------------------------------------

/// RFC 4226 Appendix D: the canonical HOTP test vectors.
///
/// EXPERT: The secret is the ASCII string "12345678901234567890" and the
///         expected values are printed in the RFC itself. These numbers are the
///         strongest evidence we have that our HMAC wiring, our dynamic
///         truncation, and our modulo reduction are all exactly right -- because
///         they were produced by the RFC authors, not by us.
/// KID: The official answers from the textbook. If we match them, we did the
///      sums the same way as the textbook.
#[test]
fn rfc4226_appendix_d_vectors() {
    let secret = b"12345678901234567890";
    let expected = [
        755_224u32, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871, 520_489,
    ];
    for (counter, want) in expected.iter().enumerate() {
        assert_eq!(
            hotp(secret, counter as u64, 6),
            *want,
            "RFC 4226 counter {counter}"
        );
    }
}

/// RFC 4231 test case 1: HMAC-SHA256 with a 20-byte 0x0b key.
///
/// EXPERT: This validates our SHA-256-based primitive (which is what the knock
///         protocol actually uses) against an independent authority. Combined
///         with the RFC 4226 test above (which validates the SHA-1 path), both
///         hash functions we depend on are pinned to published values.
/// KID: The textbook answer for the *other* maths machine.
#[test]
fn rfc4231_hmac_sha256_vector() {
    // RFC 4231 case 1: key = 20 bytes of 0x0b, data = "Hi There".
    // Expected tag: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    //
    // We reach the HMAC through the public API by hashing a message whose
    // *content* we control. `hmac_sha256` is public, so we call it directly.
    let key = [0x0bu8; 20];
    let tag = otkp::crypto::hmac_sha256(&key, b"Hi There");
    assert_eq!(
        otkp::secret::encode_hex(&tag),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

// ---------------------------------------------------------------------------
// 2. The wire format, byte for byte
// ---------------------------------------------------------------------------

/// The HMAC message must be exactly the documented byte string.
///
/// EXPERT: This is the one test that pins the protocol. Everything else could
///         change (the ranges, the defaults, the count) without breaking
///         interoperability, but a change here breaks every other
///         implementation. The expected bytes are spelled out literally so a
///         reader can compare them against docs/PROTOCOL.md without running
///         anything.
/// KID: The exact spelling of the envelope we put the name and page number on.
#[test]
fn knock_message_is_byte_exact() {
    let msg = knock_message("alice", 1);

    // Build the expected bytes by hand, from the spec:
    //   "otkp-knock-v1" || 0x00 || "alice" || 0x00 || 0x0000000000000001
    let mut expected = Vec::new();
    expected.extend_from_slice(b"otkp-knock-v1");
    expected.push(0x00);
    expected.extend_from_slice(b"alice");
    expected.push(0x00);
    expected.extend_from_slice(&1u64.to_be_bytes());

    assert_eq!(msg, expected);
    // And the label must be the exported constant, not a string literal that
    // could drift from it.
    assert!(msg.starts_with(PROTOCOL_LABEL));
}

/// The NUL separators must prevent user-name concatenation ambiguity.
///
/// EXPERT: Without the separators, `("alice", "bob")` and `("aliceb", "ob")`
///         would produce the same message bytes and therefore the same sequence.
///         This is the classic "length extension / delimiter" bug in message
///         framing, and this test is the guard against reintroducing it.
/// KID: Two people's names must never be able to glue together into a third
///      person's name.
#[test]
fn knock_message_separators_prevent_ambiguity() {
    assert_ne!(knock_message("alice", 1), knock_message("aliceb", 1));
    // The time step must also be unambiguous: step 1 and step 10 must differ.
    assert_ne!(knock_message("alice", 1), knock_message("alice", 10));
    // And a user name containing a NUL must not be able to forge a boundary
    // (the step bytes follow a fixed-width 8-byte field, so this holds).
    assert_ne!(knock_message("alice\u{0}", 1), knock_message("alice", 1));
}

// ---------------------------------------------------------------------------
// 3. Client and server must agree
// ---------------------------------------------------------------------------

/// Deriving through the client path and the server path must agree exactly.
///
/// EXPERT: This is the most important test in the file. The client derives from
///         a secret it holds as text; the server derives from a secret it holds
///         in a keyring, loaded from JSON. If those two paths diverge for any
///         reason -- a different base32 decode, a different step, a different
///         range -- the protocol silently fails and the user sees a ban. Testing
///         both paths against each other is the only way to catch that.
/// KID: Do the same sum on two different calculators and check the answers match.
#[test]
fn client_and_server_derivations_agree() {
    let cfg = ServerConfig::default();

    // A secret as text, exactly as a user would paste it.
    let secret = MasterSecret::from_bytes([0xA5; 32]);
    let as_text = secret.to_base32();

    // Build a keyring containing that user, via the JSON path the server uses.
    let json = format!(
        r#"{{"entries":{{"alice":{{"user":"alice","secret":"{}","enrolled_at":0}}}}}}"#,
        as_text
    );
    let keyring: Keyring = serde_json::from_str(&json).expect("keyring JSON must parse");

    // Sweep a range of time steps so this is not a one-off coincidence.
    for step in [0u64, 1, 2, 1000, 58_655_938, u64::MAX / 2] {
        // Server path.
        let server_spec = keyring.spec_for("alice", step, &cfg).unwrap();

        // Client path: parse the text the user holds, then derive.
        let client_secret = MasterSecret::from_text(&as_text).unwrap();
        let client_spec = derive_knock_spec(&client_secret, "alice", step, &cfg);

        assert_eq!(
            server_spec, client_spec,
            "client and server disagreed at step {step}"
        );
    }
}

/// The HOTP value printed at enrolment must match a direct HOTP call.
///
/// EXPERT: `derive_with_hotp` promises both values for the *same* window. If the
///         two halves used different steps, the printed HOTP would be useless
///         for verifying the secret, which is its only purpose.
/// KID: The phone-app number and the taps must come from the same page of the
///      book.
#[test]
fn derive_with_hotp_uses_one_window() {
    let cfg = ServerConfig::default();
    let secret = MasterSecret::from_bytes([7; 32]);
    for step in [0u64, 42, 999_999] {
        let (spec, code) = derive_with_hotp(&secret, "alice", step, &cfg);
        assert_eq!(spec.time_step, step);
        assert_eq!(code, hotp(secret.as_bytes(), step, 6));
    }
}

// ---------------------------------------------------------------------------
// 4. Invariants over many windows
// ---------------------------------------------------------------------------

/// Every derived port must land inside its configured range, for thousands of
/// windows, with several different configurations.
///
/// EXPERT: A property test in spirit (though written as a plain loop, since we
///         take no proptest dependency). The value of sweeping many inputs
///         rather than asserting one example is that off-by-one errors in the
///         range mapping show up only at the boundaries, which a single sample
///         is unlikely to hit.
/// KID: Try lots and lots of pages of the book and make sure no door number is
///      ever outside the house.
#[test]
fn ports_always_inside_configured_ranges() {
    // A few configurations with awkward boundaries, including single-port ranges
    // and ranges that touch the ends of the u16 space. NOTE: knock and open
    // ranges must be disjoint, which is why the "widest" case splits the port
    // space in half rather than giving both ranges everything.
    let configs = [
        (40_000u16, 40_099u16, 50_000u16, 50_009u16),
        (1, 32_767, 32_768, 65_535),      // the widest *disjoint* split
        (1000, 1000, 2000, 2000),         // single-port ranges
        (49_999, 50_000, 60_000, 60_001), // adjacent, tiny
    ];

    for (klo, khi, olo, ohi) in configs {
        let mut cfg = ServerConfig::default();
        cfg.knock_range = PortRange::new(klo, khi).unwrap();
        cfg.open_range = PortRange::new(olo, ohi).unwrap();
        cfg.validate().expect("test config must be valid");

        let secret = MasterSecret::from_bytes([0x33; 32]);
        for step in 0..3_000u64 {
            let spec = derive_knock_spec(&secret, "alice", step, &cfg);
            for p in &spec.knock_ports {
                assert!(
                    cfg.knock_range.contains(*p),
                    "knock port {p} escaped {klo}-{khi} at step {step}"
                );
            }
            assert!(
                cfg.open_range.contains(spec.open_port),
                "open port {} escaped {olo}-{ohi} at step {step}",
                spec.open_port
            );
            assert!(
                spec.knock_ports.len() >= cfg.knock_count_min as usize
                    && spec.knock_ports.len() <= cfg.knock_count_max as usize
            );
        }
    }
}

/// No sequence may contain two identical adjacent ports.
///
/// EXPERT: This is a *correctness* property, not a nicety. A sequence with an
///         adjacent duplicate cannot be reliably matched by a state machine that
///         sees packets but not pauses, so the protocol would be ambiguous. See
///         the comment in `derive_knock_spec`.
/// KID: You can never be asked to tap the same door twice in a row.
#[test]
fn no_adjacent_duplicate_ports_ever() {
    let cfg = ServerConfig::default();
    let secret = MasterSecret::from_bytes([0x44; 32]);
    for step in 0..5_000u64 {
        let spec = derive_knock_spec(&secret, "alice", step, &cfg);
        for pair in spec.knock_ports.windows(2) {
            assert_ne!(pair[0], pair[1], "adjacent duplicate at step {step}");
        }
    }
}

/// Different users, secrets and windows must produce different sequences.
///
/// EXPERT: This is a *statistical* property, so it is asserted over many samples
///         rather than on one. We do not assert "always different" for every
///         pair (the space is finite, so collisions are possible in principle),
///         but we do assert that the number of distinct sequences observed is
///         close to the number of samples -- which would catch a catastrophic
///         failure like "the user name is ignored" or "the secret is ignored".
/// KID: Different people, different secrets and different pages should give
///      different taps almost always. We count how many different answers we
///      get, and check it is nearly all of them.
#[test]
fn sequences_are_well_distributed() {
    let cfg = ServerConfig::default();

    // Case 1: vary the secret. All sequences must differ.
    let mut seen = std::collections::HashSet::new();
    for i in 0..=255u8 {
        let secret = MasterSecret::from_bytes([i; 32]);
        let spec = derive_knock_spec(&secret, "alice", 1, &cfg);
        seen.insert((spec.knock_ports.clone(), spec.open_port));
    }
    assert_eq!(
        seen.len(),
        256,
        "varying the secret produced only {} distinct sequences",
        seen.len()
    );

    // Case 2: vary the user. All sequences must differ.
    let secret = MasterSecret::from_bytes([1; 32]);
    let mut seen = std::collections::HashSet::new();
    for i in 0..256 {
        let user = format!("user{i}");
        let spec = derive_knock_spec(&secret, &user, 1, &cfg);
        seen.insert((spec.knock_ports.clone(), spec.open_port));
    }
    assert_eq!(
        seen.len(),
        256,
        "varying the user produced only {} distinct sequences",
        seen.len()
    );

    // Case 3: vary the window. With ~10^4 * 10^4 * 10^4 possible sequences, 5000
    // windows should almost certainly be all-distinct.
    let mut seen = std::collections::HashSet::new();
    for step in 0..5_000u64 {
        let spec = derive_knock_spec(&secret, "alice", step, &cfg);
        seen.insert((spec.knock_ports.clone(), spec.open_port));
    }
    assert!(
        seen.len() > 4_990,
        "varying the window gave only {} distinct sequences out of 5000",
        seen.len()
    );
}

// ---------------------------------------------------------------------------
// 5. Time-step arithmetic
// ---------------------------------------------------------------------------

/// `time_step` must be exact floor division, including at boundaries.
#[test]
fn time_step_boundaries() {
    assert_eq!(time_step(0, DEFAULT_STEP_SECONDS), 0);
    assert_eq!(time_step(29, 30), 0);
    assert_eq!(time_step(30, 30), 1); // the first instant of the next window
    assert_eq!(time_step(59, 30), 1);
    assert_eq!(time_step(60, 30), 2);
    // A divide-by-zero must not panic.
    assert_eq!(time_step(123_456, 0), 0);
}

/// The default step must be 30 seconds, as documented.
///
/// EXPERT: A trivial-looking test, but it pins a value that appears in the
///         README, the enrolment URI and the protocol document. If someone
///         changes it, this test fails and forces them to update the docs too.
#[test]
fn default_step_is_thirty_seconds() {
    assert_eq!(DEFAULT_STEP_SECONDS, 30);
    assert_eq!(ServerConfig::default().step_seconds, DEFAULT_STEP_SECONDS);
}

/// The default ranges must be disjoint and the listener must be outside them.
#[test]
fn default_ranges_are_disjoint() {
    let cfg = ServerConfig::default();
    cfg.validate().expect("default config must validate");
    // No overlap between knock ports and open ports.
    let overlap =
        cfg.knock_range.lo <= cfg.open_range.hi && cfg.open_range.lo <= cfg.knock_range.hi;
    assert!(!overlap, "default ranges must not overlap");
    // The listener must not be inside the knock range.
    assert!(!cfg.knock_range.contains(cfg.listen_addr.port()));
}
