// ============================================================================
//  decoy/src/trip.rs  --  classification and the graduated response
// ============================================================================
//
//  EXPERT VIEW:
//    This module is the design. Everything else in the crate is plumbing around
//    it, and it is pure: no I/O, no clock, no globals. `classify` takes an
//    observation and returns a verdict, so the whole decision surface is
//    testable with plain function calls.
//
//    Three ideas are encoded here, in order of importance:
//
//      1. **The negative space.** A decoy has no legitimate use, so any
//         interaction is anomalous. The classifier does not try to decide
//         whether the visitor *meant* harm; it decides how far they got, and
//         lets the response escalate with that. Intent is inferred from
//         behaviour, never assumed.
//
//      2. **The graduated response.** Reading a banner and sending an exploit
//         are different acts, and a single punishment for both would lock out
//         users over a typo — the same mistake as the one-strike ban fixed in
//         the main project. So: reject and warn; then revoke; then revoke and
//         alert.
//
//      3. **Credential scope, not address scope.** `Interaction` carries the
//         credential in use, and `Response` acts on *that*. There is deliberately
//         no API here that names an address as the thing to revoke. An address is
//         what a pre-authentication failure gives you; a credential is what a
//         post-authentication trip gives you, and the two are not
//         interchangeable.
//
//    HONESTY ABOUT THE HEURISTIC: exploit-shape detection is a heuristic. It has
//    false positives (a fuzzing test, a legitimate protocol probe) and false
//    negatives (a well-formed exploit that looks like a normal request). It is
//    the *third* tier of response precisely because it is the least certain —
//    the certain signal is simply that someone touched a door nobody uses.
//
//  KID VIEW:
//    Three questions, in order. "Did they knock on a door nobody uses?" -> tell
//    someone and shoo them away. "Did they try to open it?" -> take their key
//    away. "Did they try to break it?" -> take their key away AND shout.
// ============================================================================

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ===========================================================================
//  Interaction -- what was observed
// ===========================================================================
/// One observed interaction with a decoy.
///
/// EXPERT: A plain data record, built by the listener and consumed by the
///         classifier. `credential` is an `Option<String>` because the listener
///         may not always be able to attribute the connection to a session — and
///         an unattributable trip must still be recorded, just with a response
///         that cannot revoke anything (see `Response::for_trip`).
/// KID: A note describing what we saw at one of the pretend doors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interaction {
    /// Which decoy was touched.
    pub decoy: String,
    /// Where the connection came from.
    ///
    /// EXPERT: Recorded for the investigation, never used as the target of a
    ///         response. It is evidence, not a handle.
    /// KID: Where the visitor was standing.
    pub src_ip: IpAddr,
    /// The credential or session in use, if it could be attributed.
    ///
    /// EXPERT: The field that makes the response correct. See the module docs.
    /// KID: Whose key was being used.
    pub credential: Option<String>,
    /// How many bytes the client sent after the banner.
    ///
    /// EXPERT: Zero means they read the banner and left — the cheapest, most
    ///         common, and most diagnostic signal in the whole system. A scanner
    ///         that only fingerprints by banner produces exactly this.
    /// KID: Did they say anything back?
    pub bytes_from_client: usize,
    /// The first bytes the client sent, for shape analysis.
    ///
    /// EXPERT: Bounded by the listener before it gets here, so a client cannot
    ///         make us allocate without limit by sending a gigabyte. The bound
    ///         is a security property, not a tidiness one.
    /// KID: A snippet of what they said.
    pub client_payload: Vec<u8>,
    /// Unix seconds when the interaction was observed.
    pub at: u64,
}

impl Interaction {
    /// Start an interaction record for a banner read.
    ///
    /// EXPERT: The default case — connected, read, sent nothing. Naming the
    ///         constructor after what it describes makes the common path read
    ///         well at the call site, and makes it obvious that `Probe` is the
    ///         baseline rather than a special case.
    /// KID: "Someone looked at a pretend door."
    pub fn probe(decoy: &str, src_ip: IpAddr) -> Self {
        Interaction {
            decoy: decoy.to_string(),
            src_ip,
            credential: None,
            bytes_from_client: 0,
            client_payload: Vec::new(),
            at: 0,
        }
    }

    /// Attach the credential that was in use.
    ///
    /// EXPERT: A builder method taking `self` by value, so the record is
    ///         constructed in one expression and cannot be half-populated at the
    ///         call site. `impl Into<String>` accepts both `&str` and `String`.
    /// KID: Write down whose key it was.
    pub fn with_credential(mut self, credential: impl Into<String>) -> Self {
        self.credential = Some(credential.into());
        self
    }

    /// Record what the client sent back.
    ///
    /// EXPERT: Stores the byte count and a bounded prefix. The prefix is what
    ///         the exploit-shape heuristic inspects; the count is what
    ///         distinguishes "said nothing" from "said something".
    /// KID: Write down what they said.
    pub fn with_payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        let payload = payload.into();
        self.bytes_from_client = payload.len();
        self.client_payload = payload;
        self
    }

    /// Set the observation time.
    pub fn at(mut self, at: u64) -> Self {
        self.at = at;
        self
    }
}

// ===========================================================================
//  Trip -- how far they got
// ===========================================================================
/// How far an interaction with a decoy went.
///
/// EXPERT: Ordered by severity, and `Ord` is derived from declaration order so
///         `Trip::Exploit > Trip::Probe` means what it reads like. The response
///         table keys off that ordering.
///
/// Note what these variants do *not* claim: none of them asserts intent.
///         `Exploit` means "the payload has the shape of an exploit", not "this
///         person is an attacker". The classifier reports behaviour and lets a
///         human or a responder draw conclusions.
/// KID: How far they got: looked, tried, or tried to break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trip {
    /// They read the banner and sent nothing.
    ///
    /// EXPERT: The most valuable signal in the system, and the cheapest to
    ///         produce. A banner-fingerprinting scanner — which is most of them
    ///         — generates exactly this and nothing else.
    /// KID: They looked at the door.
    Probe,

    /// They sent something, but nothing with the shape of an exploit.
    ///
    /// EXPERT: A client attempting a real protocol handshake, or a human poking
    ///         at it. Ambiguous by nature: it could be a curious administrator,
    ///         which is exactly why the response here revokes rather than
    ///         alerts. Revocation is recoverable; an alert that cries wolf is
    ///         not.
    /// KID: They tried to open the door.
    Connect,

    /// They sent something with the shape of an exploit.
    ///
    /// EXPERT: The heuristic tier. See the module docs on why this is the third
    ///         response tier rather than the first: it is the least certain.
    /// KID: They tried to break the door.
    Exploit,
}

impl Trip {
    /// The stable tag used in the trip stream, matching the serde spelling.
    pub fn tag(self) -> &'static str {
        match self {
            Trip::Probe => "probe",
            Trip::Connect => "connect",
            Trip::Exploit => "exploit",
        }
    }
}

// ===========================================================================
//  Response -- what the responder should do
// ===========================================================================
/// The graduated response, **credential-scoped**.
///
/// EXPERT: This enum deliberately cannot express "revoke an address". That is
///         the single most important constraint in this crate: a decoy trip
///         happens after authentication, so the credential is what you know and
///         the address is the victim's.
///
/// The responder — separate software, per the design note §5.4 —
///         consumes these verdicts. This crate never acts on them itself.
/// KID: What we tell the guard to do. Always about a key, never about a place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// Reject the connection, warn the credential's owner, record.
    ///
    /// EXPERT: The warning is load-bearing, not decorative. A typo and a probe
    ///         are indistinguishable from here, so the user must be told — both
    ///         to recover a false positive and to learn about a true one. This
    ///         is the §2.1 payoff of the design note, delivered to the person it
    ///         matters to.
    /// KID: Shoo them away and tell them what happened.
    RejectAndWarn,

    /// Revoke the credential and force a disconnect.
    ///
    /// EXPERT: Recoverable by design — a legitimate user who tripped this can be
    ///         re-issued a credential. That asymmetry is why `Connect` revokes
    ///         rather than alerts.
    /// KID: Take their key away.
    RevokeCredential,

    /// Revoke the credential, force a disconnect, and alert.
    ///
    /// EXPERT: The only tier that raises an alert, because it is the only tier
    ///         where the evidence is strong enough to justify waking someone.
    /// KID: Take their key away and shout.
    RevokeAndAlert,
}

impl Response {
    /// The response for a given trip.
    ///
    /// EXPERT: A total function from `Trip` to `Response`, with no side
    ///         conditions. Keeping the mapping in one place means the escalation
    ///         policy is reviewable in a single glance rather than scattered
    ///         across the code that detects each case.
    ///
    /// NOTE the one adjustment made for unattributable trips: see
    ///         `for_trip_with_credential`.
    /// KID: How far they got decides what we do.
    pub fn for_trip(trip: &Trip) -> Response {
        match trip {
            Trip::Probe => Response::RejectAndWarn,
            Trip::Connect => Response::RevokeCredential,
            Trip::Exploit => Response::RevokeAndAlert,
        }
    }

    /// The response for a trip, downgraded if nothing can be revoked.
    ///
    /// EXPERT: If the listener could not attribute the connection to a session,
    ///         there is no credential to revoke — and revoking *something else*
    ///         would be worse than doing nothing. So an unattributable trip
    ///         degrades to reject-and-record rather than reaching for the only
    ///         other handle available, which would be the address.
    ///
    /// This is the DoS guard from the design note §5.2 expressed in the
    ///         type system: the code path that could revoke the wrong thing does
    ///         not exist, because it would have to name an address and there is
    ///         no variant for that.
    /// KID: If we do not know whose key it was, we cannot take a key away — so
    ///      we just shoo them away and write it down.
    pub fn for_trip_with_credential(trip: &Trip, credential: Option<&str>) -> Response {
        if credential.is_none() {
            // No credential -> nothing to revoke -> the strongest thing we may
            // do is reject and record. Never escalate to an address.
            return Response::RejectAndWarn;
        }
        Response::for_trip(trip)
    }
}

// ===========================================================================
//  The classifier
// ===========================================================================
/// The largest payload the exploit-shape heuristic will look at.
///
/// EXPERT: Bounded so that a client cannot make us scan an unbounded buffer.
///         The listener also bounds what it reads; this is the second line of
///         the same defence, because a bound that exists in one place is a bound
///         that can be removed from one place.
/// KID: We only look at the first bit of what they said.
pub const MAX_ANALYSED_PAYLOAD: usize = 4096;

/// Classify an interaction.
///
/// EXPERT: The whole decision surface, as one pure function. Three cases, in
///         increasing order of how far the visitor got:
///
/// * nothing sent      -> `Probe`
///           * something sent    -> `Connect`, unless
///           * exploit-shaped    -> `Exploit`
///
/// It does not look at the source address, the time, or the decoy name.
///         That is deliberate: none of those should change the verdict, and a
///         classifier that consulted them would be a classifier whose behaviour
///         depended on things that are not evidence.
/// KID: Look at what they did and decide how far they got.
pub fn classify(seen: &Interaction) -> Trip {
    // Nothing sent: they read the banner and went away. The cheapest and most
    // common signal, and the one a banner-fingerprinting scanner produces.
    if seen.bytes_from_client == 0 {
        return Trip::Probe;
    }

    // Something sent. Is it exploit-shaped?
    if looks_like_an_exploit(&seen.client_payload) {
        return Trip::Exploit;
    }

    Trip::Connect
}

/// Does this payload have the shape of an exploit attempt?
///
/// EXPERT: A heuristic, and named as one. It looks for the *shape* of an attempt
///         rather than any specific exploit, because a signature list is a
///         list of the attacks that already happened. The shapes:
///
/// * a payload far larger than any legitimate protocol greeting —
///             the classic buffer-overflow delivery
///           * embedded NUL bytes in what should be text — a delimiter
///             injection or a binary payload where a string was expected
///           * shell metacharacters — command injection
///           * path traversal sequences — directory escape
///           * format-string specifiers — the printf family bug
///           * long runs of a single repeated byte — the padding half of a
///             classic overflow
///
/// Each of these has a legitimate explanation in some protocol, which is
///         exactly why the response to this tier alerts rather than acts
///         silently. It is a signal to investigate, not a verdict.
/// KID: Does what they said look like they were trying to break something?
pub fn looks_like_an_exploit(payload: &[u8]) -> bool {
    // Only inspect a bounded prefix.
    let window = &payload[..payload.len().min(MAX_ANALYSED_PAYLOAD)];

    if window.is_empty() {
        return false;
    }

    // 1. Oversized payload. No legitimate greeting is 512 bytes of anything.
    if payload.len() > 512 {
        return true;
    }

    // 2. NUL bytes where text is expected.
    if window.contains(&0x00) {
        return true;
    }

    // 3. Long runs of one repeated byte (the padding of a classic overflow).
    if has_long_run(window, 64) {
        return true;
    }

    // The remaining checks are textual, so require valid-ish UTF-8 first. A
    // payload that is not text is already covered by the NUL check above in
    // practice, and treating arbitrary bytes as text invites false positives.
    let Ok(text) = std::str::from_utf8(window) else {
        return false;
    };

    // 4. Shell metacharacters: command injection.
    const SHELL_METAS: &[&str] = &[";", "|", "`", "$(", "${", "&&", "||", ">/", "\n/"];
    if SHELL_METAS.iter().any(|m| text.contains(m)) {
        return true;
    }

    // 5. Path traversal: directory escape.
    if text.contains("../") || text.contains("..\\") || text.contains("%2e%2e") {
        return true;
    }

    // 6. Format-string specifiers, in quantity. A single `%s` appears in
    //    ordinary text; a run of them is the shape of a format-string probe.
    let format_specifiers = text.matches('%').count();
    if format_specifiers >= 4 {
        return true;
    }

    false
}

/// Does `data` contain `len` or more consecutive copies of the same byte?
///
/// EXPERT: Written as an explicit scan rather than a regex, because the input is
///         attacker-controlled and a backtracking regex over attacker input is
///         its own denial-of-service vector. A linear scan has no such property,
///         and this is O(n) with a single comparison per byte.
/// KID: Is there a long stretch of the same letter?
fn has_long_run(data: &[u8], len: usize) -> bool {
    if len == 0 || data.len() < len {
        return false;
    }
    let mut run = 1usize;
    for i in 1..data.len() {
        if data[i] == data[i - 1] {
            run += 1;
            if run >= len {
                return true;
            }
        } else {
            run = 1;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // -----------------------------------------------------------------------
    // Classification
    // -----------------------------------------------------------------------

    #[test]
    fn reading_the_banner_is_a_probe() {
        // THE central case. A scanner that fingerprints by banner sends nothing
        // and leaves. This is the signal the whole design exists to produce.
        let seen = Interaction::probe("ssh-old", ip(203, 0, 113, 9));
        assert_eq!(classify(&seen), Trip::Probe);
    }

    #[test]
    fn sending_a_normal_greeting_is_a_connect() {
        // A client attempting a real handshake. Not necessarily hostile, which
        // is why this tier revokes rather than alerts.
        let seen = Interaction::probe("ssh-old", ip(203, 0, 113, 9))
            .with_payload("SSH-2.0-OpenSSH_8.9\r\n");
        assert_eq!(classify(&seen), Trip::Connect);
    }

    #[test]
    fn an_oversized_payload_is_an_exploit() {
        let seen = Interaction::probe("http-apache-old", ip(203, 0, 113, 9))
            .with_payload(vec![b'A'; 1024]);
        assert_eq!(classify(&seen), Trip::Exploit);
    }

    #[test]
    fn nul_bytes_are_an_exploit() {
        let seen = Interaction::probe("mysql-old", ip(203, 0, 113, 9))
            .with_payload(b"GET /a\x00b HTTP/1.0".to_vec());
        assert_eq!(classify(&seen), Trip::Exploit);
    }

    #[test]
    fn a_long_repeated_run_is_an_exploit() {
        // Padding of a classic overflow, under the size threshold so it must be
        // caught by the run detector rather than the length check.
        let seen =
            Interaction::probe("http-apache-old", ip(203, 0, 113, 9)).with_payload(vec![b'A'; 200]);
        assert_eq!(classify(&seen), Trip::Exploit);
    }

    #[test]
    fn shell_metacharacters_are_an_exploit() {
        let seen = Interaction::probe("http-apache-old", ip(203, 0, 113, 9))
            .with_payload(b"GET /cgi-bin/x;cat /etc/passwd HTTP/1.0".to_vec());
        assert_eq!(classify(&seen), Trip::Exploit);
    }

    #[test]
    fn path_traversal_is_an_exploit() {
        let seen = Interaction::probe("http-apache-old", ip(203, 0, 113, 9))
            .with_payload(b"GET /../../etc/shadow HTTP/1.0".to_vec());
        assert_eq!(classify(&seen), Trip::Exploit);
    }

    #[test]
    fn encoded_path_traversal_is_an_exploit() {
        let seen = Interaction::probe("http-apache-old", ip(203, 0, 113, 9))
            .with_payload(b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.0".to_vec());
        assert_eq!(classify(&seen), Trip::Exploit);
    }

    #[test]
    fn format_string_probe_is_an_exploit() {
        let seen = Interaction::probe("http-apache-old", ip(203, 0, 113, 9))
            .with_payload(b"GET /%s%s%s%s%s HTTP/1.0".to_vec());
        assert_eq!(classify(&seen), Trip::Exploit);
    }

    #[test]
    fn a_single_percent_sign_is_not_an_exploit() {
        // Guard against the heuristic being too eager: ordinary text contains
        // percent signs, and a false positive here would revoke a real user.
        let seen = Interaction::probe("http-apache-old", ip(203, 0, 113, 9))
            .with_payload(b"GET /discount-100% HTTP/1.0".to_vec());
        assert_eq!(classify(&seen), Trip::Connect);
    }

    #[test]
    fn non_utf8_without_nuls_is_not_treated_as_text() {
        // A binary protocol greeting should not be scanned for text patterns,
        // which would produce nonsense matches.
        let seen = Interaction::probe("mysql-old", ip(203, 0, 113, 9))
            .with_payload(vec![0x01, 0x02, 0x03, 0x04, 0xff, 0xfe]);
        assert_eq!(classify(&seen), Trip::Connect);
    }

    // -----------------------------------------------------------------------
    // The graduated response
    // -----------------------------------------------------------------------

    #[test]
    fn the_response_escalates_with_the_trip() {
        assert_eq!(Response::for_trip(&Trip::Probe), Response::RejectAndWarn);
        assert_eq!(
            Response::for_trip(&Trip::Connect),
            Response::RevokeCredential
        );
        assert_eq!(Response::for_trip(&Trip::Exploit), Response::RevokeAndAlert);
    }

    #[test]
    fn trips_are_ordered_by_severity() {
        // The escalation table depends on this ordering being declaration order.
        assert!(Trip::Probe < Trip::Connect);
        assert!(Trip::Connect < Trip::Exploit);
    }

    #[test]
    fn only_the_most_severe_tier_alerts() {
        // An alert that fires on a banner read would cry wolf and be ignored.
        let alerting: Vec<Trip> = [Trip::Probe, Trip::Connect, Trip::Exploit]
            .into_iter()
            .filter(|t| Response::for_trip(t) == Response::RevokeAndAlert)
            .collect();
        assert_eq!(alerting, vec![Trip::Exploit]);
    }

    // -----------------------------------------------------------------------
    // Credential scope -- the constraint that matters most
    // -----------------------------------------------------------------------

    #[test]
    fn an_unattributable_trip_never_escalates() {
        // THE DoS guard. If we cannot name a credential, we must not reach for
        // the only other handle (the address), because that handle belongs to
        // whoever is behind the NAT -- possibly the victim.
        for trip in [Trip::Probe, Trip::Connect, Trip::Exploit] {
            assert_eq!(
                Response::for_trip_with_credential(&trip, None),
                Response::RejectAndWarn,
                "an unattributable {trip:?} must not escalate"
            );
        }
    }

    #[test]
    fn an_attributable_trip_uses_the_normal_table() {
        for trip in [Trip::Probe, Trip::Connect, Trip::Exploit] {
            assert_eq!(
                Response::for_trip_with_credential(&trip, Some("alice")),
                Response::for_trip(&trip)
            );
        }
    }

    #[test]
    fn no_response_variant_can_name_an_address() {
        // A compile-time-ish assertion of the design: the enum simply has no
        // variant carrying an `IpAddr`, so there is no code path that could
        // revoke an address even if someone wanted one. This test documents the
        // property; the type system enforces it.
        let all = [
            Response::RejectAndWarn,
            Response::RevokeCredential,
            Response::RevokeAndAlert,
        ];
        // Every variant round-trips through serde without an address field.
        for r in all {
            let json = serde_json::to_string(&r).unwrap();
            assert!(
                !json.contains("ip"),
                "a response must not serialise an address: {json}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Serialisation vocabulary
    // -----------------------------------------------------------------------

    #[test]
    fn tags_match_the_serde_spelling() {
        for (trip, want) in [
            (Trip::Probe, "probe"),
            (Trip::Connect, "connect"),
            (Trip::Exploit, "exploit"),
        ] {
            assert_eq!(trip.tag(), want);
            let json = serde_json::to_string(&trip).unwrap();
            assert_eq!(json, format!("\"{want}\""));
        }
    }

    // -----------------------------------------------------------------------
    // The heuristic's own primitives
    // -----------------------------------------------------------------------

    #[test]
    fn long_run_detection_is_exact_at_the_boundary() {
        assert!(has_long_run(&[b'A'; 64], 64), "exactly 64 must match");
        assert!(!has_long_run(&[b'A'; 63], 64), "63 must not");
        assert!(!has_long_run(&[], 64), "empty input must not match");
        assert!(
            !has_long_run(&[b'A'; 64], 0),
            "a zero-length run is not a run"
        );
    }

    #[test]
    fn long_run_detection_finds_a_run_in_the_middle() {
        let mut data = vec![b'x'; 10];
        data.extend(std::iter::repeat(b'A').take(70));
        data.extend(vec![b'y'; 10]);
        assert!(has_long_run(&data, 64));
    }

    #[test]
    fn exploit_detection_ignores_an_empty_payload() {
        assert!(!looks_like_an_exploit(&[]));
    }

    #[test]
    fn exploit_detection_is_bounded_in_what_it_scans() {
        // A huge payload is caught by the length check before the scan, so the
        // scan itself never walks an unbounded buffer.
        let huge = vec![b'z'; 1_000_000];
        assert!(looks_like_an_exploit(&huge));
    }

    // -----------------------------------------------------------------------
    // The builder
    // -----------------------------------------------------------------------

    #[test]
    fn builder_sets_the_byte_count_from_the_payload() {
        let seen = Interaction::probe("d", ip(1, 2, 3, 4)).with_payload("hello");
        assert_eq!(seen.bytes_from_client, 5);
        assert_eq!(seen.client_payload, b"hello");
    }

    #[test]
    fn builder_defaults_are_a_bare_probe() {
        let seen = Interaction::probe("d", ip(1, 2, 3, 4));
        assert_eq!(seen.bytes_from_client, 0);
        assert!(seen.credential.is_none());
        assert!(seen.client_payload.is_empty());
    }
}
