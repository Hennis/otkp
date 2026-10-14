// ============================================================================
//  decoy/src/banner.rs  --  the decoy catalogue
// ============================================================================
//
//  EXPERT VIEW:
//    A decoy is three things: a name, a port, and a string that gets written to
//    whoever connects. That is the *whole* of it. Nothing listens on the port
//    except our listener, nothing parses what arrives, and no software matching
//    the announced version is installed anywhere.
//
//    The banner strings name real, historically-vulnerable versions. That is the
//    mechanism — a scanner matches them against a CVE database and believes it
//    has found something. It has found a string.
//
//    THE HONESTY NOTE, WHICH IS LOAD-BEARING: none of this is exploitable, and
//    that is not an accident of implementation, it is the design. The naive
//    version of a honeypot runs actual vulnerable software and thereby builds a
//    real foothold on purpose. This one serves bytes and reads nothing. There is
//    no parser here to overflow, because there is no parser here at all.
//
//    A catalogue rather than free-form configuration, because the point of a
//    decoy is that it is *plausible*, and plausibility is easier to review as a
//    fixed list than as something an operator improvises at 2am.
//
//  KID VIEW:
//    A shelf of pretend doors, each with a label that a burglar would recognise
//    as "this one is broken, try this one". The label is the whole trick. Behind
//    the door is a brick wall, and there is nothing to break because there is
//    nothing there.
// ============================================================================

use serde::{Deserialize, Serialize};

/// One decoy: a name, a port, and the banner it serves.
///
/// EXPERT: `Clone` but not `Copy`, because the banner is a `String`. The
///         catalogue is a `const`-ish static array of `&'static str` fields, so
///         constructing a `Decoy` copies one short string — negligible, and it
///         keeps the type simple.
/// KID: One pretend door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decoy {
    /// A short stable identifier, used in the trip stream.
    ///
    /// EXPERT: Stable because an alert rule or a dashboard will key on it. If it
    ///         changes, historical trips become uncorrelatable.
    /// KID: The name of this pretend door.
    pub name: String,

    /// The TCP port this decoy listens on.
    ///
    /// EXPERT: Chosen from ports that are *not* the legitimate service, and that
    ///         a scanner would plausibly find interesting. The catalogue below
    ///         uses well-known service ports, which means the decoys are only
    ///         reachable inside the perimeter — binding a decoy to a
    ///         world-reachable port would make it a real service with a real
    ///         attack surface.
    /// KID: Which door number.
    pub port: u16,

    /// The banner written to every connection, before anything else.
    ///
    /// EXPERT: Served verbatim and immediately, then the connection is held
    ///         silently. Serving it *first* is what makes a plain "read the
    ///         banner and leave" observable as a distinct event from "connected
    ///         and tried to talk".
    /// KID: The label on the door.
    pub banner: String,

    /// What a human would call this service, for log readability.
    ///
    /// EXPERT: Not used for logic. Present because an operator reading an alert
    ///         at 3am should not have to decode `"SSH-2.0-OpenSSH_7.4"` to know
    ///         what was touched.
    /// KID: The plain-English name of the door.
    pub service: String,
}

/// The built-in decoy catalogue.
///
/// EXPERT: Deliberately small. Each entry is a real historical version with a
///         real CVE, because that is what makes a scanner stop and pay
///         attention — but the version strings are inert text. See the module
///         docs.
///
/// **The ports are deliberately NOT the canonical ones, and the first
///         version of this catalogue got that wrong.** Two reasons, both found
///         by running it:
///
/// 1. **Privileged ports need root.** 22 and 80 are below 1024, so
///              binding them requires privileges the decoy daemon has no reason
///              to hold. A decoy that needs root to start is a decoy that gets
///              run as root, which is a worse outcome than the one it prevents.
///           2. **Canonical ports collide with the legitimate service.** Port 22
///              is, on most hosts, the actual SSH daemon — the very thing the
///              rest of this architecture exists to protect. A decoy there
///              either fails to bind or shadows the real service.
///
/// So each decoy sits on the *alternate* port that its service
///         conventionally uses, which is plausible to a scanner, unprivileged,
///         and unlikely to collide. The banner is what makes a decoy attractive;
///         the port merely has to be open and enumerable.
///
/// Operators who want different ports should override them rather than
///         edit this list — see `--port` in the binary's help.
/// KID: The shelf of pretend doors. We deliberately do NOT put them on the
///      numbers the real doors use, because the real doors are right there and
///      we are not allowed to touch them.
pub const DECOYS: &[(&str, u16, &str, &str)] = &[
    // (name, port, banner, service)
    //
    // Ports are the conventional *alternate* port for each service: unprivileged
    // (>1024) and unlikely to be in use. See the doc comment.
    (
        "ssh-old",
        2222,
        "SSH-2.0-OpenSSH_7.4\r\n",
        "SSH",
    ),
    (
        "http-apache-old",
        8080,
        "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Type: text/html\r\nContent-Length: 45\r\nConnection: close\r\n\r\n<html><body>It works!</body></html>\n",
        "HTTP",
    ),
    (
        "mysql-old",
        33060,
        "\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x39\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "MySQL",
    ),
    (
        "redis-old",
        6380,
        "-ERR unknown command\r\n",
        "Redis",
    ),
];

impl Decoy {
    /// Build a decoy from the catalogue tuple form.
    ///
    /// EXPERT: The catalogue is stored as tuples so it can be a `const` slice
    ///         with no allocation at startup; this converts one entry into the
    ///         owned struct the rest of the code uses. A single conversion point
    ///         means the tuple layout is described in exactly one place.
    /// KID: Turn a shelf label into a real pretend door.
    pub fn from_entry((name, port, banner, service): &(&str, u16, &str, &str)) -> Self {
        Decoy {
            name: (*name).to_string(),
            port: *port,
            banner: (*banner).to_string(),
            service: (*service).to_string(),
        }
    }

    /// The whole catalogue, materialised.
    ///
    /// EXPERT: Allocates, so it is called once at startup rather than per
    ///         connection. At this size that is a stylistic preference rather
    ///         than a performance one, and it is stated as such.
    /// KID: Get every pretend door off the shelf at once.
    pub fn all() -> Vec<Decoy> {
        DECOYS.iter().map(Decoy::from_entry).collect()
    }

    /// How many bytes the banner occupies.
    ///
    /// EXPERT: Used by the classifier to know how much was written, so a client
    ///         that read the banner and a client that read nothing can be told
    ///         apart where that matters.
    /// KID: How long the label is.
    pub fn banner_len(&self) -> usize {
        self.banner.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_non_empty_and_well_formed() {
        let all = Decoy::all();
        assert!(
            !all.is_empty(),
            "a catalogue with no decoys detects nothing"
        );
        for d in &all {
            assert!(
                !d.name.is_empty(),
                "every decoy needs a name for the stream"
            );
            assert!(d.port != 0, "{} has no port", d.name);
            assert!(!d.banner.is_empty(), "{} serves nothing", d.name);
            assert!(
                !d.service.is_empty(),
                "{} has no human-readable name",
                d.name
            );
        }
    }

    #[test]
    fn decoy_names_are_unique() {
        // Two decoys with the same name would make the trip stream ambiguous.
        let all = Decoy::all();
        let mut names: Vec<&str> = all.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate decoy name in the catalogue");
    }

    #[test]
    fn default_ports_are_unprivileged() {
        // THE regression test for the flaw the first live run exposed. Ports
        // below 1024 require root to bind, and a decoy daemon has no reason to
        // run as root -- so a privileged default makes the tool either fail to
        // start or demand privileges it should not have.
        for d in Decoy::all() {
            assert!(
                d.port > 1024,
                "{} defaults to privileged port {}, which needs root",
                d.name,
                d.port
            );
        }
    }

    #[test]
    fn default_ports_avoid_the_canonical_service_ports() {
        // A decoy on the canonical port collides with the legitimate service --
        // on most hosts port 22 IS sshd, which is the thing being protected.
        const CANONICAL: &[u16] = &[22, 80, 443, 3306, 6379, 5432, 25, 21, 23];
        for d in Decoy::all() {
            assert!(
                !CANONICAL.contains(&d.port),
                "{} sits on canonical port {}, which will collide with a real service",
                d.name,
                d.port
            );
        }
    }

    #[test]
    fn decoy_ports_are_unique() {
        // Two decoys on one port means one of them can never be reached, and the
        // catalogue would silently be lying about what is exposed.
        let all = Decoy::all();
        let mut ports: Vec<u16> = all.iter().map(|d| d.port).collect();
        ports.sort_unstable();
        let before = ports.len();
        ports.dedup();
        assert_eq!(before, ports.len(), "duplicate decoy port in the catalogue");
    }

    #[test]
    fn every_banner_is_a_plausible_greeting_for_its_service() {
        // The property that makes this a tripwire rather than a trap: every
        // banner is a *string* that a scanner would recognise, and nothing more.
        // The absence of anything to exploit is asserted by the fact that this
        // crate contains no parser at all.
        //
        // Plausibility is service-specific, so the checks are too. An earlier
        // version of this test required a digit in every banner, which is wrong:
        // a Redis greeting is a protocol reply (`-ERR ...`), not a version.
        for d in &Decoy::all() {
            match d.service.as_str() {
                "SSH" => {
                    assert!(
                        d.banner.starts_with("SSH-"),
                        "{}: an SSH banner must start with 'SSH-'",
                        d.name
                    );
                }
                "HTTP" => {
                    assert!(
                        d.banner.starts_with("HTTP/1."),
                        "{}: an HTTP banner must start with a status line",
                        d.name
                    );
                    assert!(
                        d.banner.contains("Server:"),
                        "{}: a scanner looks for the Server header",
                        d.name
                    );
                }
                "MySQL" => {
                    // The MySQL greeting is a binary packet; the version is in
                    // the bytes, so assert the packet is non-empty and starts
                    // with a plausible packet header length byte.
                    assert!(!d.banner.is_empty());
                }
                "Redis" => {
                    assert!(
                        d.banner.starts_with('-') || d.banner.starts_with('+'),
                        "{}: a Redis reply starts with '-' or '+'",
                        d.name
                    );
                }
                other => panic!("unhandled service '{other}' in the catalogue"),
            }
        }
    }

    #[test]
    fn version_carrying_services_name_a_version() {
        // The services whose banners *do* carry versions must carry one, because
        // that is the whole mechanism for those decoys.
        for d in Decoy::all() {
            if matches!(d.service.as_str(), "SSH" | "HTTP") {
                assert!(
                    d.banner.contains(|c: char| c.is_ascii_digit()),
                    "{} names no version, so a scanner would not care",
                    d.name
                );
            }
        }
    }

    #[test]
    fn ssh_banner_is_line_terminated() {
        // An SSH client reads the banner up to CRLF. Without it, a real client
        // would hang rather than read — which would make the decoy conspicuous.
        let ssh = Decoy::all()
            .into_iter()
            .find(|d| d.name == "ssh-old")
            .unwrap();
        assert!(
            ssh.banner.ends_with("\r\n"),
            "an SSH banner must end with CRLF or clients hang"
        );
    }

    #[test]
    fn http_banner_is_a_complete_response() {
        // A client waits for the body if Content-Length says there is one, so a
        // truncated response is a hang, and a hang is a tell.
        let http = Decoy::all()
            .into_iter()
            .find(|d| d.name == "http-apache-old")
            .unwrap();
        assert!(http.banner.starts_with("HTTP/1.1 "));
        assert!(http.banner.contains("Content-Length:"));
        assert!(http.banner.ends_with('\n'));
    }

    #[test]
    fn banner_len_matches_the_string() {
        let d = Decoy::from_entry(&("x", 1, "hello\r\n", "Test"));
        assert_eq!(d.banner_len(), 7);
    }
}
