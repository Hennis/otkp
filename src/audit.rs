// ============================================================================
//  src/audit.rs  --  the structured event stream (security level 2)
// ============================================================================
//
//  EXPERT VIEW:
//    Log *prose* is for humans reading a terminal. Log *records* are for machines
//    answering questions later — "who accessed this, when, and from where" — and
//    the two are not interchangeable. A line like
//
//        AUTHORISED 'alice' from 203.0.113.9 for port 60802 at step 58655938
//
//    is perfectly readable and completely useless to a SIEM without a bespoke
//    regex, which then silently breaks the first time the wording changes.
//
//    So level 2 adds a second, structured stream: one JSON object per line
//    (JSON Lines). Every record is self-describing and versioned, and the
//    wording of the human log can change without breaking anything downstream.
//
//    Three design decisions worth stating:
//
//      1. **JSON Lines, not a JSON array.** Appending a line is a single small
//         `write`, which the kernel makes atomic for records under `PIPE_BUF`.
//         Appending to an array requires rewriting the closing bracket, which is
//         neither atomic nor crash-safe. A log that corrupts on a crash is a log
//         that fails exactly when it matters.
//      2. **Append-only, created 0600.** The file records who accessed what; it
//         is as sensitive as the system it describes. It is never truncated by
//         the daemon and never rewritten.
//      3. **Failure to write is logged, never fatal.** Losing an audit record is
//         bad; taking the access-control daemon down because a disk filled is
//         worse, and would deny service to legitimate users. We fail soft here
//         and say so loudly — the one place in this project where failing soft is
//         the right call, and it is a deliberate exception rather than an
//         oversight.
//
//  KID VIEW:
//    Two diaries. One is written for people to read ("Alice came in at 2pm"). The
//    other is written for a robot to read later, in a language a robot
//    understands, so it can answer questions without a human translating. If the
//    second diary's pen runs out, we shout about it but we do NOT stop letting
//    people in — the door still works, we just write it down less well.
// ============================================================================

use crate::error::{OtkpError, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// The version of the audit record format.
///
/// EXPERT: Emitted in every record. A consumer can then parse records it
///         understands and skip the ones it does not, instead of failing on a
///         field it has never seen. Without a version, the first schema change
///         breaks every downstream parser silently, which is the failure mode
///         that makes people distrust audit logs.
/// KID: The number on the diary's cover, so a reader knows which edition of the
///      format this is.
pub const AUDIT_FORMAT_VERSION: u32 = 1;

/// One thing that happened, as a machine-readable record.
///
/// EXPERT: An enum with `#[serde(tag = "event")]`, so each record reads
///         `{"v":1,"event":"authorised",...}`. A tagged enum rather than a
///         separate file per event type, because a consumer wants one ordered
///         stream of everything — correlating across files is exactly the work
///         this format exists to remove.
///
/// The variants are the four decisions the daemon actually makes that a
///         human would later need to reconstruct: an access was granted, an
///         address was banned, a ban lifted, a grant expired.
/// KID: The four kinds of thing we write in the robot diary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// An access was authorised: a full sequence matched and a port was opened.
    ///
    /// EXPERT: Carries `user` because attribution is the whole point — this is
    ///         the record that answers "whose credential was used". Carries
    ///         `time_step` so the record can be tied back to the exact window the
    ///         sequence belonged to, which is what makes a later replay analysis
    ///         possible.
    /// KID: "We let this person in through this door, for this long."
    Authorised {
        /// Unix seconds when the decision was made.
        at: u64,
        /// The address the port was opened for.
        ip: IpAddr,
        /// The port that was opened.
        port: u16,
        /// The user whose sequence matched.
        user: String,
        /// The time step the sequence belonged to.
        time_step: u64,
        /// Unix seconds when the grant expires and the port closes.
        expires_at: u64,
    },

    /// An address was banned for exceeding the failure rate limit.
    ///
    /// EXPERT: Carries the count and the window, so an auditor can tell a
    ///         one-off from a sustained attempt without cross-referencing the
    ///         human log — which may already have rotated away.
    /// KID: "We threw this address out, because it knocked wrong this many times."
    Banned {
        /// Unix seconds when the ban was applied.
        at: u64,
        /// The banned address.
        ip: IpAddr,
        /// Failures counted inside the window.
        failures: u32,
        /// The length of the window, in seconds.
        window_seconds: u64,
        /// Unix seconds when the ban expires, or `None` for permanent.
        expires_at: Option<u64>,
    },

    /// A ban expired and the firewall rule was removed.
    BanExpired {
        /// Unix seconds when the ban was lifted.
        at: u64,
        /// The address that was unbanned.
        ip: IpAddr,
    },

    /// An open grant expired and the port was closed again.
    ///
    /// EXPERT: The closing half of `Authorised`. Without it a consumer cannot
    ///         compute how long a port was actually open, which is the question
    ///         an incident review asks first.
    /// KID: "The door we opened is shut again."
    PortClosed {
        /// Unix seconds when the port was closed.
        at: u64,
        /// The address the port had been open for.
        ip: IpAddr,
        /// The port that was closed.
        port: u16,
        /// The user whose grant expired.
        user: String,
    },
}

impl AuditEvent {
    /// A short stable tag, matching the serde `event` field.
    ///
    /// EXPERT: Exists so tests can assert on the tag without deserialising, and
    ///         so the human log line and the machine record agree on the
    ///         vocabulary. Kept in sync with the serde spelling by a test.
    /// KID: The one-word name of this kind of record.
    pub fn tag(&self) -> &'static str {
        match self {
            AuditEvent::Authorised { .. } => "authorised",
            AuditEvent::Banned { .. } => "banned",
            AuditEvent::BanExpired { .. } => "ban_expired",
            AuditEvent::PortClosed { .. } => "port_closed",
        }
    }
}

/// The structured audit stream.
///
/// EXPERT: Holds only a path. Every write opens, appends and closes, rather than
///         holding a file handle open for the daemon's lifetime. That is
///         deliberate: it means an operator can rotate or move the file without
///         restarting the daemon, and it means a crash cannot leave a partially
///         flushed buffer. The cost is one `open` per event, and events happen a
///         few times a minute at most, so the cost is invisible.
///
/// When the path is `None` the log is disabled and every write is a
///         no-op — which is what level 0 and level 1 deployments get, with no
///         branching at the call site.
/// KID: The robot diary. We open it, write one line, and put it away — so you can
///      swap the notebook without us noticing.
#[derive(Debug, Clone)]
pub struct AuditLog {
    /// Where to append, or `None` to disable.
    path: Option<PathBuf>,
}

impl AuditLog {
    /// Build an audit log that appends to `path`.
    pub fn new(path: Option<PathBuf>) -> Self {
        AuditLog { path }
    }

    /// A disabled audit log, for levels 0 and 1.
    ///
    /// EXPERT: An explicit constructor rather than relying on `new(None)` at
    ///         every call site, so the *intent* — "this deployment has no audit
    ///         stream" — is visible in the code rather than implied by an
    ///         argument.
    /// KID: No diary at all.
    pub fn disabled() -> Self {
        AuditLog { path: None }
    }

    /// Is this log actually writing anywhere?
    ///
    /// EXPERT: Used by tests and by the startup log, so an operator can tell
    ///         "level 2 is on and writing here" from "level 2 is on and silently
    ///         doing nothing".
    /// KID: "Is the diary actually being written in?"
    pub fn is_enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Where this log writes, if anywhere.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Append one event as a JSON line.
    ///
    /// EXPERT: Returns `Result` even though every caller logs and continues,
    ///         because a caller that wants to *fail* on a broken audit stream
    ///         (a deployment with a regulatory obligation, say) should be able
    ///         to. The daemon chooses to fail soft; the API does not force that
    ///         choice on anyone else.
    ///
    /// The record is serialised to a `String` first and written in one
    ///         `write_all` call with a trailing newline, so a reader never sees a
    ///         partial line unless the process is killed mid-write — and even
    ///         then the damage is one truncated final line, not a corrupted file.
    /// KID: Write one line in the diary.
    pub fn write(&self, event: &AuditEvent) -> Result<()> {
        // Disabled: nothing to do, and not an error.
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()),
        };

        // Serialise to a generic value first, so we can inject the format
        // version uniformly rather than repeating it in every variant. Doing it
        // here also means a new event variant cannot forget to carry the version
        // — the one place that writes records adds it.
        let mut value = serde_json::to_value(event)
            .map_err(|e| OtkpError::Json(format!("could not serialise audit event: {e}")))?;
        if let Some(obj) = value.as_object_mut() {
            let _ = obj.insert(
                "v".to_string(),
                serde_json::Value::from(AUDIT_FORMAT_VERSION),
            );
        }
        let mut line = serde_json::to_string(&value)
            .map_err(|e| OtkpError::Json(format!("could not serialise audit record: {e}")))?;
        line.push('\n');

        // `OpenOptions` with `create` + `append` rather than `File::create`,
        // which would truncate the log on every event.
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| OtkpError::io_err(path.display().to_string(), e))?;

        // Tighten permissions on the file we just created. We do this after
        // opening rather than before, because we cannot know whether the file
        // already existed; setting it every time is idempotent and cheap.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

        file.write_all(line.as_bytes())
            .map_err(|e| OtkpError::io_err(path.display().to_string(), e))?;

        Ok(())
    }
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

    /// A unique temp path per test.
    fn temp_path(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("otkp-audit-{}-{}.jsonl", std::process::id(), name));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Read a JSON Lines file into a vector of parsed values.
    ///
    /// EXPERT: A test helper, because every test here wants the same thing: prove
    ///         the file is *parseable* line by line, not merely non-empty. A log
    ///         that a machine cannot read has failed at its only job.
    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(path).expect("audit file must be readable");
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("every line must be valid JSON"))
            .collect()
    }

    #[test]
    fn disabled_log_writes_nothing_and_is_not_an_error() {
        let log = AuditLog::disabled();
        assert!(!log.is_enabled());
        assert!(log.path().is_none());
        // Must succeed silently, so callers need no branch.
        log.write(&AuditEvent::BanExpired {
            at: 1,
            ip: ip(1, 2, 3, 4),
        })
        .unwrap();
    }

    #[test]
    fn authorised_record_round_trips() {
        let path = temp_path("authorised");
        let log = AuditLog::new(Some(path.clone()));

        let event = AuditEvent::Authorised {
            at: 1_700_000_000,
            ip: ip(203, 0, 113, 9),
            port: 60802,
            user: "alice".to_string(),
            time_step: 58_655_938,
            expires_at: 1_700_000_030,
        };
        log.write(&event).unwrap();

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let r = &lines[0];
        assert_eq!(r["v"], AUDIT_FORMAT_VERSION);
        assert_eq!(r["event"], "authorised");
        assert_eq!(r["user"], "alice");
        assert_eq!(r["ip"], "203.0.113.9");
        assert_eq!(r["port"], 60802);
        assert_eq!(r["time_step"], 58_655_938u64);
        assert_eq!(r["expires_at"], 1_700_000_030u64);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn banned_record_carries_the_reason() {
        let path = temp_path("banned");
        let log = AuditLog::new(Some(path.clone()));

        log.write(&AuditEvent::Banned {
            at: 100,
            ip: ip(198, 51, 100, 66),
            failures: 5,
            window_seconds: 3600,
            expires_at: Some(3700),
        })
        .unwrap();

        let r = &read_lines(&path)[0];
        assert_eq!(r["event"], "banned");
        assert_eq!(r["failures"], 5);
        assert_eq!(r["window_seconds"], 3600);
        assert_eq!(r["expires_at"], 3700);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn permanent_ban_serialises_expiry_as_null() {
        // `None` must be an explicit null, not an omitted field: a consumer
        // distinguishing "permanent" from "field absent in an old record" needs
        // to see the difference.
        let path = temp_path("permaban");
        let log = AuditLog::new(Some(path.clone()));
        log.write(&AuditEvent::Banned {
            at: 1,
            ip: ip(1, 1, 1, 1),
            failures: 5,
            window_seconds: 3600,
            expires_at: None,
        })
        .unwrap();

        let r = &read_lines(&path)[0];
        assert!(r["expires_at"].is_null(), "got {:?}", r["expires_at"]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn multiple_events_append_as_separate_lines() {
        let path = temp_path("append");
        let log = AuditLog::new(Some(path.clone()));

        log.write(&AuditEvent::Authorised {
            at: 1,
            ip: ip(10, 0, 0, 1),
            port: 22,
            user: "a".into(),
            time_step: 1,
            expires_at: 31,
        })
        .unwrap();
        log.write(&AuditEvent::PortClosed {
            at: 31,
            ip: ip(10, 0, 0, 1),
            port: 22,
            user: "a".into(),
        })
        .unwrap();
        log.write(&AuditEvent::BanExpired {
            at: 32,
            ip: ip(10, 0, 0, 2),
        })
        .unwrap();

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 3, "one line per event");
        assert_eq!(lines[0]["event"], "authorised");
        assert_eq!(lines[1]["event"], "port_closed");
        assert_eq!(lines[2]["event"], "ban_expired");

        // The file must end with a newline, so a following append starts on a
        // fresh line rather than concatenating onto the last record.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.ends_with('\n'));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_does_not_truncate_existing_records() {
        // The single most important property of an audit log: writing to it must
        // never destroy what is already there. `File::create` would, which is why
        // the implementation uses `OpenOptions::append`.
        let path = temp_path("notruncate");
        let log = AuditLog::new(Some(path.clone()));
        log.write(&AuditEvent::BanExpired {
            at: 1,
            ip: ip(1, 1, 1, 1),
        })
        .unwrap();
        log.write(&AuditEvent::BanExpired {
            at: 2,
            ip: ip(2, 2, 2, 2),
        })
        .unwrap();
        assert_eq!(read_lines(&path).len(), 2, "the first record must survive");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tags_match_the_serialised_event_field() {
        // Guards the vocabulary: the `tag()` method and the serde tag must agree,
        // or a consumer filtering on one would miss records written by the other.
        let cases = [
            (
                AuditEvent::Authorised {
                    at: 0,
                    ip: ip(1, 1, 1, 1),
                    port: 1,
                    user: "u".into(),
                    time_step: 0,
                    expires_at: 1,
                },
                "authorised",
            ),
            (
                AuditEvent::Banned {
                    at: 0,
                    ip: ip(1, 1, 1, 1),
                    failures: 1,
                    window_seconds: 1,
                    expires_at: None,
                },
                "banned",
            ),
            (
                AuditEvent::BanExpired {
                    at: 0,
                    ip: ip(1, 1, 1, 1),
                },
                "ban_expired",
            ),
            (
                AuditEvent::PortClosed {
                    at: 0,
                    ip: ip(1, 1, 1, 1),
                    port: 1,
                    user: "u".into(),
                },
                "port_closed",
            ),
        ];
        for (event, want) in cases {
            assert_eq!(event.tag(), want);
            let json: serde_json::Value =
                serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
            assert_eq!(json["event"], want, "serde tag disagrees with tag()");
            // Note: the `v` version field is *not* asserted here. It is injected
            // by `AuditLog::write`, not by the event's own `Serialize`, and that
            // is deliberate — one place adds the version, so a new variant
            // cannot forget it. The write-path tests assert it instead.
        }
    }

    #[test]
    #[cfg(unix)]
    fn audit_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("perms");
        AuditLog::new(Some(path.clone()))
            .write(&AuditEvent::BanExpired {
                at: 0,
                ip: ip(1, 1, 1, 1),
            })
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the audit log must not be world-readable"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_to_an_unwritable_path_is_an_error() {
        // The daemon chooses to log-and-continue, but the API must still report
        // the failure so that choice stays the caller's.
        let log = AuditLog::new(Some(PathBuf::from("/nonexistent/dir/audit.jsonl")));
        let err = log
            .write(&AuditEvent::BanExpired {
                at: 0,
                ip: ip(1, 1, 1, 1),
            })
            .unwrap_err();
        assert!(matches!(err, OtkpError::Io { .. }));
    }
}
