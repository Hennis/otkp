// ============================================================================
//  decoy/src/audit.rs  --  the structured trip stream
// ============================================================================
//
//  EXPERT VIEW:
//    Same shape as the main project's audit stream, and deliberately not the
//    same code. JSON Lines, a `v` version field, an `event` tag — so a consumer
//    can join the two streams on convention without the crates depending on each
//    other.
//
//    Why duplicate forty lines rather than share a crate: the design note (§9)
//    requires that the bait not live in the component that authenticates users.
//    A shared crate is a shared blast radius. The convention is the interface;
//    the code is not.
//
//    The record carries the credential, not just the address, because the
//    credential is what the response acts on and what the *investigation* needs.
//    A stream that recorded only addresses would be a stream from which the
//    central question — whose session was this? — could not be answered.
//
//  KID VIEW:
//    The second diary, same as the first one's format so the robot can read both
//    together. We write down whose key it was, not just where they were standing.
// ============================================================================

use crate::trip::{Response, Trip};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// The version of the trip record format.
///
/// EXPERT: Same convention as the main project's audit stream. A consumer can
///         parse what it understands and skip what it does not.
pub const TRIP_FORMAT_VERSION: u32 = 1;

/// One trip: a decoy was touched, and what we decided about it.
///
/// EXPERT: A single flat record rather than a nested one, because the fields a
///         responder needs — credential, trip, response — should be at the top
///         level for a SIEM to key on without a JSON path.
/// KID: One entry in the diary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripEvent {
    /// Unix seconds when the interaction was observed.
    pub at: u64,
    /// Which decoy was touched.
    pub decoy: String,
    /// The address the connection came from. **Evidence, never a handle.**
    pub src_ip: IpAddr,
    /// The credential in use, if it could be attributed.
    pub credential: Option<String>,
    /// How far the visitor got.
    pub trip: Trip,
    /// What the responder has been asked to do.
    pub response: Response,
    /// How many bytes the visitor sent after the banner.
    pub bytes_from_client: usize,
}

impl TripEvent {
    /// Build a record from an observation and its classification.
    ///
    /// EXPERT: Computes the response via the *credential-aware* mapping, so the
    ///         record cannot claim a revocation that the responder could not
    ///         carry out. If the credential is absent, the recorded response is
    ///         the downgraded one — the stream must describe what will actually
    ///         happen, not what would ideally happen.
    /// KID: Write down what we saw and what we are going to do about it.
    pub fn new(seen: &crate::trip::Interaction, trip: Trip) -> Self {
        let response = Response::for_trip_with_credential(&trip, seen.credential.as_deref());
        TripEvent {
            at: seen.at,
            decoy: seen.decoy.clone(),
            src_ip: seen.src_ip,
            credential: seen.credential.clone(),
            trip,
            response,
            bytes_from_client: seen.bytes_from_client,
        }
    }

    /// The event tag, matching the serde spelling.
    pub fn tag(&self) -> &'static str {
        "decoy_trip"
    }
}

/// The append-only trip stream.
///
/// EXPERT: Identical discipline to the main project's `AuditLog`: open, append,
///         close per record; `0600`; never truncate. See that module's docs for
///         why JSON Lines rather than a JSON array, and why the failure policy
///         is soft rather than fatal.
///
/// The one difference: this stream has no regulatory weight, so there is
///         no argument at all for failing hard. A missed trip record is a missed
///         alert, not a compliance breach.
/// KID: The diary. Open it, write one line, put it away.
#[derive(Debug, Clone)]
pub struct TripLog {
    path: Option<PathBuf>,
}

impl TripLog {
    /// Build a trip log that appends to `path`.
    pub fn new(path: Option<PathBuf>) -> Self {
        TripLog { path }
    }

    /// A log that discards everything, for tests and for `--dry-run`.
    pub fn disabled() -> Self {
        TripLog { path: None }
    }

    /// Is this log writing anywhere?
    pub fn is_enabled(&self) -> bool {
        self.path.is_some()
    }

    /// Where it writes, if anywhere.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Append one trip as a JSON line.
    ///
    /// EXPERT: The version is injected here, in the one place that writes
    ///         records, so a new field or variant cannot forget it.
    /// KID: Write one line in the diary.
    pub fn write(&self, event: &TripEvent) -> crate::Result<()> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()),
        };

        let mut value = serde_json::to_value(event)
            .map_err(|e| crate::Error::Json(format!("could not serialise trip: {e}")))?;
        if let Some(obj) = value.as_object_mut() {
            let _ = obj.insert(
                "v".to_string(),
                serde_json::Value::from(TRIP_FORMAT_VERSION),
            );
            let _ = obj.insert("event".to_string(), serde_json::Value::from(event.tag()));
        }
        let mut line = serde_json::to_string(&value)
            .map_err(|e| crate::Error::Json(format!("could not serialise trip record: {e}")))?;
        line.push('\n');

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| crate::Error::io(path.display().to_string(), e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

        file.write_all(line.as_bytes())
            .map_err(|e| crate::Error::io(path.display().to_string(), e))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::trip::Interaction;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn temp_path(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "otkp-decoy-audit-{}-{}.jsonl",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn read_lines(path: &Path) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(path).expect("trip file must be readable");
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("every line must be valid JSON"))
            .collect()
    }

    #[test]
    fn a_probe_record_carries_the_credential_and_a_warning_response() {
        let path = temp_path("probe");
        let log = TripLog::new(Some(path.clone()));

        let seen = Interaction::probe("ssh-old", ip(203, 0, 113, 9))
            .with_credential("alice")
            .at(1_700_000_000);
        let trip = crate::trip::classify(&seen);
        log.write(&TripEvent::new(&seen, trip)).unwrap();

        let r = &read_lines(&path)[0];
        assert_eq!(r["v"], TRIP_FORMAT_VERSION);
        assert_eq!(r["event"], "decoy_trip");
        assert_eq!(r["decoy"], "ssh-old");
        assert_eq!(r["credential"], "alice");
        assert_eq!(r["trip"], "probe");
        assert_eq!(r["response"], "reject_and_warn");
        assert_eq!(r["bytes_from_client"], 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unattributable_trip_records_the_downgraded_response() {
        // The stream must describe what will actually happen. If there is no
        // credential, no revocation can occur, so the record must not claim one.
        let path = temp_path("unattrib");
        let log = TripLog::new(Some(path.clone()));

        let seen = Interaction::probe("http-apache-old", ip(203, 0, 113, 9))
            .with_payload(b"GET /../../etc/passwd HTTP/1.0")
            .at(1);
        let trip = crate::trip::classify(&seen);
        assert_eq!(trip, Trip::Exploit, "the payload is exploit-shaped");

        log.write(&TripEvent::new(&seen, trip)).unwrap();
        let r = &read_lines(&path)[0];
        assert_eq!(r["trip"], "exploit");
        assert_eq!(
            r["response"], "reject_and_warn",
            "with no credential, the response must downgrade"
        );
        assert!(r["credential"].is_null());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn disabled_log_writes_nothing_and_is_not_an_error() {
        let log = TripLog::disabled();
        assert!(!log.is_enabled());
        let seen = Interaction::probe("d", ip(1, 2, 3, 4)).at(1);
        log.write(&TripEvent::new(&seen, Trip::Probe)).unwrap();
    }

    #[test]
    fn records_append_rather_than_truncate() {
        let path = temp_path("append");
        let log = TripLog::new(Some(path.clone()));
        for i in 0..3u64 {
            let seen = Interaction::probe("d", ip(1, 2, 3, 4)).at(i);
            log.write(&TripEvent::new(&seen, Trip::Probe)).unwrap();
        }
        assert_eq!(read_lines(&path).len(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn the_trip_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("perms");
        let log = TripLog::new(Some(path.clone()));
        let seen = Interaction::probe("d", ip(1, 2, 3, 4)).at(1);
        log.write(&TripEvent::new(&seen, Trip::Probe)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unwritable_path_is_an_error() {
        let log = TripLog::new(Some(PathBuf::from("/nonexistent/dir/trips.jsonl")));
        let seen = Interaction::probe("d", ip(1, 2, 3, 4)).at(1);
        assert!(log.write(&TripEvent::new(&seen, Trip::Probe)).is_err());
    }
}
