// ============================================================================
//  src/banlist.rs  --  who is currently locked out
// ============================================================================
//
//  EXPERT VIEW:
//    A ban list is a cache with an eviction policy, and the interesting design
//    questions are all about *when entries leave*:
//
//      * Do bans expire? If `ban_ttl_seconds == 0`, never. Otherwise, after TTL.
//      * Do bans survive a restart? Yes, if we persist them -- otherwise an
//        attacker can reset the daemon's memory (or just wait for a crash) and
//        get a fresh set of attempts. That would defeat the entire point of the
//        feature, so persistence is on by default when a path is configured.
//      * Who evicts expired entries? Nobody can be trusted to call `expire()`
//        on a timer, so we make every *read* lazily purge. That is the standard
//        trick for TTL caches and it cannot be forgotten by a caller.
//
//    The type stores, per IP, the time the ban began and the reason. The reason
//    is for the operator: "why is my office IP blocked?" is answerable from the
//    ban list alone.
//
//  KID VIEW:
//    The naughty corner. When someone taps the wrong knock, we write their
//    address on a list and they have to sit out. If the list says how long they
//    must sit, we cross them off when the time is up. We keep the list in a
//    drawer so that even if we all go home and come back tomorrow, they are
//    still sitting out.
// ============================================================================

use crate::error::{OtkpError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// One entry on the naughty list.
///
/// EXPERT: `#[derive(Clone)]` is fine here: a ban entry contains no secret, only
///         public information (an IP, a timestamp, a short reason). We clone it
///         out of the map when reporting, which keeps the borrow short.
/// KID: One line on the list: which address, when it started sitting out, and
///      why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanEntry {
    /// The banned address.
    ///
    /// EXPERT: `IpAddr` (not `String`) so serde serialises it as a canonical
    ///         string and the type system prevents us storing something that is
    ///         not an address. It handles both IPv4 and IPv6.
    /// KID: The address we wrote down.
    pub ip: IpAddr,

    /// Unix seconds when the ban was applied.
    pub banned_at: u64,

    /// Unix seconds when the ban expires; `None` means forever.
    ///
    /// EXPERT: `Option<u64>` rather than the `0`-means-forever convention,
    ///         because `Option` is unambiguous and the compiler forces every
    ///         caller to consider the "forever" case. We only translate the
    ///         operator's `0` into `None` at the boundary (in `ban`).
    /// KID: When they can come back. Blank means "never".
    pub expires_at: Option<u64>,

    /// A short human-readable reason, e.g. "failed knock from 10.0.0.5".
    ///
    /// EXPERT: Deliberately free-form text. It is never parsed; it exists to
    ///         answer an operator's question at 3am. We cap its length when
    ///         storing to bound the file size an attacker could grow.
    /// KID: A little note about *why* they are in trouble.
    pub reason: String,
}

/// The set of currently-banned addresses, with optional persistence.
///
/// EXPERT: `#[derive(Default)]` gives us an empty map and no path, which is the
///         right "no persistence" default. `Debug` is safe (no secrets).
/// KID: The whole naughty list, plus a note of where we keep it.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BanList {
    /// Map from address to entry.
    ///
    /// EXPERT: Private, like `Keyring`'s map, so all mutation goes through
    ///         `ban`/`unban` and the TTL logic cannot be bypassed.
    /// KID: The list, indexed by address.
    entries: HashMap<IpAddr, BanEntry>,

    /// Where to persist, if anywhere.
    ///
    /// EXPERT: `#[serde(skip)]` keeps this field out of the JSON: the file
    ///         contents should be the ban *data*, not a record of where the file
    ///         is. Loading then re-attaching the path is the caller's job (see
    ///         `load`). Without `skip`, a file moved to a new location would
    ///         silently keep writing to the old one.
    /// KID: A sticky note on the drawer saying "this is the drawer". We do not
    ///      copy the sticky note into the list itself.
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl BanList {
    /// A new, empty, non-persistent ban list.
    pub fn new() -> Self {
        BanList::default()
    }

    /// Attach a persistence path (a builder-style method).
    ///
    /// EXPERT: Taking `self` by value and returning `Self` makes this chainable
    ///         (`BanList::new().with_path(p)`), and the "consume and return"
    ///         signature prevents the mistake of keeping an old handle that does
    ///         not know about the path.
    /// KID: "Keep the list in this drawer."
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// How many addresses are banned right now (after lazy expiry).
    ///
    /// EXPERT: `&mut self` because we purge expired entries first. This is the
    ///         lazy-eviction decision in action: any read that wants an accurate
    ///         count pays for the purge. For a list that is usually tiny, that is
    ///         far cheaper than a background timer thread.
    /// KID: How many people are sitting out, not counting anyone whose time is
    ///      already up.
    pub fn len(&mut self, now: u64) -> usize {
        self.purge_expired(now);
        self.entries.len()
    }

    /// Is the list empty (after lazy expiry)?
    pub fn is_empty(&mut self, now: u64) -> bool {
        self.len(now) == 0
    }

    /// Is this address banned at time `now`?
    ///
    /// EXPERT: The hot-path query. Note that it does NOT purge: purging on every
    ///         packet would be O(n) per packet. Instead it checks *this* entry's
    ///         expiry directly, which is O(1). The purge happens on the slower
    ///         paths (`len`, `snapshot`, `ban`) so the map cannot grow forever.
    ///         This split -- O(1) hot query, O(n) occasional purge -- is the
    ///         standard shape of a TTL cache.
    /// KID: "Is this address in the naughty corner *right now*?" (We check the
    ///      one line, not the whole list, so it is fast.)
    pub fn is_banned(&self, ip: IpAddr, now: u64) -> bool {
        match self.entries.get(&ip) {
            // Not on the list at all.
            None => false,
            // On the list with no expiry: banned.
            Some(e) if e.expires_at.is_none() => true,
            // On the list with an expiry: banned only while we are before it.
            // `Some(exp)` binds the inner u64.
            Some(e) => match e.expires_at {
                Some(exp) => now < exp,
                None => true, // unreachable given the arm above, but exhaustive
            },
        }
    }

    /// Ban an address.
    ///
    /// EXPERT: `ttl_seconds == 0` means permanent, translated here into
    ///         `expires_at: None`. Re-banning an already-banned address extends
    ///         the ban (the new entry overwrites), which is the behaviour you
    ///         want: a repeat offender should not get a shorter sentence because
    ///         the clock restarted. We cap the reason's length so an attacker who
    ///         can influence the reason string cannot grow the file unboundedly.
    /// KID: Write them on the list. If they were already there, their sentence
    ///      starts over -- no early release for repeat trouble.
    pub fn ban(&mut self, ip: IpAddr, now: u64, ttl_seconds: u64, reason: &str) -> BanEntry {
        // Translate the operator's "0 = forever" into the type-safe `None`.
        let expires_at = if ttl_seconds == 0 {
            None
        } else {
            Some(now.saturating_add(ttl_seconds))
        };

        // Truncate the reason to 200 chars. `chars().take(n)` counts *characters*,
        // not bytes, so we cannot split a multi-byte UTF-8 sequence and panic.
        let reason: String = reason.chars().take(200).collect();

        let entry = BanEntry {
            ip,
            banned_at: now,
            expires_at,
            reason,
        };
        // `insert` returns the previous entry; we do not need it.
        let _ = self.entries.insert(ip, entry.clone());
        entry
    }

    /// Lift a ban, returning `true` if there was one.
    ///
    /// EXPERT: Used by the sweeper when a ban expires, and by an operator via
    ///         the CLI. Removing a non-existent entry is not an error: "unban
    ///         this IP" is idempotent by nature.
    /// KID: Cross them off the list.
    pub fn unban(&mut self, ip: IpAddr) -> bool {
        self.entries.remove(&ip).is_some()
    }

    /// Remove every entry whose expiry has passed, returning the removed IPs.
    ///
    /// EXPERT: Returns the removed addresses rather than a count because the
    ///         caller (the daemon's sweeper) needs to remove the corresponding
    ///         *firewall rules*. A count would be useless; the list of IPs is
    ///         exactly the work to do. This is a small example of designing the
    ///         return type around the caller's next action.
    ///
    /// `retain` cannot return the removed items, so we collect the keys
    ///         first and remove in a second pass. The borrow of `self.entries`
    ///         from the first pass must end before the second pass mutates, which
    ///         the `collect::<Vec<_>>()` guarantees.
    /// KID: Find everyone whose sitting-out time is up, and cross them all off,
    ///      handing the bouncer their addresses so he can reopen their doors.
    pub fn purge_expired(&mut self, now: u64) -> Vec<IpAddr> {
        // Pass 1: read-only scan, collecting the expired addresses.
        let expired: Vec<IpAddr> = self
            .entries
            .values()
            // `filter_map` keeps only the `Some` results.
            .filter_map(|e| match e.expires_at {
                // Expired if the expiry time has arrived.
                Some(exp) if now >= exp => Some(e.ip),
                // No expiry, or not yet expired: keep.
                _ => None,
            })
            .collect();

        // Pass 2: mutate. `for ip in &expired` borrows the Vec immutably while
        // `self.entries` is borrowed mutably -- allowed, because they are
        // different objects.
        for ip in &expired {
            let _ = self.entries.remove(ip);
        }

        expired
    }

    /// A stable, sorted snapshot for reporting.
    ///
    /// EXPERT: Returns owned `BanEntry` clones, sorted by IP, so the CLI can
    ///         print a deterministic table and the tests are not flaky on
    ///         `HashMap` iteration order. Sorting `IpAddr` uses its `Ord` impl,
    ///         which orders v4 before v6 and then numerically within each family
    ///         -- exactly the order a human expects.
    /// KID: A tidy alphabetical-by-address copy of the list to show people.
    pub fn snapshot(&mut self, now: u64) -> Vec<BanEntry> {
        self.purge_expired(now);
        let mut out: Vec<BanEntry> = self.entries.values().cloned().collect();
        out.sort_by_key(|a| a.ip);
        out
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------
    /// Load a ban list from disk, attaching the path for future saves.
    ///
    /// EXPERT: A *missing* file yields an empty list, unlike `Keyring::load`.
    ///         The asymmetry is deliberate: a missing keyring is a
    ///         misconfiguration (there is nobody to authenticate), whereas a
    ///         missing ban list is the normal state of a fresh install and on the
    ///         first run after a cleanup. Failing hard there would be hostile.
    /// KID: Open the drawer. If there is no drawer yet, that is fine -- just
    ///      start with a blank list.
    pub fn load(path: &Path) -> Result<Self> {
        // `try_exists` distinguishes "does not exist" from "cannot tell", but for
        // our purposes a simple existence check is enough; the subsequent read
        // would surface a real permission problem anyway.
        if !path.exists() {
            return Ok(BanList::default().with_path(path.to_path_buf()));
        }
        let file = std::fs::File::open(path)
            .map_err(|e| OtkpError::io_err(path.display().to_string(), e))?;
        let mut list: BanList = serde_json::from_reader(file)
            .map_err(|e| OtkpError::Json(format!("{}: {e}", path.display())))?;
        // Re-attach the path: it was `#[serde(skip)]`ed, so it came back as None.
        list.path = Some(path.to_path_buf());
        Ok(list)
    }

    /// Persist the ban list, if a path is attached.
    ///
    /// EXPERT: Returns `Ok(())` immediately when there is no path, so callers
    ///         can call `save()` unconditionally without a branch. "Do the right
    ///         thing, or nothing, based on configuration" is a good shape for an
    ///         optional side effect.
    ///
    /// Same atomic-write discipline as the keyring: temp file, then
    ///         rename. Unlike the keyring we do NOT force 0600: a ban list holds
    ///         no secrets and an operator may legitimately want to read it.
    /// KID: Write the list into the drawer, if we have a drawer. Write it on a
    ///      fresh sheet and swap it in one move, so a crash never leaves half a
    ///      list.
    pub fn save(&self) -> Result<()> {
        // No path configured: nothing to do, and that is not an error.
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()),
        };

        let json = serde_json::to_vec_pretty(self).map_err(|e| OtkpError::Json(e.to_string()))?;

        // Temp file beside the target, for an atomic same-filesystem rename.
        let tmp_path: PathBuf = match path.parent() {
            Some(dir) => dir.join(format!(
                ".{}.tmp",
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("banlist")
            )),
            None => PathBuf::from(format!("{}.tmp", path.display())),
        };

        std::fs::write(&tmp_path, &json)
            .map_err(|e| OtkpError::io_err(tmp_path.display().to_string(), e))?;

        std::fs::rename(&tmp_path, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            OtkpError::io_err(path.display().to_string(), e)
        })?;

        Ok(())
    }

    /// How many entries are stored, expired or not (no purge).
    ///
    /// EXPERT: An escape hatch for diagnostics and tests that need the raw size
    ///         without paying for a purge. Named `raw_len` so nobody mistakes it
    ///         for the user-facing count.
    /// KID: The list's true length, without tidying it first.
    pub fn raw_len(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Shorthand for building an `IpAddr` from four octets.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn ban_and_query() {
        let mut bl = BanList::new();
        let addr = ip(10, 0, 0, 5);
        assert!(!bl.is_banned(addr, 100));

        bl.ban(addr, 100, 3600, "failed knock");
        assert!(bl.is_banned(addr, 100));
        assert!(bl.is_banned(addr, 100 + 3599)); // still inside the window
        assert!(!bl.is_banned(addr, 100 + 3600)); // exactly at expiry: lifted
    }

    #[test]
    fn permanent_ban_never_expires() {
        let mut bl = BanList::new();
        let addr = ip(192, 168, 1, 1);
        bl.ban(addr, 0, 0, "forever"); // ttl 0 == permanent
                                       // Check a very long time later.
        assert!(bl.is_banned(addr, u64::MAX - 1));
        assert_eq!(bl.snapshot(0)[0].expires_at, None);
    }

    #[test]
    fn purge_removes_only_expired() {
        let mut bl = BanList::new();
        let a = ip(1, 1, 1, 1);
        let b = ip(2, 2, 2, 2);
        bl.ban(a, 0, 100, "short");
        bl.ban(b, 0, 10_000, "long");

        // At t=50, nobody has expired.
        assert!(bl.purge_expired(50).is_empty());
        assert_eq!(bl.raw_len(), 2);

        // At t=100, `a` has expired (expiry is inclusive of the boundary).
        let removed = bl.purge_expired(100);
        assert_eq!(removed, vec![a]);
        assert_eq!(bl.raw_len(), 1);
        assert!(!bl.is_banned(a, 100));
        assert!(bl.is_banned(b, 100));
    }

    #[test]
    fn reban_extends_the_sentence() {
        let mut bl = BanList::new();
        let addr = ip(3, 3, 3, 3);
        bl.ban(addr, 0, 100, "first");
        bl.ban(addr, 50, 100, "again"); // expires at 150, not 100
        assert!(bl.is_banned(addr, 149));
        assert!(!bl.is_banned(addr, 150));
    }

    #[test]
    fn unban_is_idempotent() {
        let mut bl = BanList::new();
        let addr = ip(4, 4, 4, 4);
        bl.ban(addr, 0, 0, "x");
        assert!(bl.unban(addr));
        assert!(!bl.unban(addr));
    }

    #[test]
    fn snapshot_is_sorted_and_purged() {
        let mut bl = BanList::new();
        bl.ban(ip(9, 0, 0, 1), 0, 0, "z");
        bl.ban(ip(1, 0, 0, 1), 0, 0, "a");
        bl.ban(ip(5, 0, 0, 1), 0, 50, "expires soon");

        // At t=100 the third entry is gone.
        let snap = bl.snapshot(100);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].ip, ip(1, 0, 0, 1));
        assert_eq!(snap[1].ip, ip(9, 0, 0, 1));
    }

    #[test]
    fn len_purges_first() {
        let mut bl = BanList::new();
        bl.ban(ip(1, 1, 1, 1), 0, 10, "short");
        // `len` is `&mut self` precisely so it can purge.
        assert_eq!(bl.len(1000), 0);
    }

    #[test]
    fn reason_is_truncated() {
        let mut bl = BanList::new();
        let long_reason = "x".repeat(10_000);
        let entry = bl.ban(ip(1, 2, 3, 4), 0, 0, &long_reason);
        assert_eq!(entry.reason.len(), 200);
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("otkp-banlist-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("banlist.json");

        let mut bl = BanList::new().with_path(path.clone());
        bl.ban(ip(7, 7, 7, 7), 1000, 0, "permanent");
        bl.ban(ip(8, 8, 8, 8), 1000, 500, "temporary");
        bl.save().unwrap();

        let loaded = BanList::load(&path).unwrap();
        assert_eq!(loaded.raw_len(), 2);
        assert!(loaded.is_banned(ip(7, 7, 7, 7), 2000));

        // Saving again through the loaded list must work: the path survived.
        let mut loaded = loaded;
        loaded.unban(ip(7, 7, 7, 7));
        loaded.save().unwrap();
        let reloaded = BanList::load(&path).unwrap();
        assert_eq!(reloaded.raw_len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_file_is_empty_not_an_error() {
        // Unlike the keyring, a missing ban list is normal.
        let path = Path::new("/nonexistent/otkp/banlist.json");
        let bl = BanList::load(path).unwrap();
        assert_eq!(bl.raw_len(), 0);
    }

    #[test]
    fn save_without_path_is_a_noop() {
        let bl = BanList::new();
        // Must not error and must not create a file anywhere.
        bl.save().unwrap();
    }
}
