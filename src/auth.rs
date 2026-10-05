// ============================================================================
//  src/auth.rs  --  who currently has a door open, and for how long
// ============================================================================
//
//  EXPERT VIEW:
//    After a successful knock we open a firewall port for one IP. That open state
//    must be tracked, because:
//
//      * We must close it again when the TTL expires.
//      * We must *know* it is open so a second knock from the same IP does not
//        re-open (and re-log, and re-write a firewall rule) every time.
//      * We must be able to list it for the operator.
//
//    The subtlety is the relationship between this table and the firewall. They
//    are two views of the same fact, and they can disagree -- the firewall rule
//    might fail to install, or someone might flush the chain by hand. The design
//    answer here is that **this table is the source of truth for intent**, and
//    the firewall is a best-effort executor. If the firewall call fails, we do
//    NOT record the authorisation: a recorded-but-unenforced grant would make
//    the sweeper try to close a port that was never opened, and would hide the
//    failure from the operator. Failing to record is the honest choice.
//
//    Like the ban list, expiry is handled lazily on read, and the *hot* query
//    (`is_open`) is O(1) without purging.
//
//  KID VIEW:
//    When you knock correctly, we unlock the front door for you for 30 seconds.
//    This file is the note we stick on the fridge: "Bob's door is open until
//    12:00:30." When the time passes, we take the note down and lock the door
//    again. The fridge note is what we trust; the door lock itself is just the
//    machine that does what the note says.
// ============================================================================

use crate::error::OtkpError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// One currently-open grant.
///
/// EXPERT: Carries `user` and `time_step` because an operator asking "who opened
///         this port?" deserves a name, and an auditor asking "which window did
///         this come from?" deserves the window. Neither is secret. Being able
///         to answer those questions from a single struct is worth three fields.
/// KID: The fridge note: whose door, which number, and until when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// The address the port is open for.
    pub ip: IpAddr,

    /// The port that is open.
    pub port: u16,

    /// The user who authenticated.
    pub user: String,

    /// The time step whose sequence authorised this.
    pub time_step: u64,

    /// Unix seconds when the grant was created.
    pub opened_at: u64,

    /// Unix seconds when it must be closed.
    ///
    /// EXPERT: Not an `Option`: an open port with no expiry would be a firewall
    ///         hole we forgot about, which is the single worst failure mode this
    ///         whole project could have. Making expiry mandatory in the type
    ///         means "open forever" is unrepresentable. (`open_ttl_seconds` is
    ///         validated to be >= 1, so there is always a deadline.)
    /// KID: When we must lock the door again. Never blank -- that would be
    ///      dangerous.
    pub expires_at: u64,
}

/// The set of currently-open grants.
///
/// EXPERT: `Default` gives an empty map. No persistence: an open port must not
///         outlive the process that opened it, or a crash would leave a hole
///         with no record of why. On startup we reconcile by closing anything we
///         might have left behind (see `daemon`).
/// KID: The whole set of fridge notes.
#[derive(Debug, Default)]
pub struct AuthTable {
    /// Map from address to grant.
    ///
    /// EXPERT: Keyed by IP, not by `(IP, port)`. The protocol opens exactly one
    ///         port per IP per grant, so IP is a sufficient key, and it keeps the
    ///         hot `is_open(ip)` query a single hash lookup. If a future version
    ///         opens a *set* of ports per user, this becomes the natural place to
    ///         change the key to `(IpAddr, u16)`.
    /// KID: The notes, indexed by whose door it is.
    grants: HashMap<IpAddr, Grant>,
}

impl AuthTable {
    /// An empty table.
    pub fn new() -> Self {
        AuthTable::default()
    }

    /// How many grants are live at `now` (after lazy expiry).
    ///
    /// EXPERT: `&mut self` for the same reason as `BanList::len`: it purges.
    /// KID: How many doors are open right now.
    pub fn len(&mut self, now: u64) -> usize {
        self.purge_expired(now);
        self.grants.len()
    }

    /// Is any port currently open for this address?
    ///
    /// EXPERT: The O(1) hot query. It does not purge; it checks this entry's
    ///         expiry directly. The engine calls this on every packet, so it must
    ///         be allocation-free and branch-cheap.
    /// KID: "Is this person's door already open?"
    pub fn is_open(&self, ip: IpAddr, now: u64) -> bool {
        match self.grants.get(&ip) {
            Some(g) => now < g.expires_at,
            None => false,
        }
    }

    /// Look up the full grant for an address, if it is still live.
    ///
    /// EXPERT: Returns a clone rather than a borrow. The alternative -- returning
    ///         `Option<&Grant>` -- would hold a borrow of `self` across whatever
    ///         the caller does next, which in the daemon means holding it across
    ///         a firewall call. Cloning three small fields is far cheaper than
    ///         the borrow-checker gymnastics required otherwise. This is a
    ///         deliberate trade, not laziness.
    /// KID: Read the whole fridge note for this person.
    pub fn get(&self, ip: IpAddr, now: u64) -> Option<Grant> {
        self.grants.get(&ip).filter(|g| now < g.expires_at).cloned()
    }

    /// Record a new grant.
    ///
    /// EXPERT: Overwrites any existing grant for the IP. The caller (the engine)
    ///         only calls this after a *fresh* successful knock, and it has
    ///         already checked `is_open` to avoid duplicates -- so an overwrite
    ///         here means the previous grant expired between the check and now,
    ///         which is fine. `saturating_add` prevents a `u64` overflow if an
    ///         operator sets an absurd TTL; it saturates at `u64::MAX`, i.e.
    ///         "effectively forever", rather than wrapping to a small number and
    ///         closing the port instantly.
    /// KID: Stick a fresh note on the fridge, replacing any old one.
    pub fn open(
        &mut self,
        ip: IpAddr,
        port: u16,
        user: &str,
        time_step: u64,
        now: u64,
        ttl_seconds: u64,
    ) -> Grant {
        let grant = Grant {
            ip,
            port,
            user: user.to_string(),
            time_step,
            opened_at: now,
            expires_at: now.saturating_add(ttl_seconds),
        };
        let _ = self.grants.insert(ip, grant.clone());
        grant
    }

    /// Remove a grant without closing anything, returning it.
    ///
    /// EXPERT: Used by `purge_expired` and by the shutdown path. The name is
    ///         `take` (not `close`) to make clear that this method does NOT touch
    ///         the firewall -- the caller is responsible for that. Naming a
    ///         method after the side effect it does *not* have would be a trap.
    /// KID: Take the note off the fridge. (The caller then locks the door.)
    pub fn take(&mut self, ip: IpAddr) -> Option<Grant> {
        self.grants.remove(&ip)
    }

    /// Remove all expired grants, returning them so the caller can close ports.
    ///
    /// EXPERT: Returns the full `Grant`s, not just the IPs, because the sweeper
    ///         needs `port` to remove the *specific* firewall rule. Returning IPs
    ///         would force the sweeper to look up the port, which it cannot do
    ///         after the entry is gone. Design the return type around the
    ///         caller's next action -- the same principle as `BanList`.
    /// KID: Find every note whose time is up, take them all down, and hand them
    ///      to the bouncer so he can lock each door.
    pub fn purge_expired(&mut self, now: u64) -> Vec<Grant> {
        // Pass 1: collect expired IPs (read-only).
        let expired: Vec<IpAddr> = self
            .grants
            .values()
            .filter(|g| now >= g.expires_at)
            .map(|g| g.ip)
            .collect();

        // Pass 2: remove and collect the grants (mutable).
        let mut out = Vec::with_capacity(expired.len());
        for ip in expired {
            if let Some(grant) = self.grants.remove(&ip) {
                out.push(grant);
            }
        }
        out
    }

    /// A stable, sorted snapshot for reporting (after lazy expiry).
    ///
    /// EXPERT: Sorted by IP for determinism, same reasoning as the ban list.
    /// KID: A tidy copy of all the fridge notes, to show people.
    pub fn snapshot(&mut self, now: u64) -> Vec<Grant> {
        let _ = self.purge_expired(now);
        let mut out: Vec<Grant> = self.grants.values().cloned().collect();
        out.sort_by_key(|a| a.ip);
        out
    }

    /// Remove every grant, returning them all.
    ///
    /// EXPERT: Used on shutdown so we can close every port we opened. A daemon
    ///         that exits leaving firewall rules behind is a bug, and this method
    ///         exists to make the clean-shutdown path trivially correct: take
    ///         everything, then close everything.
    /// KID: Rip every note off the fridge at closing time.
    pub fn drain(&mut self) -> Vec<Grant> {
        // `drain()` on a HashMap yields `(key, value)` pairs and empties it.
        // We only need the values.
        self.grants.drain().map(|(_, v)| v).collect()
    }

    /// Validate that a grant's invariants hold. Used by tests.
    ///
    /// EXPERT: A tiny predicate rather than an assertion inside `open`, because
    ///         we want tests to be able to express "every grant satisfies this"
    ///         without duplicating the logic. It also documents the invariant in
    ///         one readable place.
    /// KID: A little check that a note makes sense (the door really does close
    ///      after it opens).
    #[cfg(test)]
    pub fn grant_is_well_formed(g: &Grant) -> bool {
        g.expires_at > g.opened_at && g.port != 0 && !g.user.is_empty()
    }
}

/// A convenience constructor for errors raised while opening/closing ports.
///
/// EXPERT: Free function in this module because it is this module's concern.
///         Returning `OtkpError::Firewall` (not `Net`) is deliberate: the
///         failure is "the firewall refused", not "the socket failed".
/// KID: A little machine that builds the right kind of oops for door problems.
pub fn firewall_failure(action: &str, ip: IpAddr, port: u16, detail: &str) -> OtkpError {
    OtkpError::firewall(format!("could not {action} port {port} for {ip}: {detail}"))
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

    #[test]
    fn open_and_query() {
        let mut t = AuthTable::new();
        let addr = ip(10, 0, 0, 1);
        assert!(!t.is_open(addr, 100));

        let grant = t.open(addr, 22, "alice", 7, 100, 30);
        assert_eq!(grant.port, 22);
        assert_eq!(grant.expires_at, 130);

        assert!(t.is_open(addr, 100));
        assert!(t.is_open(addr, 129));
        assert!(!t.is_open(addr, 130)); // exactly at expiry: closed
    }

    #[test]
    fn get_returns_none_after_expiry() {
        let mut t = AuthTable::new();
        let addr = ip(10, 0, 0, 2);
        t.open(addr, 22, "alice", 7, 0, 10);
        assert!(t.get(addr, 5).is_some());
        assert!(t.get(addr, 10).is_none());
    }

    #[test]
    fn purge_returns_grants_with_ports() {
        let mut t = AuthTable::new();
        let a = ip(1, 0, 0, 1);
        let b = ip(1, 0, 0, 2);
        t.open(a, 100, "alice", 1, 0, 10); // expires at 10
        t.open(b, 200, "bob", 1, 0, 1000); // expires at 1000

        let expired = t.purge_expired(10);
        assert_eq!(expired.len(), 1);
        // The port must be carried out with the grant -- this is the whole point.
        assert_eq!(expired[0].port, 100);
        assert_eq!(expired[0].user, "alice");
        assert_eq!(t.len(10), 1);
    }

    #[test]
    fn open_overwrites_existing_grant() {
        let mut t = AuthTable::new();
        let addr = ip(2, 2, 2, 2);
        t.open(addr, 100, "alice", 1, 0, 10);
        t.open(addr, 200, "alice", 2, 50, 10); // same IP, new grant
        let g = t.get(addr, 50).unwrap();
        assert_eq!(g.port, 200);
        assert_eq!(g.expires_at, 60);
        assert_eq!(t.snapshot(50).len(), 1);
    }

    #[test]
    fn take_removes_without_side_effects() {
        let mut t = AuthTable::new();
        let addr = ip(3, 3, 3, 3);
        t.open(addr, 22, "alice", 1, 0, 10);
        let taken = t.take(addr).unwrap();
        assert_eq!(taken.port, 22);
        assert!(t.take(addr).is_none());
        assert!(!t.is_open(addr, 0));
    }

    #[test]
    fn drain_empties_the_table() {
        let mut t = AuthTable::new();
        t.open(ip(4, 0, 0, 1), 22, "a", 1, 0, 10);
        t.open(ip(4, 0, 0, 2), 22, "b", 1, 0, 10);
        let all = t.drain();
        assert_eq!(all.len(), 2);
        assert_eq!(t.snapshot(0).len(), 0);
    }

    #[test]
    fn snapshot_is_sorted() {
        let mut t = AuthTable::new();
        t.open(ip(9, 0, 0, 1), 22, "z", 1, 0, 100);
        t.open(ip(1, 0, 0, 1), 22, "a", 1, 0, 100);
        let snap = t.snapshot(0);
        assert_eq!(snap[0].ip, ip(1, 0, 0, 1));
        assert_eq!(snap[1].ip, ip(9, 0, 0, 1));
    }

    #[test]
    fn grants_are_well_formed() {
        let mut t = AuthTable::new();
        let g = t.open(ip(5, 5, 5, 5), 22, "alice", 1, 100, 30);
        assert!(AuthTable::grant_is_well_formed(&g));
    }

    #[test]
    fn huge_ttl_saturates_instead_of_wrapping() {
        let mut t = AuthTable::new();
        let addr = ip(6, 6, 6, 6);
        // `now + ttl` would overflow u64 here if we used `+`.
        let g = t.open(addr, 22, "alice", 1, u64::MAX - 5, u64::MAX);
        // Saturating add gives u64::MAX, which is "open", not a wrapped small
        // number that would close the port immediately.
        assert_eq!(g.expires_at, u64::MAX);
        assert!(t.is_open(addr, u64::MAX - 1));
    }
}
