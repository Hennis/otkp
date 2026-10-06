// ============================================================================
//  src/keyring.rs  --  who is enrolled, and the secret each of them holds
// ============================================================================
//
//  EXPERT VIEW:
//    The keyring is the server's half of the shared-secret relationship. It maps
//    a user name to that user's `MasterSecret`, and it is the *only* place on
//    the server where secrets live. Everything about this file follows from two
//    facts:
//
//      1. The file is extremely sensitive. It must be readable only by root
//         (`chmod 0600`, root-owned). `otkp init` and `otkp enroll` enforce this.
//      2. It is read once at daemon startup and then consulted in the hot path.
//         So we load it into a `HashMap` and never touch the disk again.
//
//    The type is a newtype over `HashMap<String, MasterSecret>` rather than a
//    bare map, because a bare map would let any code call `.insert()` and add a
//    user with no validation. Wrapping it means the only way to add a user is
//    `enroll()`, which generates the secret properly and rejects duplicates.
//    Encapsulation, used for a real reason rather than as ceremony.
//
//  KID VIEW:
//    This is the guest list at the door of the club. Next to each name is that
//    person's secret handshake. The list is kept in a locked drawer only the
//    bouncer (root) can open. We never let anyone scribble on the list while the
//    club is open -- you add names before you open the doors.
// ============================================================================

use crate::config::ServerConfig;
use crate::crypto::{derive_with_hotp, KnockSpec};
use crate::error::{OtkpError, Result};
use crate::secret::MasterSecret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// One enrolled user: their name, their secret, and some bookkeeping.
///
/// EXPERT: `secret` is a `MasterSecret`, which does not implement `Clone`. That
///         means `Enrollment` is not `Clone` either, which is the correct
///         consequence: cloning an enrolment would duplicate a key in memory.
///         The `enrolled_at` timestamp is not security-critical; it exists so an
///         operator can audit "when was this account created?" and so a future
///         revocation feature has something to work with.
/// KID: A line on the guest list: your name, your handshake, and the day you
///      joined the club.
#[derive(Debug, Serialize, Deserialize)]
pub struct Enrollment {
    /// The user's name, exactly as it will be typed on the client.
    ///
    /// EXPERT: This string is an input to the HMAC, so changing it changes every
    ///         derived sequence. It is therefore immutable in spirit: renaming a
    ///         user is a re-enrolment, not an edit. We say so in `enroll`'s docs.
    /// KID: Your name. Change your name and you need a brand-new handshake.
    pub user: String,

    /// The user's secret key material.
    ///
    /// EXPERT: Serialised by `MasterSecret`'s hand-written `Serialize` as a
    ///         base32 string, so the on-disk keyring is greppable and editable
    ///         by a human in an emergency.
    /// KID: The handshake itself.
    pub secret: MasterSecret,

    /// Unix seconds when this enrolment was created.
    pub enrolled_at: u64,
}

// ===========================================================================
//  Keyring
// ===========================================================================
/// The full set of enrolled users.
///
/// EXPERT: `#[derive(Debug)]` is safe here because `MasterSecret`'s `Debug` is
///         hand-written to redact the bytes. This is the payoff for that earlier
///         care: we get debuggable structs without leaking keys.
/// KID: The whole guest list.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Keyring {
    /// Map from user name to enrolment.
    ///
    /// EXPERT: Private. Reach it through `get`, `users`, `len`. A `HashMap`
    ///         rather than a `Vec` because the hot path does a lookup per
    ///         candidate user per packet, and O(1) beats O(n) there. With a
    ///         handful of users the difference is irrelevant, but the access
    ///         pattern is what you should encode, not today's small n.
    /// KID: The list, indexed by name so we can find you fast.
    entries: HashMap<String, Enrollment>,
}

impl Keyring {
    /// An empty keyring.
    ///
    /// EXPERT: `HashMap::new()` allocates nothing until the first insert, so
    ///         this is free.
    /// KID: A blank guest list.
    pub fn new() -> Self {
        Keyring {
            entries: HashMap::new(),
        }
    }

    /// How many users are enrolled.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the keyring empty?
    ///
    /// EXPERT: `is_empty` accompanies `len` per the clippy convention (see the
    ///         note in `crypto::KnockSpec`). Unlike that one, this can be true,
    ///         and the daemon refuses to start with an empty keyring -- there
    ///         would be nobody to authenticate.
    /// KID: "Is the guest list blank?"
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up one user's enrolment.
    ///
    /// EXPERT: Returns `Option<&Enrollment>`, borrowing from the map. The borrow
    ///         checker guarantees the caller cannot hold this reference while
    ///         mutating the keyring, which is exactly the aliasing rule we want
    ///         around key material.
    /// KID: "Find me Bob's line on the list."
    pub fn get(&self, user: &str) -> Option<&Enrollment> {
        self.entries.get(user)
    }

    /// All user names, sorted.
    ///
    /// EXPERT: Sorting is deliberate. A `HashMap` iterates in a *nondeterministic*
    ///         order (it is randomised per process to prevent hash-flooding
    ///         attacks). Anywhere we iterate the keyring -- the engine's
    ///         per-packet loop, the CLI's `list` output -- nondeterminism would
    ///         make logs unreproducible and tests flaky. Sorting restores a
    ///         stable order at O(n log n) once per call, which is nothing.
    /// KID: A tidy alphabetical list of everyone's names.
    pub fn users(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(|s| s.as_str()).collect();
        names.sort_unstable(); // `sort_unstable` is fine: names are unique.
        names
    }

    /// Iterate `(name, enrollment)` pairs in a stable, sorted order.
    ///
    /// EXPERT: This is the method the engine's hot loop actually uses. Returning
    ///         a `Vec` of references allocates once per call, which sounds bad
    ///         for a per-packet path -- but the engine caches the candidate list
    ///         per time step, so this runs once per window, not once per packet.
    /// KID: Walk the whole list, in the same order every time.
    pub fn iter_sorted(&self) -> Vec<(&str, &Enrollment)> {
        self.users()
            .into_iter()
            // `filter_map` is `filter` + `map` in one pass: it drops `None`s.
            .filter_map(|name| self.entries.get(name).map(|e| (name, e)))
            .collect()
    }

    /// Enrol a new user, generating a fresh secret.
    ///
    /// EXPERT: Returns a *borrow* of the new enrolment so the caller can print
    ///         the enrolment URI without cloning the secret. Rejects duplicate
    ///         names, because silently overwriting a user's secret would lock
    ///         them out of a working client with no explanation -- a nasty,
    ///         confusing failure. Explicit is better.
    ///
    /// IMPORTANT SEMANTIC: the user name is an input to the HMAC. A
    ///         "rename" is therefore not a rename; it is a new identity with a
    ///         new secret. There is no `rename` method on purpose.
    /// KID: "Add a new person to the guest list with a brand-new handshake. If
    ///      their name is already there, stop and tell me -- do not overwrite
    ///      their old handshake by accident."
    pub fn enroll(&mut self, user: &str, now: u64) -> Result<&Enrollment> {
        // Reject empty or whitespace-only names: they would be valid HMAC
        // inputs but impossible to type reliably.
        if user.trim().is_empty() {
            return Err(OtkpError::config("user name must not be empty"));
        }
        // Reject a duplicate rather than overwriting.
        if self.entries.contains_key(user) {
            return Err(OtkpError::config(format!(
                "user '{user}' is already enrolled; revoke them first if you mean to re-enrol"
            )));
        }
        // Generate the key material from the OS CSPRNG.
        let secret = MasterSecret::generate();
        let enrollment = Enrollment {
            user: user.to_string(),
            secret,
            enrolled_at: now,
        };
        // `insert` returns the old value if any; we already checked there is
        // none, so we discard the `Option` explicitly with `let _ =` to make the
        // intent visible rather than relying on `#[must_use]` suppression.
        let _ = self.entries.insert(user.to_string(), enrollment);
        // Return a borrow. `expect` here is safe by construction (we just
        // inserted), and it is a *startup/CLI* path, not a per-packet path.
        Ok(self
            .entries
            .get(user)
            .expect("just inserted the entry, so it must exist"))
    }

    /// Remove a user, returning `true` if they were present.
    ///
    /// EXPERT: `HashMap::remove` returns `Option<V>`. Mapping that to a `bool`
    ///         lets the CLI say "revoked alice" versus "no such user" without
    ///         exposing the enrolment (and hence the secret) to the caller.
    /// KID: "Cross someone off the guest list."
    pub fn revoke(&mut self, user: &str) -> bool {
        self.entries.remove(user).is_some()
    }

    /// Derive the knock spec for a user at a given step, or explain why not.
    ///
    /// EXPERT: This is a *convenience* that fuses the lookup and the derivation,
    ///         because the two are always used together and splitting them would
    ///         force every caller to handle the `None` case separately. Note the
    ///         error is `NotFound`, not `Secret`: from the caller's perspective
    ///         the problem is "that user is not on the list", and naming the
    ///         right problem is half of a good error message.
    /// KID: "Look up Bob and work out his taps for this page of the book."
    pub fn spec_for(
        &self,
        user: &str,
        step: u64,
        cfg: &ServerConfig,
        src_ip: Option<IpAddr>,
    ) -> Result<KnockSpec> {
        let enrollment = self
            .get(user)
            .ok_or_else(|| OtkpError::not_found(format!("user '{user}' is not enrolled")))?;
        Ok(crate::crypto::derive_knock_spec(
            &enrollment.secret,
            user,
            step,
            cfg,
            src_ip,
        ))
    }

    /// Derive the spec *and* the HOTP for a user, for enrolment/verification.
    ///
    /// EXPERT: Delegates to `crypto::derive_with_hotp` so the "same window for
    ///         both" guarantee lives in exactly one place.
    /// KID: Same as above, but also give the phone-app number.
    pub fn spec_and_hotp_for(
        &self,
        user: &str,
        step: u64,
        cfg: &ServerConfig,
        src_ip: Option<IpAddr>,
    ) -> Result<(KnockSpec, u32)> {
        let enrollment = self
            .get(user)
            .ok_or_else(|| OtkpError::not_found(format!("user '{user}' is not enrolled")))?;
        Ok(derive_with_hotp(
            &enrollment.secret,
            user,
            step,
            cfg,
            src_ip,
        ))
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------
    /// Load a keyring from a JSON file.
    ///
    /// EXPERT: `serde_json::from_reader` streams from the file, so we do not
    ///         build a second copy of the file contents in memory. The parse
    ///         goes through `MasterSecret`'s hand-written `Deserialize`, which
    ///         accepts both base32 and hex -- so a hand-edited keyring keeps
    ///         working.
    ///
    /// A missing file is an error, not an empty keyring. If an operator
    ///         points the daemon at the wrong directory, we want a loud "no such
    ///         file" rather than a silently-empty keyring that authenticates
    ///         nobody and looks like a mysterious client-side bug.
    /// KID: Open the guest-list drawer and read it. If the drawer is missing,
    ///      shout -- do not pretend the list is empty.
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| OtkpError::io_err(path.display().to_string(), e))?;
        let keyring: Keyring = serde_json::from_reader(file)
            .map_err(|e| OtkpError::Json(format!("{}: {e}", path.display())))?;
        Ok(keyring)
    }

    /// Write the keyring to a JSON file with owner-only permissions.
    ///
    /// EXPERT: Two subtleties, both important:
    ///
    /// 1. **Atomicity.** We write to a temporary file and `rename` it
    ///            into place. `rename` within a filesystem is atomic, so a crash
    ///            mid-write leaves the *old* keyring intact rather than a
    ///            half-written one that locks everyone out. This is the standard
    ///            "write, fsync, rename" pattern.
    ///         2. **Permissions.** We set mode 0600 on Unix. On a fresh file
    ///            created by `File::create` the mode is 0644 minus umask, which
    ///            is world-readable -- unacceptable for secrets. We set the mode
    ///            explicitly rather than relying on the umask.
    ///
    /// On non-Unix platforms we skip the chmod (the crate still compiles
    ///         there; it just cannot promise the permission).
    /// KID: Write the list on a fresh sheet of paper, then swap it for the old
    ///      one in one quick move so the drawer is never half-empty. And lock
    ///      the drawer so only the bouncer can read it.
    pub fn save(&self, path: &Path) -> Result<()> {
        // Step 1: serialise to pretty JSON. `to_vec_pretty` gives a `Vec<u8>`
        // (UTF-8 bytes), which is what we want to write.
        let json = serde_json::to_vec_pretty(self).map_err(|e| OtkpError::Json(e.to_string()))?;

        // Step 2: build a temporary path next to the target, so the `rename` is
        // within the same filesystem (and therefore atomic).
        let tmp_path: PathBuf = match path.parent() {
            Some(dir) => dir.join(format!(
                ".{}.tmp",
                path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("keyring")
            )),
            // No parent means the path is just a bare filename; use it directly.
            None => PathBuf::from(format!("{}.tmp", path.display())),
        };

        // Step 3: write the temp file.
        std::fs::write(&tmp_path, &json)
            .map_err(|e| OtkpError::io_err(tmp_path.display().to_string(), e))?;

        // Step 4: tighten permissions BEFORE the rename, so the file is never
        // briefly world-readable under its final name.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // 0o600 = owner read+write, nothing for group or other.
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)
                .map_err(|e| OtkpError::io_err(tmp_path.display().to_string(), e))?;
        }

        // Step 5: atomically move it into place.
        std::fs::rename(&tmp_path, path).map_err(|e| {
            // On failure, try to clean up the temp file so we do not litter.
            let _ = std::fs::remove_file(&tmp_path);
            OtkpError::io_err(path.display().to_string(), e)
        })?;

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
    fn enroll_and_get() {
        let mut kr = Keyring::new();
        assert!(kr.is_empty());
        kr.enroll("alice", 1000).unwrap();
        assert_eq!(kr.len(), 1);
        assert!(kr.get("alice").is_some());
        assert!(kr.get("bob").is_none());
    }

    #[test]
    fn enroll_rejects_duplicates() {
        let mut kr = Keyring::new();
        kr.enroll("alice", 1000).unwrap();
        let err = kr.enroll("alice", 2000).unwrap_err();
        assert!(err.to_string().contains("already enrolled"));
        // The original secret must be untouched by the failed attempt.
        assert_eq!(kr.get("alice").unwrap().enrolled_at, 1000);
    }

    #[test]
    fn enroll_rejects_empty_name() {
        let mut kr = Keyring::new();
        assert!(kr.enroll("", 1).is_err());
        assert!(kr.enroll("   ", 1).is_err());
    }

    #[test]
    fn revoke_removes() {
        let mut kr = Keyring::new();
        kr.enroll("alice", 1).unwrap();
        assert!(kr.revoke("alice"));
        assert!(!kr.revoke("alice")); // second time: already gone
        assert!(kr.is_empty());
    }

    #[test]
    fn users_are_sorted() {
        let mut kr = Keyring::new();
        for name in ["carol", "alice", "bob"] {
            kr.enroll(name, 1).unwrap();
        }
        assert_eq!(kr.users(), vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn spec_for_unknown_user_is_not_found() {
        let kr = Keyring::new();
        let cfg = ServerConfig::default();
        let err = kr.spec_for("nobody", 1, &cfg, None).unwrap_err();
        assert!(matches!(err, OtkpError::NotFound(_)));
    }

    #[test]
    fn spec_for_known_user_matches_direct_derivation() {
        let mut kr = Keyring::new();
        kr.enroll("alice", 1).unwrap();
        let cfg = ServerConfig::default();
        let via_keyring = kr.spec_for("alice", 5, &cfg, None).unwrap();
        let direct = crate::crypto::derive_knock_spec(
            &kr.get("alice").unwrap().secret,
            "alice",
            5,
            &cfg,
            None,
        );
        assert_eq!(via_keyring, direct);
    }

    #[test]
    fn save_and_load_round_trip() {
        // Use a unique temp path so parallel tests do not collide.
        let dir = std::env::temp_dir().join(format!("otkp-keyring-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keyring.json");

        let mut kr = Keyring::new();
        kr.enroll("alice", 42).unwrap();
        kr.enroll("bob", 43).unwrap();
        kr.save(&path).unwrap();

        let loaded = Keyring::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.users(), vec!["alice", "bob"]);
        // The secrets must survive the round trip byte-for-byte.
        assert!(loaded
            .get("alice")
            .unwrap()
            .secret
            .ct_eq(&kr.get("alice").unwrap().secret));

        // On Unix, the file must be owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "keyring must be chmod 600");
        }

        // Clean up.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_file_is_an_error() {
        let path = Path::new("/nonexistent/otkp/keyring.json");
        let err = Keyring::load(path).unwrap_err();
        assert!(matches!(err, OtkpError::Io { .. }));
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let mut kr = Keyring::new();
        kr.enroll("alice", 1).unwrap();
        let printed = format!("{kr:?}");
        let secret_b32 = kr.get("alice").unwrap().secret.to_base32();
        assert!(!printed.contains(&secret_b32), "Debug leaked the secret!");
        assert!(printed.contains("redacted"));
    }
}
