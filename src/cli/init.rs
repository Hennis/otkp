// ============================================================================
//  src/cli/init.rs  --  `otkp init`: create the data directory and its files
// ============================================================================
//
//  EXPERT VIEW:
//    `init` is the least glamorous command and the most important to get right,
//    because it is the one that establishes the *permissions posture* of the
//    whole installation. Three things must be true after it runs:
//
//      1. The directory exists and is `0700` (owner-only). If the keyring
//         directory is world-readable, every other security property is moot.
//      2. `keyring.json` exists, is valid JSON, and is `0600`. It starts empty:
//         `init` never enrols anyone, so it cannot leak a secret it never had.
//      3. `banlist.json` exists and is valid (an empty list). We create it so
//         the daemon's first `load` finds a well-formed file rather than relying
//         on the "missing is fine" path -- fewer special cases at runtime.
//
//    The command refuses to overwrite existing files unless `--force` is given.
//    That is a safety default with real consequences: re-running `init` by
//    accident should not destroy a keyring full of live secrets. When `--force`
//    is given we still do not touch an existing keyring unless it is empty, and
//    we say so loudly -- because "I forced init and now everyone is locked out"
//    is exactly the kind of support ticket that a good tool prevents.
//
//  KID VIEW:
//    Set up the club's office: make the room, put a locked drawer in it for the
//    guest list, and put a blank sheet in the drawer for the naughty list. If
//    the room already has stuff in it, stop and ask before touching anything --
//    we never want to throw away the guest list by accident.
// ============================================================================

use crate::banlist::BanList;
use crate::cli::Options;
use crate::config::ServerConfig;
use crate::error::{OtkpError, Result};
use crate::keyring::Keyring;
use std::path::Path;

/// Run `otkp init`.
///
/// EXPERT: The function is a straight-line sequence of "create this, then that",
///         with the permission setting interleaved at exactly the right moment
///         (immediately after each file is created, before anything else can read
///         it). Straight-line code is the right shape here: there is no branching
///         logic beyond the existence checks, and a reader can verify the
///         ordering by reading top to bottom.
/// KID: Follow the checklist in order: make the room, lock it, make the guest
///      drawer, make the naughty drawer.
pub fn run(options: &Options) -> Result<()> {
    let dir = Path::new(&options.dir);

    // ------------------------------------------------------------------
    // 1. Create the directory (and its parents) with restrictive mode.
    // ------------------------------------------------------------------
    if dir.exists() && !dir.is_dir() {
        return Err(OtkpError::config(format!(
            "'{}' exists but is not a directory",
            dir.display()
        )));
    }

    if !dir.exists() {
        crate::log_info!("creating data directory {}", dir.display());
        // `create_dir_all` makes every missing parent, which is what a user
        // typing `--dir /var/lib/otkp/data` expects.
        std::fs::create_dir_all(dir)
            .map_err(|e| OtkpError::io_err(dir.display().to_string(), e))?;

        // Tighten the directory itself. On Unix only; elsewhere the concept does
        // not apply and the code simply does not compile that branch.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // 0o700 = owner may read/write/traverse; nobody else may do anything.
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(dir, perms)
                .map_err(|e| OtkpError::io_err(dir.display().to_string(), e))?;
        }
    } else {
        crate::log_info!("data directory {} already exists", dir.display());
    }

    // ------------------------------------------------------------------
    // 2. Config file.
    // ------------------------------------------------------------------
    let config_path = dir.join("config.json");
    if config_path.exists() && !options.force {
        crate::log_info!(
            "{} already exists; leaving it alone (use --force to rewrite)",
            config_path.display()
        );
    } else {
        // Build the default server config and validate it before writing. Writing
        // a config we know is invalid would be a nasty surprise later.
        let config = ServerConfig::default();
        config.validate()?;
        write_json(&config_path, &config)?;
        crate::log_info!("wrote {}", config_path.display());
    }

    // ------------------------------------------------------------------
    // 3. Keyring.
    // ------------------------------------------------------------------
    let keyring_path = dir.join("keyring.json");
    if keyring_path.exists() && !options.force {
        crate::log_info!(
            "{} already exists; leaving it alone (use --force to rewrite)",
            keyring_path.display()
        );
    } else if keyring_path.exists() && options.force {
        // Even with `--force` we do NOT wipe a keyring that has users in it,
        // unless the operator is explicit about the consequences. This is a
        // deliberate refusal: losing a keyring means re-enrolling everyone, and
        // an accidental `--force` should not do that silently.
        let existing = Keyring::load(&keyring_path)?;
        if !existing.is_empty() {
            return Err(OtkpError::config(format!(
                "{} already contains {} enrolled user(s); refusing to overwrite. \
                 Delete the file by hand if you really mean to re-enrol everyone.",
                keyring_path.display(),
                existing.len()
            )));
        }
        write_json(&keyring_path, &Keyring::new())?;
        crate::log_info!("re-wrote empty {}", keyring_path.display());
    } else {
        // `Keyring::save` sets 0600 for us; that is why we go through it rather
        // than calling `write_json` directly.
        Keyring::new().save(&keyring_path)?;
        crate::log_info!("wrote {} (chmod 0600)", keyring_path.display());
    }

    // ------------------------------------------------------------------
    // 4. Ban list.
    // ------------------------------------------------------------------
    let banlist_path = dir.join("banlist.json");
    if banlist_path.exists() && !options.force {
        crate::log_info!(
            "{} already exists; leaving it alone",
            banlist_path.display()
        );
    } else {
        // A `BanList` with no path writes nothing on `save()`, so we use
        // `write_json` directly here. The ban list contains no secrets, so the
        // default file permissions are fine.
        write_json(&banlist_path, &BanList::new())?;
        crate::log_info!("wrote {}", banlist_path.display());
    }

    // ------------------------------------------------------------------
    // 5. Report.
    // ------------------------------------------------------------------
    // Printed to stdout (not the log), because this is the command's *output*.
    println!("otkp initialised in {}", dir.display());
    println!();
    println!("Next steps:");
    println!(
        "  1. Enrol a user:   sudo otkp enroll <user> --dir {}",
        dir.display()
    );
    println!(
        "  2. Start safely:   sudo otkp serve --dir {} --firewall dry-run",
        dir.display()
    );
    println!();
    println!("The firewall backend in config.json defaults to \"DryRun\".");
    println!("Nothing will be blocked or opened until you change it.");

    Ok(())
}

/// Serialise a value to pretty JSON and write it.
///
/// EXPERT: A small generic helper. The bound `T: Serialize` is all we need; we do
///         not care what `T` is. `to_vec_pretty` gives a human-readable file,
///         which matters because an operator may need to inspect or hand-edit
///         these files in an emergency -- at 3am, compact JSON is a cruelty.
///
/// Note this helper does NOT set permissions. Callers that write secrets
///         go through `Keyring::save` instead, which does. Keeping the two
///         concerns separate means "does this file get 0600?" is answered by
///         which function you called, not by a flag you might forget.
/// KID: Write the form neatly on paper (not squished into one line).
fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| OtkpError::Json(format!("{}: {e}", path.display())))?;
    std::fs::write(path, json).map_err(|e| OtkpError::io_err(path.display().to_string(), e))?;
    Ok(())
}

/// A helper used by the tests to build an `Options` pointing at a temp dir.
///
/// EXPERT: `#[cfg(test)]` so it does not ship. Integration tests in `tests/`
///         cannot see it (they are a separate crate), so they build `Options`
///         by hand -- which is fine, and arguably better, because it exercises
///         the public shape of the struct.
/// KID: A shortcut for tests.
#[cfg(test)]
pub fn test_options(dir: &str) -> Options {
    Options {
        dir: dir.to_string(),
        ..Options::default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FirewallConfig, PortRange};
    use std::path::PathBuf;

    /// A unique temp directory per test, cleaned up afterwards.
    ///
    /// EXPERT: We build the path from the process id and a per-test name so
    ///         parallel tests cannot collide. `std::env::temp_dir()` respects
    ///         `TMPDIR`, which in this environment points at the agent's scratch
    ///         directory -- exactly what we want.
    /// KID: A private scratch folder for each test.
    fn temp_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("otkp-init-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn init_creates_all_three_files() {
        let dir = temp_dir("creates");
        let opts = test_options(dir.to_str().unwrap());
        run(&opts).unwrap();

        assert!(dir.join("config.json").exists());
        assert!(dir.join("keyring.json").exists());
        assert!(dir.join("banlist.json").exists());

        // The keyring must parse back into an empty keyring.
        let kr = Keyring::load(&dir.join("keyring.json")).unwrap();
        assert!(kr.is_empty());

        // The config must parse and validate.
        let text = std::fs::read_to_string(dir.join("config.json")).unwrap();
        let cfg: ServerConfig = serde_json::from_str(&text).unwrap();
        cfg.validate().unwrap();
        // The safe default backend must survive the round trip.
        assert_eq!(cfg.firewall, FirewallConfig::DryRun);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn init_sets_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let opts = test_options(dir.to_str().unwrap());
        run(&opts).unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "data dir must be 0700");

        let key_mode = std::fs::metadata(dir.join("keyring.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(key_mode & 0o777, 0o600, "keyring must be 0600");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_is_idempotent_without_force() {
        let dir = temp_dir("idempotent");
        let opts = test_options(dir.to_str().unwrap());
        run(&opts).unwrap();
        // Running again must succeed and must not error on existing files.
        run(&opts).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_refuses_to_wipe_a_populated_keyring() {
        let dir = temp_dir("no-wipe");
        let opts = test_options(dir.to_str().unwrap());
        run(&opts).unwrap();

        // Enrol a user directly into the keyring file.
        let mut kr = Keyring::load(&dir.join("keyring.json")).unwrap();
        kr.enroll("alice", 1).unwrap();
        kr.save(&dir.join("keyring.json")).unwrap();

        // Now `init --force` must refuse.
        let mut forced = opts.clone();
        forced.force = true;
        let err = run(&forced).unwrap_err();
        assert!(err.to_string().contains("refusing to overwrite"));

        // And the user must still be there.
        let kr = Keyring::load(&dir.join("keyring.json")).unwrap();
        assert_eq!(kr.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_creates_nested_parent_directories() {
        let dir = temp_dir("nested").join("a").join("b").join("c");
        let opts = test_options(dir.to_str().unwrap());
        run(&opts).unwrap();
        assert!(dir.join("config.json").exists());
        // Clean up from the top of our test tree.
        let top = std::env::temp_dir().join(format!("otkp-init-{}-nested", std::process::id()));
        let _ = std::fs::remove_dir_all(&top);
    }

    #[test]
    fn init_rejects_a_file_where_a_directory_should_be() {
        let path = temp_dir("not-a-dir");
        // Create a *file* at the target path.
        std::fs::write(&path, b"i am a file").unwrap();
        let opts = test_options(path.to_str().unwrap());
        let err = run(&opts).unwrap_err();
        assert!(err.to_string().contains("not a directory"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn default_config_uses_disjoint_ranges() {
        // A regression guard on the default config, since the whole protocol
        // depends on the knock range and the open range not overlapping.
        let cfg = ServerConfig::default();
        assert!(!cfg.knock_range.contains(cfg.open_range.lo));
        assert!(!cfg.open_range.contains(cfg.knock_range.lo));
        // And the ranges must be sane objects.
        assert!(PortRange::new(cfg.knock_range.lo, cfg.knock_range.hi).is_ok());
    }
}
