// ============================================================================
//  src/logging.rs  --  a tiny, dependency-free logger
// ============================================================================
//
//  EXPERT VIEW:
//    Real projects use `tracing` or `log` + `env_logger`. Those are excellent,
//    but they are also two more crates in the dependency graph of a program that
//    runs as root and touches the firewall. Every dependency is attack surface,
//    so for v0.1.0 we hand-roll ~80 lines that do exactly what we need:
//      * four levels (Error, Warn, Info, Debug),
//      * an RFC-3339-ish UTC timestamp,
//      * a global verbosity that can be raised by `--verbose`,
//      * output to stderr, so it never pollutes machine-readable stdout.
//
//    The one subtlety worth understanding is the global verbosity. Rust's
//    default is to forbid mutable global state (`static mut` is unsafe). We use
//    an `AtomicU8`: a byte that can be read and written from any thread without
//    a lock, because the CPU guarantees the read-modify-write is indivisible.
//    That is exactly the right tool for "a log level every thread reads".
//
//  KID VIEW:
//    This is the machine that writes notes in a diary about what the program is
//    doing, each note stamped with the time. `--verbose` is the dial that makes
//    it write *lots* of notes instead of only important ones.
//
//  WHY stderr AND NOT stdout?
//    `otkp verify` prints a machine-parseable sequence to stdout. If logs went
//    to stdout too, you could not pipe the output into another program without
//    the logs getting mixed in. Logs go to stderr; data goes to stdout. Always.
// ============================================================================

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Level
// ---------------------------------------------------------------------------
/// How loud a log line is. Lower numbers are more important.
///
/// EXPERT: We use `#[repr(u8)]` so the enum has a defined in-memory layout as a
///         byte, which lets us store it in an `AtomicU8` without a conversion
///         dance. The explicit discriminants double as the threshold values.
/// KID: A ladder. "Error" is at the bottom (we always shout about it). "Debug"
///      is at the top (we only mention it when you ask for everything).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Something failed. Always printed.
    Error = 0,
    /// Something is suspicious but we carried on. Printed unless quiet.
    Warn = 1,
    /// Normal operation. The default level.
    Info = 2,
    /// Verbose diagnostics, including every observed packet.
    Debug = 3,
}

impl Level {
    /// The short uppercase tag that appears in each line, e.g. `INFO`.
    ///
    /// EXPERT: A tiny method like this keeps the tag in one place. If we ever
    ///         want `WARNING` instead of `WARN`, it is a one-line change.
    /// KID: The label we write next to each note.
    pub fn tag(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
        }
    }

    /// Convert a byte back into a `Level`, saturating at `Debug`.
    ///
    /// EXPERT: Needed because the atomic stores a raw `u8`. `unwrap_or` avoids a
    ///         panic on a value we did not write ourselves.
    /// KID: Turning the dial's number back into a word.
    fn from_u8(v: u8) -> Level {
        match v {
            0 => Level::Error,
            1 => Level::Warn,
            2 => Level::Info,
            _ => Level::Debug,
        }
    }
}

// ---------------------------------------------------------------------------
// Global verbosity
// ---------------------------------------------------------------------------
// `static` = one instance for the whole program (no `let` needed).
// `AtomicU8::new(2)` starts us at `Level::Info` (= 2).
// `Ordering::Relaxed` is the cheapest memory ordering. It is correct here
// because we only need *eventual* visibility of a log level; we are not using
// it to synchronise access to any other data.
static VERBOSITY: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Set the maximum level that will be printed.
///
/// EXPERT: Called once at startup from the CLI. `store(.., Relaxed)` is a single
///         atomic write; any thread that logs later will observe it.
/// KID: Turn the diary dial.
pub fn set_verbosity(level: Level) {
    VERBOSITY.store(level as u8, Ordering::Relaxed);
}

/// Read the current maximum level.
///
/// EXPERT: `load(.., Relaxed)` is a single atomic read -- no lock, no blocking,
///         which matters because this is called on every single packet.
/// KID: Peek at the dial.
pub fn verbosity() -> Level {
    Level::from_u8(VERBOSITY.load(Ordering::Relaxed))
}

/// Is a message at `level` currently loud enough to print?
///
/// EXPERT: We compare the numeric discriminants via the derived `Ord`. Keeping
///         this as its own function means `debug!` can bail out *before*
///         formatting anything, which is the whole performance argument for
///         lazy logging.
/// KID: "Is this note important enough for the current dial setting?"
pub fn enabled(level: Level) -> bool {
    level <= verbosity()
}

// ---------------------------------------------------------------------------
// The core emit function
// ---------------------------------------------------------------------------
/// Write one log line to stderr, if `level` is enabled.
///
/// EXPERT: `&str` for the message means the *caller* does the formatting, which
///         is why the macros below guard with `enabled(..)` first: formatting a
///         debug string for a packet we are about to discard would be wasteful.
///         We deliberately ignore write errors: if stderr is closed, there is
///         nowhere to report that fact, and we must not crash a security daemon
///         over a logging failure.
/// KID: The actual pen touching the paper.
pub fn log(level: Level, msg: &str) {
    if !enabled(level) {
        return;
    }
    // `eprintln!` writes to stderr and appends a newline, unlike `print!`.
    eprintln!("{} [{}] {}", timestamp(), level.tag(), msg);
}

/// A UTC timestamp like `2026-10-05T14:09:00Z`.
///
/// EXPERT: We avoid the `chrono`/`time` crates by implementing the civil-date
///         conversion ourselves. The algorithm below (Howard Hinnant's
///         `civil_from_days`) is the standard, well-known way to turn a day
///         count into year/month/day without lookup tables. Writing it out is
///         also a nice reminder that "date formatting" is just integer maths.
/// KID: The clock stamp in the corner of the diary page.
pub fn timestamp() -> String {
    // `SystemTime::now()` is the wall clock. `duration_since(UNIX_EPOCH)` gives
    // the time since 1970-01-01. It fails only if the clock is set before 1970.
    let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        // Before the epoch: print a clearly-bogus marker rather than panicking.
        Err(_) => return "1970-01-01T00:00:00Z".to_string(),
    };

    // Break the Unix seconds into calendar pieces. All integer maths.
    let days = (secs / 86_400) as i64; // whole days since 1970-01-01
    let secs_of_day = secs % 86_400; // seconds elapsed today (UTC)
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let (year, month, day) = civil_from_days(days);

    // `{:04}` = pad with zeros to width 4. `{:02}` = width 2.
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert "days since 1970-01-01" into `(year, month, day)`.
///
/// EXPERT: This is Howard Hinnant's `civil_from_days`, shifted so the era starts
///         on 0000-03-01. The shift makes leap years fall at the *end* of the
///         era, which removes all special-casing from the maths. It is exact for
///         the whole proleptic Gregorian calendar. See the "chrono-Compatible
///         Low-Level Date Algorithms" paper.
/// KID: A magic but correct way to turn "how many days have passed" into "it is
///      the 5th of October, 2026". We do not need to understand every step; we
///      just need to know it is the standard recipe and that our tests check it.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift the epoch so that day 0 is 0000-03-01.
    let z = z + 719_468;
    // `div_euclid` is floor division that behaves for negatives (unlike `/`).
    let era = z.div_euclid(146_097); // 400-year eras
    let doe = z.rem_euclid(146_097); // day of era, 0..=146096
                                     // Year of era, counting leap-day placement correctly.
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, 0-based
    let mp = (5 * doy + 2) / 153; // month, shifted (0 = March)
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    // If the shifted month wrapped past December, the year advances by one.
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------------
// EXPERT: `macro_rules!` is Rust's declarative macro system: textual patterns
//         expanded at compile time. `$($arg:tt)*` captures "the rest of the
//         arguments as a token stream", which we forward to `format!`. This
//         gives us `info!("user {} knocked port {}", u, p)` with zero runtime
//         cost when the level is disabled -- the `if` runs first.
//
//         `#[macro_export]` puts the macro at the crate root, so it is used as
//         `otkp::info!(..)` or, after `use otkp::info;`, as `info!(..)`.
// KID: Little shouty words that print a note with a label already attached.

/// Log at [`Level::Error`].
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        if $crate::logging::enabled($crate::logging::Level::Error) {
            $crate::logging::log($crate::logging::Level::Error, &format!($($arg)*));
        }
    }};
}

/// Log at [`Level::Warn`].
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        if $crate::logging::enabled($crate::logging::Level::Warn) {
            $crate::logging::log($crate::logging::Level::Warn, &format!($($arg)*));
        }
    }};
}

/// Log at [`Level::Info`].
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        if $crate::logging::enabled($crate::logging::Level::Info) {
            $crate::logging::log($crate::logging::Level::Info, &format!($($arg)*));
        }
    }};
}

/// Log at [`Level::Debug`].
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        if $crate::logging::enabled($crate::logging::Level::Debug) {
            $crate::logging::log($crate::logging::Level::Debug, &format!($($arg)*));
        }
    }};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_1970() {
        // 0 days after the epoch must be 1970-01-01.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn known_dates_round_trip() {
        // 2000-03-01 is 11017 days after 1970-01-01 (verified by hand and by
        // any date calculator).
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        // The day after a leap day in a leap year:
        // 2024-03-01 is 19783 days after 1970-01-01.
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
        // And the leap day itself: 2024-02-29 is 19782.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn verbosity_gate_works() {
        // Save and restore so this test cannot affect others (tests run in
        // parallel threads by default).
        let saved = verbosity();
        set_verbosity(Level::Warn);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Warn));
        assert!(!enabled(Level::Info));
        assert!(!enabled(Level::Debug));
        set_verbosity(saved);
    }

    #[test]
    fn timestamp_looks_like_rfc3339() {
        let t = timestamp();
        // Cheap structural check: 20 chars, 'T' at index 10, 'Z' at the end.
        assert_eq!(t.len(), 20, "got {t}");
        assert_eq!(&t[10..11], "T");
        assert!(t.ends_with('Z'));
    }
}
