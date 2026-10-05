// ============================================================================
//  src/error.rs  --  ONE error type for the whole library
// ============================================================================
//
//  EXPERT VIEW:
//    Rust has no exceptions. A fallible function returns `Result<T, E>`. The
//    question every project must answer is "what is E?".
//
//    Two schools:
//      * `Box<dyn Error>` / `anyhow::Error` -- great for *applications*, where
//        you just want to print a nice message and exit. Erases the type.
//      * A concrete `enum` -- great for *libraries*, where callers may want to
//        `match` on the failure and react differently. Preserves the type.
//
//    `otkp` is a library, so we define a concrete enum. The binary layer wraps
//    it in `anyhow` only at the very top, purely for pretty printing.
//
//  KID VIEW:
//    When something goes wrong, we want to say *exactly what* went wrong, not
//    just "it broke". This file is the official list of all the ways things can
//    break, so every part of the program describes trouble in the same words.
//
//  WHY AN ENUM?
//    An enum is a type whose value is exactly one of a fixed list of variants.
//    `match`ing on it is *exhaustive*: if we add a variant later, the compiler
//    points at every place that forgot to handle it. That is a maintenance
//    superpower you do not get with string error messages.
// ============================================================================

use std::fmt; // `fmt` gives us the `Display` and `Debug` traits, used for printing.
use std::io; // `io` gives us `io::Error`, which we wrap for I/O failures.

/// The single error type returned by every fallible function in this library.
///
/// EXPERT: Every variant is a *struct-like* or *tuple-like* enum variant so it
///         can carry context (which file, which port, ...). Carrying context at
///         the point of failure beats reconstructing it later from a stack trace.
/// KID: Each item in this list is a different kind of oops, and each one carries
///      a little note about *where* the oops happened.
#[derive(Debug)] // `Debug` lets us print the error with `{:?}` -- needed by Result.
pub enum OtkpError {
    /// A file we needed could not be read or written.
    ///
    /// The `String` is the path, so the message says *which* file, not just
    /// "permission denied".
    Io {
        /// The path we were working with when the I/O failed.
        path: String,
        /// The underlying operating-system error.
        source: io::Error,
    },

    /// A configuration file (or value) was missing, malformed, or nonsensical.
    ///
    /// EXPERT: Config errors deserve their own variant because the operator can
    ///         *fix* them. A security library should be able to say "your port
    ///         range is empty" rather than "invalid input".
    /// KID: The settings sheet was filled in wrong -- maybe a range where the
    ///      small number is bigger than the big number.
    Config(String),

    /// JSON (de)serialisation failed for the keyring, config or ban list.
    Json(String),

    /// A secret, base32 string, hex string or enrolment URI could not be parsed.
    ///
    /// EXPERT: We keep this distinct from `Config` because it usually means the
    ///         *user* mistyped their secret, not that the operator misconfigured
    ///         the daemon. Different audience, different message.
    /// KID: The secret handshake you typed in has a typo in it.
    Secret(String),

    /// A network operation failed (bind, send, recv, raw socket setup).
    Net(String),

    /// The firewall backend refused or failed to apply a rule.
    Firewall(String),

    /// The user asked for something that does not exist or makes no sense.
    ///
    /// e.g. `--user bob` when bob was never enrolled.
    NotFound(String),

    /// A cryptographic primitive returned an error (wrong key length, etc).
    ///
    /// EXPERT: In practice HMAC-SHA256 accepts any key length, so this variant
    ///         should be unreachable. We keep it so we never have to `unwrap()`
    ///         in crypto code -- `unwrap` in a security path is how panics become
    ///         denial-of-service.
    /// KID: The maths machine said "I cannot do that". (Should never happen, but
    ///      we would rather hear it than crash.)
    Crypto(String),

    /// The clock is unusable (e.g. system time is before the Unix epoch).
    Clock(String),
}

// ---------------------------------------------------------------------------
//  Display: the *human-readable* form, used by `println!("{}", err)`
// ---------------------------------------------------------------------------
// EXPERT: `Display` is for users, `Debug` is for programmers. We implement both.
//         The compiler gives us `Debug` for free via `#[derive(Debug)]` above,
//         but `Display` must be written by hand because only you know the right
//         wording.
// KID: This is how we turn the error into a sentence a person can read.
impl fmt::Display for OtkpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A `match` on `self`. Each arm names a variant and *destructures* the
        // data inside it, binding the inner values to fresh local names.
        // `&mut f` is a *mutable reference* to the formatter -- we write into it.
        match self {
            // `{path}` and `{source}` are "inline format args": they capture the
            // local variables of the same name. (Rust 2021 feature.)
            OtkpError::Io { path, source } => {
                write!(f, "i/o error on '{path}': {source}")
            }
            OtkpError::Config(msg) => write!(f, "configuration error: {msg}"),
            OtkpError::Json(msg) => write!(f, "json error: {msg}"),
            OtkpError::Secret(msg) => write!(f, "secret error: {msg}"),
            OtkpError::Net(msg) => write!(f, "network error: {msg}"),
            OtkpError::Firewall(msg) => write!(f, "firewall error: {msg}"),
            OtkpError::NotFound(msg) => write!(f, "not found: {msg}"),
            OtkpError::Crypto(msg) => write!(f, "crypto error: {msg}"),
            OtkpError::Clock(msg) => write!(f, "clock error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// std::error::Error: makes our type play nicely with the wider ecosystem
// ---------------------------------------------------------------------------
// EXPERT: Implementing this trait means `Box<dyn Error>` and `anyhow` can wrap
//         our error, and `?` works when converting *into* it. We also implement
//         `source()` so error-chain printers can show the underlying io::Error.
// KID: This makes our error a "real" Rust error that other libraries know how
//      to hold and pass around.
impl std::error::Error for OtkpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // For the I/O variant we hand back the OS error as the "cause".
            OtkpError::Io { source, .. } => Some(source),
            // Everything else has no deeper cause.
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// From<io::Error>: lets us write `?` on I/O calls
// ---------------------------------------------------------------------------
// EXPERT: The `?` operator on a `Result<T, io::Error>` inside a function
//         returning `Result<T, OtkpError>` requires a conversion. Rust's std
//         trait `From` provides it. We cannot build the nice `path` field here
//         because we do not know it, so we use "<unknown>"; callers that *do*
//         know the path use the `io_err(path)` helper below instead.
// KID: This is the translator that turns an operating-system grumble into our
//      own kind of grumble automatically.
impl From<io::Error> for OtkpError {
    fn from(source: io::Error) -> Self {
        OtkpError::Io {
            path: "<unknown>".to_string(),
            source,
        }
    }
}

// ---------------------------------------------------------------------------
// From<serde_json::Error>: same trick, for JSON
// ---------------------------------------------------------------------------
// KID: And this is the translator for "the text file was not valid JSON".
impl From<serde_json::Error> for OtkpError {
    fn from(e: serde_json::Error) -> Self {
        OtkpError::Json(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Result<T>: our project-wide alias
// ---------------------------------------------------------------------------
/// `Result<T>` is shorthand for `Result<T, OtkpError>`.
///
/// EXPERT: A type alias like this is one of the highest-value lines in a
///         codebase: every signature becomes `-> Result<()>` instead of
///         `-> Result<(), OtkpError>`, and the error type can change once,
///         here, without touching a hundred functions.
/// KID: Everywhere we say "Result", we secretly mean "Result or our oops list".
pub type Result<T> = std::result::Result<T, OtkpError>;

// ---------------------------------------------------------------------------
// Small constructor helpers
// ---------------------------------------------------------------------------
// EXPERT: Named constructors (`io_err(path, e)`) are more readable than struct
//         literals at call sites, and they keep the variant's shape private-ish.
// KID: Little machines that build a specific kind of oops, already filled in.
impl OtkpError {
    /// Build an [`OtkpError::Io`] that remembers *which file* failed.
    ///
    /// EXPERT: This is why we do not rely on the blanket `From<io::Error>`: a
    ///         path in the message turns "Permission denied" into
    ///         "i/o error on '/etc/otkp/keyring.json': Permission denied",
    ///         which is the difference between a 5-second fix and a 5-hour one.
    /// KID: "The door would not open" is worse than "the *kitchen* door would
    ///      not open". This helper remembers to say which door.
    pub fn io_err(path: impl Into<String>, source: io::Error) -> Self {
        OtkpError::Io {
            path: path.into(),
            source,
        }
    }

    /// Build an [`OtkpError::Config`].
    ///
    /// EXPERT: `impl Into<String>` accepts `&str`, `String`, ... so callers can
    ///         pass a literal or an owned string without thinking about it.
    /// KID: Same idea: a helper that makes a settings-mistake oops.
    pub fn config(msg: impl Into<String>) -> Self {
        OtkpError::Config(msg.into())
    }

    /// Build an [`OtkpError::NotFound`].
    pub fn not_found(msg: impl Into<String>) -> Self {
        OtkpError::NotFound(msg.into())
    }

    /// Build an [`OtkpError::Net`].
    pub fn net(msg: impl Into<String>) -> Self {
        OtkpError::Net(msg.into())
    }

    /// Build an [`OtkpError::Firewall`].
    pub fn firewall(msg: impl Into<String>) -> Self {
        OtkpError::Firewall(msg.into())
    }

    /// Build an [`OtkpError::Secret`].
    pub fn secret(msg: impl Into<String>) -> Self {
        OtkpError::Secret(msg.into())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// `#[cfg(test)]` means "compile this module only when running tests". That keeps
// test code out of the shipped binary entirely.
// `mod tests` is the conventional name; `use super::*` imports everything from
// the enclosing module so the tests can name `OtkpError` directly.
#[cfg(test)]
mod tests {
    use super::*;

    #[test] // `#[test]` marks a function as a test; `cargo test` runs it.
    fn display_is_human_readable() {
        let e = OtkpError::config("knock range is empty");
        // `to_string()` uses our `Display` impl.
        assert_eq!(e.to_string(), "configuration error: knock range is empty");
    }

    #[test]
    fn io_error_remembers_the_path() {
        let io = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        let e = OtkpError::io_err("/etc/otkp/keyring.json", io);
        let text = e.to_string();
        // `contains` keeps the assertion robust if we tweak wording later.
        assert!(text.contains("/etc/otkp/keyring.json"));
        // The underlying message must survive into the display string. (Note
        // that `io::Error::new` uses the message we gave it, not the kind's
        // default description -- so we assert on "nope".)
        assert!(text.contains("nope"));
    }

    #[test]
    fn question_mark_conversion_works() {
        // A helper that returns io::Error, to prove `From` + `?` line up.
        fn fails() -> io::Result<()> {
            Err(io::Error::other("boom"))
        }
        // A helper returning our Result, using `?` on the io::Result above.
        fn uses_question_mark() -> Result<()> {
            fails()?; // `?` converts io::Error -> OtkpError via our From impl.
            Ok(())
        }
        assert!(uses_question_mark().is_err());
    }
}
