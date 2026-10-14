// ============================================================================
//  decoy/src/error.rs  --  the crate's error type
// ============================================================================
//
//  EXPERT VIEW:
//    Much smaller than the main project's error enum, because this crate does
//    much less: it writes files and it opens sockets. Two variants would almost
//    do; the third exists because configuration parsing is the other thing that
//    can fail.
//
//    Kept separate from `otkp::OtkpError` on purpose. Sharing the error type
//    would mean sharing a dependency, and the design note requires these two
//    crates to be independent — a shared error type is the first thread of a
//    shared blast radius.
//
//  KID VIEW:
//    The short list of things that can go wrong here.
// ============================================================================

use std::fmt;
use std::io;

/// The things that can go wrong in the decoy layer.
#[derive(Debug)]
pub enum Error {
    /// A file could not be read or written, with the path that failed.
    Io {
        /// The path involved.
        path: String,
        /// The underlying operating-system error.
        source: io::Error,
    },
    /// JSON (de)serialisation failed.
    Json(String),
    /// A socket operation failed.
    Net(String),
    /// The operator asked for something that does not make sense.
    Config(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "i/o error on '{path}': {source}"),
            Error::Json(msg) => write!(f, "json error: {msg}"),
            Error::Net(msg) => write!(f, "network error: {msg}"),
            Error::Config(msg) => write!(f, "configuration error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    /// Build an I/O error that remembers the path.
    pub fn io(path: impl Into<String>, source: io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }

    /// Build a network error.
    pub fn net(msg: impl Into<String>) -> Self {
        Error::Net(msg.into())
    }

    /// Build a configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Error::Io {
            path: "<unknown>".to_string(),
            source,
        }
    }
}

/// `Result<T>` is shorthand for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_readable() {
        assert_eq!(
            Error::config("no decoys").to_string(),
            "configuration error: no decoys"
        );
    }

    #[test]
    fn io_error_remembers_the_path() {
        let e = Error::io("/tmp/x.jsonl", io::Error::other("nope"));
        let s = e.to_string();
        assert!(s.contains("/tmp/x.jsonl"));
        assert!(s.contains("nope"));
    }

    #[test]
    fn question_mark_conversion_works() {
        fn fails() -> io::Result<()> {
            Err(io::Error::other("boom"))
        }
        fn uses_it() -> Result<()> {
            fails()?;
            Ok(())
        }
        assert!(uses_it().is_err());
    }
}
