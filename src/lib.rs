// ============================================================================
//  src/lib.rs  --  THE FRONT DOOR of the `otkp` library
// ============================================================================
//
//  EXPERT VIEW:
//    In Rust, a library crate has exactly one root module. This file is it.
//    Its job is NOT to contain logic; its job is to *declare* which modules
//    exist and to *re-export* the handful of names that outside code (our
//    binary, our integration tests) is allowed to depend on.
//
//    Keeping this file thin is deliberate. When you read `lib.rs` you should be
//    able to see the entire shape of the project in ten seconds. That is what
//    "top-down" means in practice: the highest-level file describes the system,
//    and you only descend into a module when you need its detail.
//
//  KID VIEW:
//    This is the cover of a colouring book. It does not colour anything. It
//    just lists the pages inside ("here is the page about secrets, here is the
//    page about firewalls") so you can flip straight to the one you want.
//
//  WHY A LIBRARY *AND* A BINARY?
//    - src/lib.rs  -> the engine, testable in isolation with `cargo test`.
//    - src/main.rs -> a 30-line shell that parses argv and calls the engine.
//    Integration tests in tests/ can only `use` a *library*, never a binary.
//    So all interesting code must live here, behind `pub`, to be testable.
// ============================================================================

// `#![...]` at the top of the crate root applies attributes to the WHOLE crate.
// `#![deny(unsafe_code)]` forbids `unsafe` blocks everywhere in this crate
// *unless* a module explicitly re-enables them with `#[allow(unsafe_code)]`.
// That is the important distinction from `#![forbid(unsafe_code)]`: `forbid` is
// absolute and cannot be overridden by any inner `allow`, which would make it
// impossible to write the one module that genuinely needs raw syscalls.
//
// We need exactly one such module: `net::raw`, which uses `libc` to open an
// `AF_PACKET` socket so the daemon can see packets addressed to *closed* ports
// (the whole point of port knocking). With `deny` here and a single documented
// `allow` there, the answer to "is there memory-unsafety in otkp?" is a one-line
// grep: it is confined to `src/net.rs`, in functions that never dereference a
// pointer without a length check.
#![deny(unsafe_code)]
// `#![deny(missing_docs)]` would force every public item to have a doc comment.
// We keep it as a warning instead, so a missing doc is noisy but not fatal.
#![warn(missing_docs)]
// Clippy's `doc_overindented_list_items` fires on our `EXPERT:` / `KID:`
// comment style: clippy treats `EXPERT:` as a markdown list marker and then
// objects that the continuation lines are indented to line up with the prose
// rather than by the three spaces markdown expects. Aligning the continuations
// *is* the point -- it is what makes the two voices scannable -- so we disable
// the lint deliberately, with this note as the reason. It is a formatting
// preference, not a correctness issue.
#![allow(clippy::doc_overindented_list_items)]
// Clippy's `field_reassign_with_default` suggests `Struct { field: ..,
// ..Default::default() }` instead of `let mut x = Default::default(); x.field =
// ..`. We use the latter form in tests and fixtures because a sequence of
// assignments lets each line carry its own explanatory comment, which the struct
// literal form cannot. Disabled deliberately; it is a readability preference.
#![allow(clippy::field_reassign_with_default)]
// ---------------------------------------------------------------------------
// 1. CRATE-LEVEL DOCUMENTATION
// ---------------------------------------------------------------------------
// `//!` (inner doc comments) document the item they are *inside* -- here, the
// whole crate. `cargo doc` turns this into the library's front page.
//! # otkp — One Time Knock Protocol
//!
//! `otkp` fuses two well-known security ideas:
//!
//! 1. **One-Time Passwords** (HOTP/TOTP, the thing in your authenticator app):
//!    a shared secret plus the clock yields a value that changes every window
//!    and can never be reused.
//! 2. **Port knocking** (as popularised by `knockd`): a daemon silently watches
//!    for a specific *sequence* of connection attempts and only then opens a
//!    firewall hole.
//!
//! In `otkp` the one-time value is not a six-digit number but a **one-time
//! sequence of port numbers**, plus the **one-time port that sequence unlocks**.
//! Nothing is listening by default; a single wrong knock bans the source IP.
//!
//! ## Reading order (top-down)
//!
//! 1. [`config`]  — what the operator chooses (ranges, timings, backend).
//! 2. [`secret`]  — the per-user key and its textual encodings.
//! 3. [`crypto`]  — how secret + clock become a [`crypto::KnockSpec`].
//! 4. [`engine`]  — the state machine that decides allow / wait / ban.
//! 5. [`firewall`] — how an allow becomes a real firewall rule.
//! 6. [`net`]     — how packets are observed and sent.
//! 7. [`daemon`]  — the loop that wires all of the above together.
//!
//! ## Example
//!
//! ```
//! use otkp::{config::ServerConfig, crypto, secret::MasterSecret};
//!
//! // A fixed secret and a fixed clock make the whole thing deterministic,
//! // which is exactly what you want in a doctest.
//! let secret = MasterSecret::from_bytes([7u8; 32]);
//! let cfg = ServerConfig::default();
//! let spec = crypto::derive_knock_spec(&secret, "alice", 1234, &cfg, None);
//!
//! // The sequence length is always inside the configured bounds...
//! assert!(spec.knock_ports.len() >= cfg.knock_count_min as usize);
//! assert!(spec.knock_ports.len() <= cfg.knock_count_max as usize);
//! // ...every knock port is inside the knock range...
//! assert!(spec.knock_ports.iter().all(|p| cfg.knock_range.contains(*p)));
//! // ...and the port we will open is inside the open range.
//! assert!(cfg.open_range.contains(spec.open_port));
//! ```

// ---------------------------------------------------------------------------
// 2. MODULE DECLARATIONS
// ---------------------------------------------------------------------------
// `pub mod x;` means "compile src/x.rs (or src/x/mod.rs) and make it visible to
// the outside world". Without `pub`, the module would be private to the crate.
//
// The order below is the top-down reading order from the docs above. It is a
// convention only -- Rust does not care about declaration order -- but it means
// a human can read this list and understand the architecture.

/// The structured audit stream, for security level 2.
pub mod audit; //    the machine-readable event stream
/// Who currently has a port open, and until when.
pub mod auth; //    who currently has a port open, until when
/// Who is currently banned, and until when.
pub mod banlist; //    who is currently banned
/// Argument parsing and subcommand dispatch.
pub mod cli;
/// What the operator chooses: ranges, timings, ban policy, firewall backend.
pub mod config; // 1. what the operator configured
/// Derivation: secret + clock -> a one-time knock sequence.
pub mod crypto; // 3. secret + clock -> knock sequence
/// The loop that wires the source, engine and firewall together.
pub mod daemon; // 7. the loop that wires everything together
/// The per-IP knock state machine (the heart of the project).
pub mod engine; // 4. the state machine (the heart of the project)
/// The one error type used across the library.
pub mod error; //    the one error type used across the library
/// Turning decisions into real firewall rules.
pub mod firewall; // 5. turning decisions into real rules
/// Who is enrolled, and the secret each of them holds.
pub mod keyring; //    who is enrolled, and their secrets
/// A tiny dependency-free logger.
pub mod logging; //    a tiny dependency-free logger
/// Observing and sending knocks over the network.
pub mod net; // 6. observing and sending knocks
/// The key material: a zeroising 32-byte secret and its text encodings.
pub mod secret; // 2. the key material //    argument parsing and subcommand dispatch

// ---------------------------------------------------------------------------
// 3. RE-EXPORTS (the public API surface)
// ---------------------------------------------------------------------------
// `pub use` creates a *shortcut*: after this, outside code can write
// `otkp::Engine` instead of `otkp::engine::Engine`.
//
// EXPERT: This is the "facade" pattern. You expose a curated set of names and
//         keep the rest reachable but not front-and-centre. If you later move
//         `Engine` to another module, callers using `otkp::Engine` never notice.
// KID:    Instead of saying "the red box, second shelf, third drawer", we put
//         the things you use most on the kitchen counter where you can grab them.
pub use config::{ClientConfig, FirewallConfig, ServerConfig};
pub use crypto::KnockSpec;
pub use engine::{Engine, KnockEvent, Outcome};
pub use error::{OtkpError, Result};
pub use secret::MasterSecret;

/// The protocol label embedded in every HMAC input.
///
/// EXPERT: This is *domain separation*. If we ever change how the sequence is
///         derived, we bump this string to `"otkp-knock-v2"`. Old clients then
///         derive different (wrong) sequences against a new server, which fails
///         loudly and immediately instead of silently mis-authenticating.
///         Never reuse a label with different semantics.
/// KID: It is the name of the game written on the box. If we change the rules
///      of the game, we give it a new name, so nobody mixes up the old rules.
pub const PROTOCOL_LABEL: &[u8] = b"otkp-knock-v1";

/// The protocol label used when the sequence is bound to the source address.
///
/// EXPERT: A *distinct* label for the source-bound variant, for exactly the
///         domain-separation reason given above. The two derivations differ, so
///         they must not share a label -- otherwise "the same label" would map to
///         two different wire formats depending on configuration, which is the
///         ambiguity the label exists to prevent. A client and server that
///         disagree about binding mode then derive different sequences and fail
///         loudly, which is what we want.
/// KID: A second name for the second version of the game.
pub const PROTOCOL_LABEL_IPBOUND: &[u8] = b"otkp-knock-v1-ipbind";

/// The default number of seconds in one time window.
///
/// EXPERT: 30 s matches the TOTP convention and is short enough that a sniffed
///         sequence is stale quickly, while long enough that ordinary clock
///         drift (tens of seconds) does not lock people out. We additionally
///         tolerate ±1 step in the engine, so the effective window is ~90 s.
/// KID: Every 30 seconds the secret handshake changes to a new one. You have to
///      knock with the *current* handshake, like a password that expires.
pub const DEFAULT_STEP_SECONDS: u64 = 30;
