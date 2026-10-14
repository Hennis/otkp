// ============================================================================
//  decoy/src/lib.rs  --  the deception layer's front door
// ============================================================================
//
//  EXPERT VIEW:
//    This crate implements **rung 1 of the deception ratchet** (see
//    `docs/DESIGN-deception-layer.md` §7): banner decoys placed inside the
//    authenticated perimeter, where any interaction is anomalous by definition.
//
//    The design rests on one principle, and it is worth restating here because
//    it is the thing an earlier draft of the note got wrong:
//
//      **Detection does not depend on the attacker believing the bait.**
//
//    The decoy has no legitimate use. So any interaction with it — reading a
//    banner, opening a connection, sending bytes — is signal. A smarter attacker
//    spots the decoy faster and trips it sooner. The signal comes from the
//    probe, not from the belief.
//
//    Two consequences shape the code:
//
//      1. **The decoy never reacts in-band.** It serves its banner and nothing
//         else. No error, no delay, no disconnect that would tell the attacker
//         they have been detected. Detection is recorded out of band; the
//         attacker's experience is indistinguishable from a real service that
//         ignores them.
//      2. **The response is credential-scoped, never address-scoped.** This is
//         the opposite of the knock layer's behaviour, and deliberately so. A
//         knock failure happens before authentication, so an address is all you
//         have. A decoy trip happens *after* authentication, so a credential is
//         exactly what you have — and an attacker riding a stolen session is at
//         a legitimate address. Banning the address would punish the victim.
//
//    What this crate does NOT do, by design: exploit anyone, retaliate, serve
//    real vulnerable software, or take any autonomous corrective action. It
//    observes and it records. A separate responder decides what happens next.
//
//  KID VIEW:
//    We put a few fake doors inside the building, in places the real staff never
//    go. They look like doors that a burglar would want to try. Nobody real ever
//    touches them — so if anyone touches one, we know. We do not fight the
//    burglar. We just quietly write down who they were and tell the person whose
//    key they used.
// ============================================================================

// Same lint posture as the main crate: no `unsafe` anywhere, and docs on
// everything public. This crate has no `unsafe` at all, so the grep answer is
// trivially "none".
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::field_reassign_with_default)]

//! # otkp-decoy — the deception layer
//!
//! Banner decoys inside the authenticated perimeter. Any interaction is signal.
//!
//! ## Reading order (top-down)
//!
//! 1. [`banner`] — the catalogue of decoys and the inert banner strings they serve.
//! 2. [`trip`]   — what was observed, how it is classified, and the graduated
//!    response. **This is the design; the rest is plumbing.**
//! 3. [`audit`]  — the structured trip stream.
//! 4. [`listener`] — the TCP listener that serves banners and never reacts.
//!
//! ## The one rule
//!
//! Every response this crate produces is **credential-scoped**. There is no API
//! that revokes an address, and that is intentional: an address is not what a
//! decoy trip tells you about.
//!
//! ## Example
//!
//! ```
//! use otkp_decoy::trip::{classify, Interaction, Response, Trip};
//!
//! // Someone connected, read the banner, and sent nothing.
//! let seen = Interaction::probe("ssh-old", "203.0.113.9".parse().unwrap())
//!     .with_credential("alice")
//!     .at(1_700_000_000);
//!
//! let trip = classify(&seen);
//! assert!(matches!(trip, Trip::Probe { .. }));
//! assert_eq!(Response::for_trip(&trip), Response::RejectAndWarn);
//! ```

/// The structured trip stream (JSON Lines).
pub mod audit;
/// The decoy catalogue and the inert banner strings.
pub mod banner;
/// The crate's error type.
pub mod error;
/// The TCP listener that serves banners and never reacts.
pub mod listener;
/// Classification and the graduated, credential-scoped response. **The design.**
pub mod trip;

// ---------------------------------------------------------------------------
// Re-exports: the curated surface
// ---------------------------------------------------------------------------
pub use banner::{Decoy, DECOYS};
pub use error::{Error, Result};
pub use trip::{classify, Interaction, Response, Trip};
