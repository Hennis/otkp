// ============================================================================
//  src/main.rs  --  the binary: the thinnest possible shell around the library
// ============================================================================
//
//  EXPERT VIEW:
//    This file is deliberately almost empty, and that is a deliberate
//    architectural statement rather than laziness. Everything a program *does*
//    lives in `src/lib.rs` and its modules, where it can be unit-tested, fuzzed,
//    and reused. `main.rs` does the three things that can only happen at the top
//    of a process:
//
//      1. Collect `argv`.
//      2. Call the library's CLI entry point.
//      3. Turn any error into a non-zero exit code and a readable message.
//
//    That is all. If you find yourself wanting to put logic here, the right move
//    is almost always to add a function to the library and call it -- because
//    code in `main.rs` cannot be reached by an integration test.
//
//    The exit-code convention is the standard one, and worth stating: `0` means
//    success, `1` means a runtime error, `2` means a usage error. Scripts and
//    systemd depend on this, so it is a real interface, not a nicety.
//
//  KID VIEW:
//    This is the light switch on the outside of the machine. You flip it, and the
//    machine inside (the library) does all the actual work. If something goes
//    wrong, the switch lights up red (a non-zero exit code) so the person
//    flipping it knows.
// ============================================================================

// Clippy's `doc_overindented_list_items` flags our aligned `EXPERT:`/`KID:`
// comment style (see the note in `src/lib.rs`). Binaries do not inherit the
// library's lint configuration, so we repeat the allows here.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::field_reassign_with_default)]

use std::process::ExitCode;

/// Where the program starts.
///
/// EXPERT: `fn main() -> ExitCode` (rather than the plain `fn main()`) lets us
///         return a real exit status without calling `std::process::exit`, which
///         would skip destructors. That matters here because our secrets are
///         wiped in `Drop`; `process::exit` would bypass the wipe and leave key
///         material in the (soon to be reclaimed) heap. Returning `ExitCode` lets
///         the normal unwinding path run first.
/// KID: The light switch. Flip it, and when the machine finishes it tells you
///      whether everything was fine.
fn main() -> ExitCode {
    // `std::env::args()` yields the program name first, so we `skip(1)`.
    //
    // EXPERT: We deliberately do NOT use `args_os`, because a secret or a host
    //         name that is not valid UTF-8 cannot be meaningfully used by our
    //         protocol anyway (the HMAC input is defined over UTF-8), and the
    //         error message from `args()` on invalid input is clearer than the
    //         lossy conversion we would otherwise need.
    let args = std::env::args().skip(1);

    // Parse. A parse failure is a *usage* error, hence exit code 2.
    let parsed = match otkp::cli::parse(args) {
        Ok(p) => p,
        Err(e) => {
            // `eprintln!` to stderr: errors belong on stderr, not stdout.
            eprintln!("otkp: {e}");
            eprintln!();
            // Point at the help text rather than printing it inline, so the
            // actual error is not buried under a screenful of usage.
            eprintln!("Run `otkp help` for usage.");
            return ExitCode::from(2);
        }
    };

    // Run. A runtime failure is exit code 1.
    match otkp::cli::run(parsed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("otkp: {e}");
            // Walk the error chain, printing each cause. Our `OtkpError`
            // implements `source()`, so a wrapped `io::Error` appears here too.
            // This is why implementing `source()` was worth the four lines.
            let mut cause = std::error::Error::source(&e);
            while let Some(c) = cause {
                eprintln!("  caused by: {c}");
                cause = c.source();
            }
            ExitCode::from(1)
        }
    }
}
