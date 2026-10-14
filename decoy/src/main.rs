// ============================================================================
//  decoy/src/main.rs  --  the decoy daemon
// ============================================================================
//
//  EXPERT VIEW:
//    A thin shell, same discipline as the main project's binary: parse argv,
//    wire the pieces, run, and turn errors into exit codes. Everything
//    interesting is in the library where it can be tested.
//
//    What this binary does, in order:
//
//      1. Bind every decoy in the catalogue, up front. If any bind fails we exit
//         rather than running partially — a detection mechanism that silently
//         covers half its surface is worse than one that refuses to start,
//         because the operator believes they are covered.
//      2. Spawn one accept thread per decoy.
//      3. Classify each observation and append it to the trip stream.
//      4. Never act on a verdict. The response is *recorded*; a separate
//         responder enforces it. See the design note §5.4.
//
//    There is deliberately no `--enforce` flag. This binary cannot revoke
//    anything, by construction, and that is the point: a component that both
//    detects and acts is a component whose compromise both blinds you and
//    revokes your users.
//
//  KID VIEW:
//    The night watchman. He opens every pretend door, stands behind each one,
//    writes down who touched it, and tells the day staff. He does not chase
//    anyone and he does not take anyone's key — that is somebody else's job.
// ============================================================================

#![deny(unsafe_code)]
#![allow(clippy::doc_overindented_list_items)]

use otkp_decoy::audit::{TripEvent, TripLog};
use otkp_decoy::listener::{self, Sink};
use otkp_decoy::trip::{classify, Interaction};
use otkp_decoy::{Decoy, Error, Result};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Parsed command line.
struct Args {
    /// Which interface to bind the decoys on.
    ///
    /// EXPERT: Defaults to loopback. The decoys are meant to be reachable only
    ///         inside the authenticated perimeter, and defaulting to loopback
    ///         means a misconfiguration exposes them to nobody rather than to
    ///         everybody. The operator opts in to a wider bind.
    bind_addr: String,
    /// Where the trip stream is written. `None` means log-only.
    trip_log: Option<PathBuf>,
    /// Print the catalogue and exit.
    list: bool,
    /// Only run these decoys, by name. Empty means all.
    only: Vec<String>,
    /// Port overrides, by decoy name.
    ///
    /// EXPERT: A real deployment must place decoys on ports that are open,
    ///         unprivileged, and not in use by anything real. The catalogue
    ///         defaults are a starting point, not a plan, so overriding them has
    ///         to be a first-class operation rather than a source edit.
    /// KID: "Put this pretend door on a different number."
    ports: Vec<(String, u16)>,
}

fn usage() -> String {
    concat!(
        "otkp-decoy -- deception layer: banner decoys inside the authenticated perimeter\n",
        "\n",
        "USAGE:\n",
        "  otkp-decoy [--bind ADDR] [--trip-log PATH] [--only NAME[,NAME...]] [--list]\n",
        "\n",
        "OPTIONS:\n",
        "  --bind ADDR       Interface to bind on (default 127.0.0.1).\n",
        "                    These decoys belong INSIDE the perimeter: bind them\n",
        "                    to the VPN interface, never to a public one.\n",
        "  --trip-log PATH   Append the structured trip stream here (JSON Lines).\n",
        "                    Without it, trips are written to stderr only.\n",
        "  --only NAMES      Run only the named decoys (comma-separated).\n",
        "  --port NAME=PORT  Move a decoy to a different port (repeatable).\n",
        "                    The defaults are unprivileged alternates; override\n",
        "                    them if a port is taken or you want it elsewhere.\n",
        "  --list            Print the decoy catalogue and exit.\n",
        "  -h, --help        This message.\n",
        "\n",
        "WHAT THIS DOES NOT DO:\n",
        "  It does not revoke anything, block anything, or retaliate. It observes\n",
        "  and records. A separate responder consumes the trip stream and decides\n",
        "  what happens next.\n",
        "\n",
        "WHAT THE BANNERS ARE:\n",
        "  Inert strings naming historically-vulnerable versions. No such software\n",
        "  is installed, nothing is parsed, and there is nothing here to exploit.\n",
        "  That is the design, not an omission.\n",
    )
    .to_string()
}

fn parse_args() -> Result<Args> {
    let mut args = Args {
        bind_addr: "127.0.0.1".to_string(),
        trip_log: None,
        list: false,
        only: Vec::new(),
        ports: Vec::new(),
    };

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "--list" => args.list = true,
            "--bind" => {
                args.bind_addr = it
                    .next()
                    .ok_or_else(|| Error::config("--bind requires an address"))?;
            }
            "--trip-log" => {
                let p = it
                    .next()
                    .ok_or_else(|| Error::config("--trip-log requires a path"))?;
                args.trip_log = Some(PathBuf::from(p));
            }
            "--only" => {
                let v = it
                    .next()
                    .ok_or_else(|| Error::config("--only requires a name list"))?;
                args.only = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            "--port" => {
                let v = it
                    .next()
                    .ok_or_else(|| Error::config("--port requires NAME=PORT"))?;
                let (name, port) = v
                    .split_once('=')
                    .ok_or_else(|| Error::config(format!("--port expects NAME=PORT, got '{v}'")))?;
                let port: u16 = port
                    .parse()
                    .map_err(|_| Error::config(format!("--port: '{port}' is not a port number")))?;
                args.ports.push((name.trim().to_string(), port));
            }
            other => {
                return Err(Error::config(format!(
                    "unknown argument '{other}' (try --help)"
                )))
            }
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("otkp-decoy: {e}");
            let mut cause = std::error::Error::source(&e);
            while let Some(c) = cause {
                eprintln!("  caused by: {c}");
                cause = c.source();
            }
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let args = parse_args()?;

    // Materialise the catalogue, then apply any port overrides.
    let mut catalogue = Decoy::all();
    for (name, port) in &args.ports {
        let target = catalogue
            .iter_mut()
            .find(|d| &d.name == name)
            .ok_or_else(|| {
                Error::config(format!("--port names unknown decoy '{name}'; see --list"))
            })?;
        target.port = *port;
    }

    // Then any name filter.
    if !args.only.is_empty() {
        catalogue.retain(|d| args.only.iter().any(|n| n == &d.name));
        if catalogue.is_empty() {
            return Err(Error::config(
                "--only selected no decoys; check the names against --list",
            ));
        }
    }

    if args.list {
        // The header has no placeholders, so it is a literal rather than a
        // format argument — clippy was right that passing it as one was
        // pointless indirection.
        println!(
            "{:<18} {:>6}  {:<8} BANNER (first line)",
            "NAME", "PORT", "SERVICE"
        );
        for d in &catalogue {
            let first = d.banner.lines().next().unwrap_or("");
            // Show control characters visibly rather than letting them mangle
            // the terminal output.
            let safe: String = first
                .chars()
                .map(|c| if c.is_control() { '.' } else { c })
                .collect();
            println!("{:<18} {:>6}  {:<8} {}", d.name, d.port, d.service, safe);
        }
        println!();
        println!("These are inert strings. No matching software is installed.");
        return Ok(());
    }

    // ------------------------------------------------------------------
    // Bind everything up front. A partial bind is a silent coverage gap.
    // ------------------------------------------------------------------
    let mut bound = Vec::with_capacity(catalogue.len());
    for decoy in &catalogue {
        let listener = listener::bind(decoy, &args.bind_addr)?;
        bound.push((decoy.clone(), listener));
    }

    // ------------------------------------------------------------------
    // The sink: classify, record, and never act.
    // ------------------------------------------------------------------
    let log = Arc::new(TripLog::new(args.trip_log.clone()));
    let sink: Sink = {
        let log = Arc::clone(&log);
        Arc::new(move |seen: Interaction| {
            let trip = classify(&seen);
            let event = TripEvent::new(&seen, trip);

            // Human-readable line to stderr, so an operator watching sees it
            // immediately without a log pipeline.
            eprintln!(
                "otkp-decoy: TRIP {} decoy='{}' from {} credential={} bytes={} -> {}",
                trip.tag(),
                event.decoy,
                event.src_ip,
                event.credential.as_deref().unwrap_or("<unattributed>"),
                event.bytes_from_client,
                response_tag(event.response),
            );

            // Machine-readable record.
            if let Err(e) = log.write(&event) {
                // Soft failure, same reasoning as the main project: losing a
                // record is bad, but stopping the detector is worse.
                eprintln!("otkp-decoy: TRIP RECORD FAILED: {e}");
            }
        })
    };

    // ------------------------------------------------------------------
    // Report, then serve.
    // ------------------------------------------------------------------
    eprintln!("otkp-decoy: binding on {}", args.bind_addr);
    for (decoy, _) in &bound {
        eprintln!(
            "otkp-decoy:   {} ({}) on port {}",
            decoy.name, decoy.service, decoy.port
        );
    }
    match &args.trip_log {
        Some(p) => eprintln!("otkp-decoy: trip stream -> {}", p.display()),
        None => eprintln!("otkp-decoy: no --trip-log; trips go to stderr only"),
    }
    eprintln!(
        "otkp-decoy: NOTE this process does not revoke or block anything. \
         A separate responder consumes the trip stream."
    );

    // One thread per decoy. The main thread parks; a decoy daemon that exits on
    // its own would be a detection mechanism that silently stops detecting.
    let mut handles = Vec::with_capacity(bound.len());
    for (decoy, listener) in bound {
        let sink = Arc::clone(&sink);
        handles.push(std::thread::spawn(move || {
            listener::run(decoy, listener, sink);
        }));
    }
    for h in handles {
        // A panic in a decoy thread is logged by the runtime; we re-panic here
        // so the process does not limp on with one decoy silently dead.
        if h.join().is_err() {
            return Err(Error::net("a decoy listener thread panicked"));
        }
    }

    Ok(())
}

/// The stable tag for a response, for the human line.
fn response_tag(r: otkp_decoy::trip::Response) -> &'static str {
    use otkp_decoy::trip::Response::*;
    match r {
        RejectAndWarn => "reject_and_warn",
        RevokeCredential => "revoke_credential",
        RevokeAndAlert => "revoke_and_alert",
    }
}
