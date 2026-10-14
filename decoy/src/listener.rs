// ============================================================================
//  decoy/src/listener.rs  --  the listener that never reacts
// ============================================================================
//
//  EXPERT VIEW:
//    A thread per decoy port, each doing the same five things:
//
//      1. accept a connection
//      2. write the banner immediately
//      3. read whatever the client sends, bounded, with a short timeout
//      4. build an `Interaction`
//      5. hand it to a callback, and close
//
//    Three properties are load-bearing and easy to get wrong:
//
//      * **Nothing is parsed.** The bytes read are counted and truncated, never
//        interpreted. There is no parser here to overflow, because there is no
//        parser here. This is what makes the decoy un-exploitable rather than
//        merely un-exploited.
//      * **The read is bounded in time and in size.** A client that connects and
//        says nothing must not hold a thread forever, and a client that sends a
//        gigabyte must not make us allocate one. Both bounds are security
//        properties, not tidiness.
//      * **The decoy never reacts in-band.** No error, no delay beyond the read
//        timeout, no message. The attacker's experience is a service that served
//        a banner and then ignored them — which is also what a busy real service
//        looks like.
//
//    The listener does not classify and does not respond. It emits observations
//    to a callback; classification and response belong to `trip`, and the
//    responder belongs to separate software entirely.
//
//  KID VIEW:
//    Each pretend door has someone standing behind it who says the label out
//    loud, waits a moment to see if you say anything back, writes a note, and
//    closes the door. They never argue, never chase, never shout. Just a note.
// ============================================================================

use crate::banner::Decoy;
use crate::error::{Error, Result};
use crate::trip::Interaction;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long to wait for the client to say something after the banner.
///
/// EXPERT: Two seconds. Long enough that a real client attempting a handshake
///         gets to speak, short enough that a silent connection does not pin a
///         thread. Note that a silent connection is the *common* case — it is
///         exactly what a banner-fingerprinting scanner does — so this timeout
///         is on the hot path, not an edge case.
/// KID: We wait two seconds to see if they say anything, then we stop waiting.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// The most we will read from a client.
///
/// EXPERT: 8 KiB. Beyond the analysable window (`trip::MAX_ANALYSED_PAYLOAD`),
///         but not so far beyond that a client can make us allocate
///         meaningfully. The byte *count* is still recorded in full up to this
///         cap, so "they sent more than 8 KiB" remains observable.
/// KID: We only read a small bucket of what they send.
pub const MAX_READ: usize = 8192;

/// What the listener does with each observation.
///
/// EXPERT: A boxed `Fn` rather than a trait, because the callback has exactly one
///         method and defining a trait for it would be ceremony. It must be
///         `Send + Sync` because each decoy runs on its own thread and shares
///         the callback.
///
/// The listener does not classify. Handing the raw `Interaction` to the
///         caller keeps classification in one pure, testable place instead of
///         duplicating it per thread.
/// KID: The note-taker. Someone hands them what happened and they decide what to
///      write down.
pub type Sink = Arc<dyn Fn(Interaction) + Send + Sync>;

/// The current Unix time, or 0 if the clock is before the epoch.
///
/// EXPERT: Never panics. A decoy that crashed on a clock problem would be a
///         decoy that stops detecting, and the whole point is that it is always
///         there.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serve one connection on a decoy and report what happened.
///
/// EXPERT: Factored out of the accept loop so it can be exercised directly by a
///         test with a real loopback socket — no threads, no ports bound for the
///         duration of a test suite, no flakiness. The accept loop is then a
///         three-line wrapper, and the interesting behaviour is testable.
/// KID: Handle one visitor at one door.
pub fn serve_one(decoy: &Decoy, stream: &mut TcpStream, src_ip: std::net::IpAddr) -> Interaction {
    let at = now();

    // 1. Write the banner. If this fails the client is gone, and a connection
    //    that vanished before the banner is still worth recording as a probe:
    //    something connected to a door nobody uses.
    let _ = stream.write_all(decoy.banner.as_bytes());
    let _ = stream.flush();

    // 2. Bound the read, in time and in size. Both are security properties.
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));

    // 3. Read, bounded. We do NOT parse — the bytes are counted and kept for
    //    shape analysis, nothing more.
    let mut buf = vec![0u8; MAX_READ];
    let n = stream.read(&mut buf).unwrap_or(0);

    // A negative or absent read is treated as "said nothing", which is the
    // correct reading: a connection that errored before speaking told us nothing
    // beyond the fact that it connected.
    let n = n.min(MAX_READ);
    buf.truncate(n);

    Interaction {
        decoy: decoy.name.clone(),
        src_ip,
        // The listener cannot know the credential — that is the job of whatever
        // sits in front of the decoy and attributes the session. Leaving it
        // `None` is honest, and `Response::for_trip_with_credential` downgrades
        // accordingly rather than inventing an attribution.
        credential: None,
        bytes_from_client: n,
        client_payload: buf,
        at,
    }
}

/// Bind a listener for a decoy.
///
/// EXPERT: Separate from serving so a caller can bind all decoys up front and
///         fail *before* claiming to be running. A decoy that silently fails to
///         bind is a decoy that detects nothing while appearing healthy, which
///         is the worst possible failure for a detection mechanism.
/// KID: Open the door and make sure it actually opened.
pub fn bind(decoy: &Decoy, addr: &str) -> Result<TcpListener> {
    let full = format!("{addr}:{}", decoy.port);
    TcpListener::bind(&full).map_err(|e| {
        // The two realistic causes are worth naming, because the bare OS error
        // ("Permission denied", "Address already in use") sends an operator
        // looking in the wrong place. A decoy that silently covers less than the
        // operator believes is the worst failure mode this tool has.
        let hint = match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                " (ports below 1024 need root; use an unprivileged port)"
            }
            std::io::ErrorKind::AddrInUse => {
                " (something is already listening there -- check it is not the \
                  legitimate service)"
            }
            _ => "",
        };
        Error::net(format!(
            "could not bind decoy '{}' on {full}: {e}{hint}",
            decoy.name
        ))
    })
}

/// Run the accept loop for one decoy, forever.
///
/// EXPERT: One thread per decoy. The connection handling is synchronous and
///         short-lived (bounded by `READ_TIMEOUT`), so a thread-per-connection
///         model would also work — but a thread per *decoy* is simpler and the
///         accept loop serialises connections, which incidentally rate-limits
///         how fast a single decoy can be hammered.
///
/// Errors are logged and the loop continues. A decoy that stops accepting
///         because one connection misbehaved would be trivially disabled by the
///         attacker it is meant to observe.
/// KID: Keep answering the door, no matter how rude the visitors are.
pub fn run(decoy: Decoy, listener: TcpListener, sink: Sink) {
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                // The peer address is evidence for the record. If we cannot get
                // it, the connection is unusable for our purpose, so skip.
                let Ok(peer) = stream.peer_addr() else {
                    continue;
                };
                let seen = serve_one(&decoy, &mut stream, peer.ip());
                sink(seen);
                // The stream drops here, closing the connection. Closing is
                // not a signal — a real service closes idle connections too.
            }
            Err(e) => {
                // Log-and-continue: see the doc comment.
                eprintln!("otkp-decoy: accept failed on '{}': {e}", decoy.name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn test_decoy() -> Decoy {
        Decoy {
            name: "test-decoy".to_string(),
            port: 0, // unused in these tests; we pass an explicit listener
            banner: "SSH-2.0-TestBanner\r\n".to_string(),
            service: "Test".to_string(),
        }
    }

    /// Bind an ephemeral loopback listener and return it with its address.
    fn ephemeral() -> (TcpListener, std::net::SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    /// Accept one connection and serve it, on another thread.
    ///
    /// EXPERT: The ordering matters and got this wrong once. `serve_one` writes
    ///         the banner, so it must be *running* before the client tries to
    ///         read it. Accepting after the client's read means the client waits
    ///         on a socket nobody is writing to, until the read times out.
    ///
    /// Spawning the server side first makes the test express the real
    ///         sequence: the decoy is already listening and serving when a
    ///         visitor arrives.
    /// KID: Put the note-taker behind the door BEFORE the visitor knocks.
    fn serve_in_background(
        listener: TcpListener,
        decoy: Decoy,
    ) -> std::thread::JoinHandle<Interaction> {
        std::thread::spawn(move || {
            let (mut stream, peer) = listener.accept().expect("accept must succeed");
            serve_one(&decoy, &mut stream, peer.ip())
        })
    }

    /// Connect, read the banner, and return the client stream.
    ///
    /// EXPERT: Every test needs these three lines, and getting them subtly wrong
    ///         is how the first version of this suite deadlocked. Factoring them
    ///         out means there is one place to be right.
    /// KID: Walk up to the door and read the label.
    fn connect_and_read_banner(addr: std::net::SocketAddr) -> TcpStream {
        let mut client = TcpStream::connect(addr).expect("connect must succeed");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("setting a timeout must succeed");
        let mut banner = [0u8; 128];
        let n = client
            .read(&mut banner)
            .expect("the decoy must serve a banner promptly");
        assert!(n > 0, "the decoy must serve a non-empty banner");
        client
    }

    #[test]
    fn a_client_that_reads_and_leaves_is_a_probe() {
        // THE central case, exercised over a real socket.
        let (listener, addr) = ephemeral();
        let server = serve_in_background(listener, test_decoy());

        // Connect, read the banner, send nothing, close.
        let client = connect_and_read_banner(addr);
        drop(client);

        let seen = server.join().expect("the server thread must finish");
        assert_eq!(seen.decoy, "test-decoy");
        assert_eq!(seen.bytes_from_client, 0, "the client said nothing");
        assert!(
            seen.credential.is_none(),
            "the listener cannot attribute a session, and must not pretend to"
        );
        assert_eq!(crate::trip::classify(&seen), crate::trip::Trip::Probe);
    }

    #[test]
    fn a_client_that_sends_data_is_recorded_with_its_payload() {
        let (listener, addr) = ephemeral();
        let server = serve_in_background(listener, test_decoy());

        let mut client = connect_and_read_banner(addr);
        client.write_all(b"SSH-2.0-Client_1.0\r\n").unwrap();
        client.flush().unwrap();
        // Give the server's read a moment to see the bytes. The server closes
        // after one read, so the ordering here is deterministic once the bytes
        // are in the socket buffer.
        std::thread::sleep(Duration::from_millis(100));
        drop(client);

        let seen = server.join().expect("the server thread must finish");
        // Assert against the expression rather than a hand-counted literal: an
        // earlier version of this test said 21 and was wrong by one, which is
        // exactly the kind of mistake a magic number invites.
        assert_eq!(seen.bytes_from_client, b"SSH-2.0-Client_1.0\r\n".len());
        assert_eq!(seen.client_payload, b"SSH-2.0-Client_1.0\r\n");
        assert_eq!(crate::trip::classify(&seen), crate::trip::Trip::Connect);
    }

    #[test]
    fn an_exploit_shaped_payload_is_classified_as_such_over_the_wire() {
        let (listener, addr) = ephemeral();
        let server = serve_in_background(listener, test_decoy());

        let mut client = connect_and_read_banner(addr);
        client.write_all(b"GET /../../etc/passwd HTTP/1.0").unwrap();
        client.flush().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        drop(client);

        let seen = server.join().expect("the server thread must finish");
        assert_eq!(crate::trip::classify(&seen), crate::trip::Trip::Exploit);
    }

    #[test]
    fn the_read_is_bounded() {
        // A client that floods must not make us buffer more than MAX_READ.
        let (listener, addr) = ephemeral();
        let server = serve_in_background(listener, test_decoy());

        let mut client = connect_and_read_banner(addr);
        // The write may block once our side stops reading, which is fine: the
        // server does exactly one bounded read and then closes.
        let flood = vec![b'A'; MAX_READ * 4];
        let _ = client.write_all(&flood);
        let _ = client.flush();
        std::thread::sleep(Duration::from_millis(100));
        drop(client);

        let seen = server.join().expect("the server thread must finish");
        assert!(
            seen.client_payload.len() <= MAX_READ,
            "the listener must not buffer more than MAX_READ, got {}",
            seen.client_payload.len()
        );
    }

    #[test]
    fn binding_a_privileged_port_reports_an_error_rather_than_panicking() {
        // Port 1 is privileged; binding it as a normal user fails. The point is
        // that the failure is a value, not a panic.
        let mut decoy = test_decoy();
        decoy.port = 1;
        let result = bind(&decoy, "127.0.0.1");
        // Either it failed (expected) or we are root and it succeeded.
        match result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("test-decoy"),
                    "the error should name the decoy"
                );
            }
            Ok(_) => { /* running as root; nothing to assert */ }
        }
    }

    #[test]
    fn the_sink_receives_every_observation() {
        use std::sync::Mutex;
        let collected: Arc<Mutex<Vec<Interaction>>> = Arc::new(Mutex::new(Vec::new()));
        let sink: Sink = {
            let c = Arc::clone(&collected);
            Arc::new(move |seen| c.lock().unwrap().push(seen))
        };

        let (listener, addr) = ephemeral();
        let decoy = test_decoy();
        let handle = {
            let d = decoy.clone();
            std::thread::spawn(move || run(d, listener, sink))
        };

        // Two connections, one silent and one talkative.
        {
            let mut c = TcpStream::connect(addr).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut b = [0u8; 64];
            let _ = c.read(&mut b).unwrap();
        }
        {
            let mut c = TcpStream::connect(addr).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut b = [0u8; 64];
            let _ = c.read(&mut b).unwrap();
            let _ = c.write_all(b"hello");
        }

        // Wait for both to land.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if collected.lock().unwrap().len() >= 2 {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("the sink did not receive both observations");
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let seen = collected.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].bytes_from_client, 0);
        assert_eq!(seen[1].bytes_from_client, 5);

        // The thread is detached on purpose: `run` loops forever and the process
        // is about to end. Dropping the listener would be cleaner but requires
        // an API `run` does not have, and adding one for a test would be worse.
        drop(handle);
        let _ = UdpSocket::bind("127.0.0.1:0"); // no-op, keeps the import used
    }
}
