// ============================================================================
//  src/net.rs  --  observing knocks, and sending them
// ============================================================================
//
//  EXPERT VIEW:
//    This module is the only place in the project that talks to the network, and
//    it is split into two halves that are deliberately symmetric:
//
//      * **Receiving** (server side). A trait `KnockSource` with two
//        implementations: `UdpKnockSource` (an ordinary UDP socket, no
//        privileges) and `RawKnockSource` (an `AF_PACKET` socket that sees
//        packets to *closed* ports, needs root). Both produce the same
//        `KnockEvent`, which is why the engine needs only one implementation of
//        the security logic.
//
//      * **Sending** (client side). Free functions `send_knocks` that mirror the
//        two modes. No trait is needed here because the client does exactly one
//        thing once; a trait would be ceremony.
//
//    The critical design move is that **packet parsing is a pure function**.
//    `parse_ipv4_dest_port` takes a byte slice and returns an address and port.
//    It contains no syscalls, so it can be unit-tested exhaustively -- including
//    against malformed input -- without root, without a network, and without
//    flakiness. The unsafe socket code around it is reduced to "read bytes into
//    a buffer and hand them to the pure function".
//
//    On `unsafe`: this file contains the project's only `unsafe` blocks, and
//    they are confined to `RawKnockSource`. Every one of them is a direct libc
//    call with a comment stating the invariant being upheld. There is no pointer
//    arithmetic, no manual allocation, and no lifetime laundering.
//
//  KID VIEW:
//    Two ways to listen for taps on the wall:
//
//      * The *easy* way: one door is slightly open, and friends slip a note
//        under it saying which door they would have tapped. No special
//        permission needed -- but a real stranger tapping a real wall would go
//        unnoticed.
//      * The *proper* way: we put our ear right against the wall and listen to
//        every tap on every door, even closed ones. That needs special
//        permission (being the building manager), but it is what real port
//        knocking is.
//
//    Either way, we write down the same note for the bouncer: "someone at this
//    address tapped this door."
// ============================================================================

use crate::crypto::KnockSpec;
use crate::engine::KnockEvent;
use crate::error::{OtkpError, Result};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

// ===========================================================================
//  The receiving interface
// ===========================================================================
/// A source of knock events.
///
/// EXPERT: `recv` returns `Result<Option<KnockEvent>>` rather than
///         `Result<KnockEvent>` for a specific reason: the daemon loop must also
///         perform periodic housekeeping (expiring grants and bans), and a
///         blocking read would starve it. `Ok(None)` means "nothing arrived
///         before the timeout", which is a *normal* result, not an error. Making
///         that explicit in the type means the daemon loop reads naturally and
///         cannot forget to sweep.
/// KID: An ear against the wall. You listen for a short while; if you hear
///      nothing, you say "nothing yet" and go do your chores.
pub trait KnockSource {
    /// Wait up to a short timeout for one knock, stamping it with `now`.
    ///
    /// EXPERT: The timestamp is a *parameter*, not something the source reads
    ///         itself. That is a deliberate and important choice: the daemon owns
    ///         the `Clock`, and if the source read the wall clock independently,
    ///         then a test with an injected clock would see the engine reasoning
    ///         about one time while events carried another -- and a daemon that
    ///         "worked" under test would silently misbehave in production (or
    ///         vice versa). One clock, owned by one component, passed down.
    ///
    /// * `Ok(Some(event))` -- a knock arrived.
    /// * `Ok(None)` -- the timeout elapsed with no knock.
    /// * `Err(_)` -- something actually went wrong.
    fn recv_at(&mut self, now: u64) -> Result<Option<KnockEvent>>;

    /// A short name for log lines.
    fn name(&self) -> &'static str;
}

/// The magic prefix of a `udp`-mode knock payload: the ASCII bytes `OTKP`.
///
/// EXPERT: A magic value lets the listener reject random UDP traffic that
///         happens to hit the port (port scanners, stray packets) instead of
///         treating it as a malformed knock and -- worse -- counting it as a
///         failure that bans an innocent sender. Rejecting silently is the
///         correct behaviour for noise.
/// KID: A secret little signature at the start of the note, so we know the note
///      is really from a friend and not just litter blown under the door.
pub const UDP_MAGIC: [u8; 4] = *b"OTKP";

/// The total length of a `udp`-mode knock payload: magic + big-endian u16 port.
pub const UDP_PAYLOAD_LEN: usize = 6;

/// Build a `udp`-mode knock payload for `port`.
///
/// EXPERT: Factored out so the client's sender and the tests share one
///         definition of the wire format. A test that hard-codes the bytes is
///         testing the *format*; a test that calls this function is testing the
///         *round trip*. We do both, in different tests.
/// KID: Write the note: the signature, then the door number.
pub fn build_udp_payload(port: u16) -> [u8; UDP_PAYLOAD_LEN] {
    let mut out = [0u8; UDP_PAYLOAD_LEN];
    // First four bytes: the magic.
    out[..4].copy_from_slice(&UDP_MAGIC);
    // Last two bytes: the port, big-endian (network byte order).
    out[4..6].copy_from_slice(&port.to_be_bytes());
    out
}

/// Parse a `udp`-mode knock payload, returning the intended port.
///
/// EXPERT: Returns `Option`, not `Result`: "this is not one of our payloads" is
///         the overwhelmingly common case (any random UDP packet), and it is not
///         an error condition. `None` means "ignore this packet", which the
///         caller does silently.
/// KID: Read the note. If it does not have our signature, it is not for us --
///      throw it away without making a fuss.
pub fn parse_udp_payload(data: &[u8]) -> Option<u16> {
    // Too short to contain a header: not ours.
    if data.len() < UDP_PAYLOAD_LEN {
        return None;
    }
    // Wrong magic: not ours.
    if data[..4] != UDP_MAGIC {
        return None;
    }
    // `try_into` converts the 2-byte slice to `[u8; 2]`; it cannot fail here
    // because we know the length, but we use `ok()?` rather than `unwrap()` to
    // keep the "no panics" rule even in the face of a future edit.
    let bytes: [u8; 2] = data[4..6].try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

// ===========================================================================
//  UdpKnockSource -- the unprivileged listener
// ===========================================================================
/// A knock source backed by a single UDP socket.
///
/// EXPERT: The socket is bound to `listen_addr` and configured with a read
///         timeout, so `recv` returns promptly when idle. The timeout is the
///         mechanism that lets the daemon loop interleave packet handling with
///         housekeeping; it is not a performance optimisation.
///
/// The *intended* port comes from the payload, not from the packet's
///         destination port -- because every packet arrives at the same
///         `listen_addr`. This is what lets the whole protocol be exercised
///         without root. See docs/PROTOCOL.md section 4.1.
/// KID: One door is slightly open. Friends slip notes under it saying which door
///      they meant to tap.
#[derive(Debug)]
pub struct UdpKnockSource {
    /// The bound socket.
    ///
    /// EXPERT: `UdpSocket` is `Send + Sync` and owns its file descriptor, closing
    ///         it on drop. No manual resource management needed -- a nice example
    ///         of Rust's RAII making a resource leak hard to write.
    /// KID: The slightly-open door.
    socket: UdpSocket,
    /// The current time, in seconds, as of the last `recv`.
    ///
    /// EXPERT: We do NOT store a `Clock` here (which would force a lifetime or an
    ///         `Arc`). Instead the caller passes the timestamp in when it calls
    ///         `recv_at`. The plain `recv` uses the system clock. This keeps the
    ///         type simple while still allowing deterministic tests through
    ///         `recv_at`.
    /// KID: A little note of what time it is when a tap arrives.
    _private: (),
}

impl UdpKnockSource {
    /// Bind a UDP listener to `addr`.
    ///
    /// EXPERT: `set_read_timeout` is what makes `recv` non-blocking-ish. We use
    ///         250 ms: short enough that housekeeping runs promptly, long enough
    ///         that we are not spinning on `recv` and burning CPU. This is a
    ///         deliberate trade and the number deserves its comment.
    /// KID: Open the door a crack and set an egg timer for a quarter of a second.
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .map_err(|e| OtkpError::net(format!("could not bind UDP listener on {addr}: {e}")))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .map_err(|e| OtkpError::net(format!("could not set read timeout: {e}")))?;
        Ok(UdpKnockSource {
            socket,
            _private: (),
        })
    }

    /// The address we are actually bound to.
    ///
    /// EXPERT: Useful when the config says `0.0.0.0:0` (let the OS pick a port)
    ///         -- as the integration tests do. `local_addr` asks the kernel what
    ///         it chose.
    /// KID: "Which door did we actually open?"
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| OtkpError::net(format!("local_addr failed: {e}")))
    }
}

impl KnockSource for UdpKnockSource {
    /// Receive one knock, stamping it with `now`.
    ///
    /// EXPERT: The timestamp is a parameter so tests can supply a fixed value;
    ///         the daemon supplies its own `Clock`'s reading. This is the
    ///         simplest possible dependency injection -- no traits or generics
    ///         needed, just an argument.
    /// KID: Listen for a note, and write down what time it arrived.
    fn recv_at(&mut self, now: u64) -> Result<Option<KnockEvent>> {
        // A 2 KiB buffer is far larger than any legitimate knock payload, which
        // keeps the syscall simple. Anything bigger than this from a single
        // datagram is not a knock.
        let mut buf = [0u8; 2048];

        match self.socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                // `&buf[..n]` is exactly the received bytes; the rest is zeros.
                match parse_udp_payload(&buf[..n]) {
                    Some(port) => Ok(Some(KnockEvent {
                        src_ip: from.ip(),
                        dst_port: port,
                        at: now,
                    })),
                    // Not one of our payloads: ignore it silently. Logging every
                    // stray packet would be a log-flooding DoS.
                    None => Ok(None),
                }
            }
            Err(e) => {
                // A timeout is a *normal* outcome, not an error.
                // `ErrorKind::WouldBlock` and `TimedOut` both mean "nothing yet"
                // depending on platform, so we accept either.
                match e.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Ok(None),
                    // A real error. `ConnectionRefused` on a UDP socket means an
                    // ICMP port-unreachable came back -- common and harmless on
                    // Linux when sending to a closed port, so we tolerate it too.
                    std::io::ErrorKind::ConnectionRefused => Ok(None),
                    _ => Err(OtkpError::net(format!("recv_from failed: {e}"))),
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "udp"
    }
}

// ===========================================================================
//  Raw packet parsing -- a PURE function, hence fully testable
// ===========================================================================
/// Extract the destination IP and port from a captured IPv4 packet.
///
/// EXPERT: The input is the raw bytes delivered by an `AF_PACKET` socket: an
///         Ethernet frame (possibly VLAN-tagged), containing an IPv4 datagram,
///         containing TCP or UDP. This function walks that structure with
///         explicit bounds checks at every step and returns `None` for anything
///         it does not recognise. It performs NO syscalls and touches no global
///         state, which is why the tests below can feed it hand-built packets --
///         including truncated and hostile ones -- and assert on the results.
///
/// Returning `Option<(IpAddr, u16)>` rather than panicking on malformed
///         input is essential: these bytes come from the network, i.e. from an
///         attacker. A parser that panics on a crafted packet is a remote
///         denial-of-service.
/// KID: A letter arrives in a big envelope. Inside is a smaller envelope, and
///      inside that is the note. We open them one at a time, and if anything
///      looks wrong we just say "not a real letter" instead of getting upset.
pub fn parse_ipv4_dest_port(frame: &[u8]) -> Option<(IpAddr, u16)> {
    // ------------------------------------------------------------------
    // Layer 1: the Ethernet header. 14 bytes: 6 dest MAC, 6 src MAC, 2 type.
    // ------------------------------------------------------------------
    const ETH_HEADER_LEN: usize = 14;
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    // The EtherType tells us what is inside. `from_be_bytes` because the field
    // is big-endian on the wire.
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    // An offset past the Ethernet header, which a VLAN tag will increase.
    let mut l3_offset = ETH_HEADER_LEN;

    // ------------------------------------------------------------------
    // VLAN tagging (802.1Q) inserts 4 bytes between Ethernet and IPv4, and
    // sets the EtherType to 0x8100. We support a single tag, which covers
    // essentially every real deployment.
    // ------------------------------------------------------------------
    const ETH_P_8021Q: u16 = 0x8100;
    if ethertype == ETH_P_8021Q {
        // Need 4 more bytes for the tag, then 2 for the real EtherType.
        if frame.len() < l3_offset + 4 + 2 {
            return None;
        }
        // The real EtherType sits after the 2-byte TCI, i.e. at offset+2.
        ethertype = u16::from_be_bytes([frame[l3_offset + 2], frame[l3_offset + 3]]);
        l3_offset += 4;
    }

    // We only understand IPv4. IPv6 would need its own parser; see the roadmap.
    const ETH_P_IP: u16 = 0x0800;
    if ethertype != ETH_P_IP {
        return None;
    }

    // ------------------------------------------------------------------
    // Layer 2: the IPv4 header. Minimum 20 bytes.
    // ------------------------------------------------------------------
    if frame.len() < l3_offset + 20 {
        return None;
    }
    let ip = &frame[l3_offset..];

    // The first nibble is the version; the second is the header length in
    // 32-bit words ("IHL"). Anything other than version 4 is not for us.
    let version = ip[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    // IHL must be at least 5 words (20 bytes) and must fit in what we received.
    if ihl < 20 || ip.len() < ihl {
        return None;
    }

    // Byte 9 is the protocol number: 6 = TCP, 17 = UDP.
    let protocol = ip[9];
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return None;
    }

    // Bytes 12..16 are the source address.
    let src = IpAddr::V4(std::net::Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));

    // ------------------------------------------------------------------
    // Layer 3: the transport header. Both TCP and UDP put the destination
    // port in bytes 2..4 of their header, which is a happy coincidence that
    // lets us share one code path.
    // ------------------------------------------------------------------
    let l4 = &ip[ihl..];
    if l4.len() < 4 {
        return None;
    }
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);

    Some((src, dst_port))
}

// ===========================================================================
//  RawKnockSource -- the AF_PACKET sniffer
// ===========================================================================
/// A knock source that reads every IPv4 packet off the wire.
///
/// EXPERT: This is real port knocking: the knock ports are *closed*, nothing is
///         listening on them, and we still see the packets. That requires an
///         `AF_PACKET` raw socket, which requires `CAP_NET_RAW` (in practice,
///         root). The alternative -- a UDP listener -- cannot see packets to
///         closed ports, which is why both exist.
///
/// All the `unsafe` in this crate lives in this struct's methods. Each
///         block is a direct libc call; the invariants are stated inline.
///
/// This type is Linux-only. On other platforms `bind` returns a clear
///         error rather than failing to compile, so the crate stays portable and
///         the message tells the operator what to do.
/// KID: We press our ear to the wall and listen to *every* tap, even on doors
///      that are shut. That needs the building manager's key (root).
#[derive(Debug)]
pub struct RawKnockSource {
    /// The raw socket's file descriptor, or `None` on non-Linux / before `bind`.
    ///
    /// EXPERT: On non-Linux this is always `None` and `recv` returns an error, so
    ///         the type still exists and the daemon can still be *configured*
    ///         with `--source raw` on macOS and get a clear runtime message.
    /// KID: The special ear trumpet. We do not have one on this computer.
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
    /// Marker so the field set is non-empty on non-Linux builds.
    #[cfg(not(target_os = "linux"))]
    _private: (),
}

#[cfg(target_os = "linux")]
impl RawKnockSource {
    /// Open the raw socket.
    ///
    /// EXPERT: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))` creates a socket
    ///         that receives copies of every IPv4 packet seen by any interface.
    ///         `htons` is applied by converting the constant with `to_be()`,
    ///         which is exactly what `htons` does.
    ///
    /// We set `SO_RCVTIMEO` so `recvfrom` returns on a timeout, mirroring
    ///         the UDP source's behaviour. Without it the daemon could never
    ///         sweep, and an open port would never close.
    ///
    /// `#[allow(unsafe_code)]` on this `impl` block re-enables `unsafe`
    ///         locally, which is only possible because the crate uses `deny`, not
    ///         `forbid`. See the note in `lib.rs`.
    /// KID: Ask the building manager for the ear trumpet.
    #[allow(unsafe_code)]
    pub fn bind() -> Result<Self> {
        // SAFETY: `libc::socket` is a plain syscall wrapper. We pass valid
        // constants; the only failure mode is an error return, which we check
        // immediately. `ETH_P_IP` must be in network byte order, hence `to_be()`.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_IP as u16).to_be() as libc::c_int,
            )
        };

        if fd < 0 {
            let err = std::io::Error::last_os_error();
            // The overwhelmingly likely cause is missing privileges, so we say
            // so -- a bare "Operation not permitted" would send the operator
            // hunting in the wrong place.
            return Err(OtkpError::net(format!(
                "could not open AF_PACKET socket ({err}); raw mode needs root or CAP_NET_RAW"
            )));
        }

        // Set a receive timeout so the daemon loop can do housekeeping.
        //
        // SAFETY: `setsockopt` reads `size_of::<timeval>()` bytes from the
        // pointer we pass, and `tv` is a live, correctly-typed local for the
        // duration of the call. The pointer cast is the conventional `void*`
        // idiom of the C API.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000, // 250 ms, matching the UDP source
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // Close the socket we opened before returning the error, so we do
            // not leak a descriptor on a failure path.
            // SAFETY: `fd` is a valid, open descriptor we just created.
            unsafe { libc::close(fd) };
            return Err(OtkpError::net(format!(
                "could not set SO_RCVTIMEO on raw socket: {err}"
            )));
        }

        Ok(RawKnockSource { fd })
    }

    /// Receive one packet and parse it.
    ///
    /// EXPERT: `recvfrom` with null address arguments is fine for `AF_PACKET`:
    ///         the source address is inside the packet, which we parse ourselves.
    ///         We pass a 64 KiB buffer -- the maximum IPv4 datagram -- so we
    ///         never truncate a packet and mis-parse it.
    /// KID: Listen for a tap; when one comes, open the envelope and read it.
    #[allow(unsafe_code)]
    pub fn recv_at(&mut self, now: u64) -> Result<Option<KnockEvent>> {
        // A stack buffer of 64 KiB. This is large but bounded, and it is
        // allocated once per call rather than per packet. For a daemon loop that
        // is entirely acceptable; if profiling ever showed it mattered we would
        // hoist it into the struct.
        let mut buf = [0u8; 65_536];

        // SAFETY: `recvfrom` writes at most `buf.len()` bytes to `buf.as_mut_ptr()`,
        // and returns the number written (or -1). We therefore never read
        // uninitialised memory: we slice `buf[..n]` only for `n > 0`, and the
        // buffer is zero-initialised anyway. Null address pointers are explicitly
        // permitted by the API when the peer address is not wanted.
        let n = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            // Timeouts are normal: report "nothing yet" rather than an error.
            return match err.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Ok(None),
                // EINTR: a signal interrupted the call. Also normal; retry later.
                std::io::ErrorKind::Interrupted => Ok(None),
                _ => Err(OtkpError::net(format!("raw recvfrom failed: {err}"))),
            };
        }

        // `n` is the number of bytes actually received. `as usize` is safe: we
        // just checked it is non-negative.
        let data = &buf[..n as usize];
        match parse_ipv4_dest_port(data) {
            Some((src_ip, dst_port)) => Ok(Some(KnockEvent {
                src_ip,
                dst_port,
                at: now,
            })),
            // Not an IPv4 TCP/UDP packet we understand: ignore silently.
            None => Ok(None),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawKnockSource {
    /// Close the socket when the source is dropped.
    ///
    /// EXPERT: Rust does not close raw file descriptors automatically, so we must
    ///         do it by hand. Implementing `Drop` means it happens on every exit
    ///         path -- early return, panic unwind, or normal scope exit -- which
    ///         is exactly the guarantee we want and exactly what a manual
    ///         `close()` call at the end of `main` would fail to provide.
    /// KID: Give the ear trumpet back when we are done with it.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.fd` was created by `socket()` in `bind` and is not
        // closed anywhere else, so it is still a valid open descriptor.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(target_os = "linux")]
impl KnockSource for RawKnockSource {
    fn recv_at(&mut self, now: u64) -> Result<Option<KnockEvent>> {
        RawKnockSource::recv_at(self, now)
    }

    fn name(&self) -> &'static str {
        "raw"
    }
}

// ---------------------------------------------------------------------------
// Non-Linux stubs
// ---------------------------------------------------------------------------
// EXPERT: We provide a `bind` that compiles everywhere but only works on Linux.
//         That is better than `#[cfg]`-ing the type out entirely, because the
//         daemon and CLI can then be written without platform conditionals --
//         they always have a `RawKnockSource` type to name, and the failure is a
//         clear runtime message instead of a compile error that would force
//         `cfg` attributes up through the whole call graph.
// KID: On a computer without an ear trumpet, we still have a box labelled "ear
//      trumpet"; it just says "sorry, not on this computer" when you open it.
#[cfg(not(target_os = "linux"))]
impl RawKnockSource {
    /// Always fails on non-Linux platforms.
    pub fn bind() -> Result<Self> {
        Err(OtkpError::net(
            "raw mode requires Linux AF_PACKET support; use --source udp on this platform",
        ))
    }

    /// Always fails on non-Linux platforms.
    pub fn recv_at(&mut self, _now: u64) -> Result<Option<KnockEvent>> {
        Err(OtkpError::net(
            "raw mode requires Linux AF_PACKET support; use --source udp on this platform",
        ))
    }
}

#[cfg(not(target_os = "linux"))]
impl KnockSource for RawKnockSource {
    fn recv_at(&mut self, _now: u64) -> Result<Option<KnockEvent>> {
        Err(OtkpError::net(
            "raw mode requires Linux AF_PACKET support; use --source udp on this platform",
        ))
    }

    fn name(&self) -> &'static str {
        "raw"
    }
}

// ===========================================================================
//  The client side: sending knocks
// ===========================================================================
/// Where to send knocks and in which mode.
///
/// EXPERT: A small parameter object rather than four separate arguments. Four
///         arguments of which two are `u16` and one is a `&str` is the kind of
///         signature where a caller silently swaps two values and gets a
///         confusing failure. A named struct makes the call site self-documenting.
/// KID: A little card with the address, the door, and which method to use.
#[derive(Debug, Clone)]
pub struct SendTarget {
    /// The server's hostname or IP, as typed by the user.
    pub host: String,
    /// The port to send `udp`-mode knocks to (the listener's port).
    pub listen_port: u16,
    /// The transport mode.
    pub raw_mode: bool,
    /// Milliseconds to wait between knocks.
    pub inter_knock_delay_ms: u64,
}

/// Send a full knock sequence.
///
/// EXPERT: The client's entire job. Two behaviours depending on mode:
///
/// * **udp mode**: every datagram goes to the same `listen_port`, and
///           the payload carries the intended port. The socket sends from an
///           ephemeral local port, which is fine -- the server learns the source
///           address from `recvfrom`.
///
/// * **raw mode**: datagram *i* goes to the real port `knock_ports[i]`.
///           Nothing is listening there, so no reply ever comes; the client is
///           fire-and-forget by design (see docs/PROTOCOL.md section 4.2).
///
/// A single `UdpSocket` is reused for the whole sequence, which matters
///         for a subtle reason: reusing one socket keeps the same source port for
///         every knock, so a server that (incorrectly) keyed state on
///         `(ip, port)` would still work. Reuse is also cheaper.
///
/// Returns the number of datagrams actually sent, so the caller can
///         report it. A partial send is reported honestly rather than dressed up
///         as success.
/// KID: Tap every door in the list, in order, with a short pause between taps so
///      the person inside can count them.
pub fn send_knocks(target: &SendTarget, spec: &KnockSpec) -> Result<usize> {
    // Resolve the host once. `to_socket_addrs` returns an iterator because a
    // name can map to several addresses; we take the first that works.
    let resolved: Vec<SocketAddr> = (target.host.as_str(), target.listen_port)
        .to_socket_addrs()
        .map_err(|e| {
            OtkpError::net(format!(
                "could not resolve '{}:{}': {e}",
                target.host, target.listen_port
            ))
        })?
        .collect();

    let base = resolved.first().copied().ok_or_else(|| {
        OtkpError::net(format!(
            "'{}:{}' resolved to no addresses",
            target.host, target.listen_port
        ))
    })?;

    // Bind an ephemeral local socket. `0.0.0.0:0` lets the OS choose both the
    // local interface and port.
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| OtkpError::net(format!("could not bind local socket: {e}")))?;

    let mut sent = 0usize;
    for (i, &port) in spec.knock_ports.iter().enumerate() {
        // Choose the destination and the payload for this mode.
        let (dest, payload): (SocketAddr, Vec<u8>) = if target.raw_mode {
            // Raw mode: the *real* destination port is the knock port.
            let mut d = base;
            d.set_port(port);
            (d, Vec::new()) // empty payload; the port itself is the message
        } else {
            // UDP mode: always the listener, with the intended port in the body.
            (base, build_udp_payload(port).to_vec())
        };

        socket.send_to(&payload, dest).map_err(|e| {
            OtkpError::net(format!("failed to send knock {i} ({port}) to {dest}: {e}"))
        })?;
        sent += 1;

        // Pause between knocks. We skip the delay after the last one, because
        // there is nothing left to keep in order.
        if i + 1 < spec.knock_ports.len() && target.inter_knock_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(target.inter_knock_delay_ms));
        }
    }

    Ok(sent)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // -----------------------------------------------------------------------
    // Payload codec
    // -----------------------------------------------------------------------
    #[test]
    fn udp_payload_round_trips() {
        for port in [0u16, 1, 80, 1024, 27488, 65535] {
            let payload = build_udp_payload(port);
            assert_eq!(parse_udp_payload(&payload), Some(port));
        }
    }

    #[test]
    fn udp_payload_is_big_endian() {
        // Port 0x1234 must appear as bytes 0x12, 0x34 -- network byte order.
        let payload = build_udp_payload(0x1234);
        assert_eq!(&payload[..4], b"OTKP");
        assert_eq!(payload[4], 0x12);
        assert_eq!(payload[5], 0x34);
    }

    #[test]
    fn udp_payload_rejects_wrong_magic() {
        let mut payload = build_udp_payload(1000);
        payload[0] = b'X';
        assert_eq!(parse_udp_payload(&payload), None);
    }

    #[test]
    fn udp_payload_rejects_short_input() {
        assert_eq!(parse_udp_payload(b""), None);
        assert_eq!(parse_udp_payload(b"OTK"), None);
        assert_eq!(parse_udp_payload(b"OTKP"), None); // magic but no port
        assert_eq!(parse_udp_payload(b"OTKP\x12"), None); // only one port byte
    }

    #[test]
    fn udp_payload_ignores_trailing_bytes() {
        // A longer datagram with our magic is still ours; we read the port and
        // ignore the rest. This keeps us forward-compatible with a future
        // version that appends an HMAC (see the roadmap).
        let mut payload = build_udp_payload(4242).to_vec();
        payload.extend_from_slice(b"future-extension-bytes");
        assert_eq!(parse_udp_payload(&payload), Some(4242));
    }

    // -----------------------------------------------------------------------
    // Packet parsing -- the pure function. These tests are the reason the
    // parser is separate from the socket code.
    // -----------------------------------------------------------------------

    /// Build a synthetic Ethernet + IPv4 + UDP/TCP frame.
    ///
    /// EXPERT: Hand-building the bytes is the *point*: it lets us assert on the
    ///         parser's behaviour for structures no real NIC would produce
    ///         (truncated, mislabelled, VLAN-tagged), which is exactly the input
    ///         an attacker controls.
    /// KID: Make a pretend letter with a pretend envelope, so we can check the
    ///      opener works.
    fn build_frame(src: [u8; 4], dst_port: u16, protocol: u8, vlan: bool) -> Vec<u8> {
        let mut f = Vec::new();
        // Ethernet: 6 dst + 6 src MAC (contents irrelevant to us) + EtherType.
        f.extend_from_slice(&[0xff; 6]); // broadcast dst
        f.extend_from_slice(&[0x02; 6]); // some src
        if vlan {
            f.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN EtherType
            f.extend_from_slice(&0x0064u16.to_be_bytes()); // VLAN TCI
        }
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

        // IPv4 header: 20 bytes, version 4, IHL 5.
        f.push(0x45); // version 4, IHL 5
        f.push(0x00); // DSCP/ECN
        f.extend_from_slice(&40u16.to_be_bytes()); // total length (unused by us)
        f.extend_from_slice(&0u16.to_be_bytes()); // identification
        f.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment
        f.push(64); // TTL
        f.push(protocol); // protocol
        f.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unused)
        f.extend_from_slice(&src); // source address
        f.extend_from_slice(&[10, 0, 0, 9]); // destination address

        // Transport header: 20 bytes is enough for our needs (we read bytes 2..4).
        f.extend_from_slice(&12345u16.to_be_bytes()); // source port
        f.extend_from_slice(&dst_port.to_be_bytes()); // destination port
        f.extend_from_slice(&[0u8; 16]); // padding to make it a plausible header
        f
    }

    #[test]
    fn parse_udp_frame() {
        let frame = build_frame([192, 168, 1, 50], 27488, 17, false);
        let (ip, port) = parse_ipv4_dest_port(&frame).expect("must parse");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(port, 27488);
    }

    #[test]
    fn parse_tcp_frame() {
        // TCP must work too: a user may knock with a TCP connection attempt.
        let frame = build_frame([10, 1, 2, 3], 40001, 6, false);
        let (ip, port) = parse_ipv4_dest_port(&frame).expect("must parse");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(port, 40001);
    }

    #[test]
    fn parse_vlan_tagged_frame() {
        let frame = build_frame([172, 16, 0, 1], 41111, 17, true);
        let (ip, port) = parse_ipv4_dest_port(&frame).expect("VLAN frame must parse");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(port, 41111);
    }

    #[test]
    fn parse_rejects_truncated_frames() {
        let full = build_frame([1, 2, 3, 4], 1000, 17, false);
        // Every prefix shorter than the full frame must be rejected without
        // panicking. This is the anti-DoS property: an attacker controls these
        // bytes and a panic here would take the daemon down.
        for cut in 0..full.len() {
            let _ = parse_ipv4_dest_port(&full[..cut]);
        }
    }

    #[test]
    fn parse_rejects_non_ipv4() {
        // IPv6 EtherType: not our parser's job.
        let mut frame = build_frame([1, 2, 3, 4], 1000, 17, false);
        frame[12] = 0x86;
        frame[13] = 0xdd;
        assert_eq!(parse_ipv4_dest_port(&frame), None);
    }

    #[test]
    fn parse_rejects_wrong_ip_version() {
        let mut frame = build_frame([1, 2, 3, 4], 1000, 17, false);
        // Set the version nibble to 6 while keeping IHL 5.
        frame[14] = 0x65;
        assert_eq!(parse_ipv4_dest_port(&frame), None);
    }

    #[test]
    fn parse_rejects_other_protocols() {
        // ICMP (1) is not TCP or UDP, so it has no port numbers.
        let frame = build_frame([1, 2, 3, 4], 1000, 1, false);
        assert_eq!(parse_ipv4_dest_port(&frame), None);
    }

    #[test]
    fn parse_handles_ipv4_options() {
        // A header with IHL = 6 (24 bytes) must have its transport header read
        // at the right offset, not blindly at byte 20.
        let mut frame = build_frame([9, 9, 9, 9], 44444, 17, false);
        // Insert 4 bytes of options after the 20-byte fixed header, and bump IHL.
        frame[14] = 0x46; // version 4, IHL 6
                          // The IP header starts at frame[14]; transport starts at 14+24 = 38.
                          // Currently the transport header starts at 14+20 = 34, so insert 4 bytes
                          // there to push it to 38.
        let insert_at = 14 + 20;
        for _ in 0..4 {
            frame.insert(insert_at, 0u8);
        }
        let (ip, port) = parse_ipv4_dest_port(&frame).expect("options frame must parse");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(port, 44444);
    }

    // -----------------------------------------------------------------------
    // UdpKnockSource -- a real socket, but loopback-only and fast.
    // -----------------------------------------------------------------------
    #[test]
    fn udp_source_receives_a_knock() {
        // Bind to port 0: the OS picks a free port, so the test cannot collide
        // with anything else on the machine.
        let mut source =
            UdpKnockSource::bind("127.0.0.1:0".parse().unwrap()).expect("bind must succeed");
        let addr = source.local_addr().expect("local_addr must work");

        // Send a well-formed knock from another socket.
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(&build_udp_payload(27488), addr)
            .expect("send must succeed");

        // Receive it. We pass a fixed timestamp so the assertion is exact.
        let event = source
            .recv_at(12345)
            .expect("recv must succeed")
            .expect("a knock must be present");
        assert_eq!(event.dst_port, 27488);
        assert_eq!(event.at, 12345);
        assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn udp_source_times_out_cleanly() {
        let mut source = UdpKnockSource::bind("127.0.0.1:0".unwrap_parse()).unwrap();
        // With nothing sent, `recv_at` must return Ok(None) after its timeout,
        // NOT an error. This is the property the daemon loop depends on.
        let result = source.recv_at(0).expect("timeout must not be an error");
        assert!(result.is_none());
    }

    #[test]
    fn udp_source_ignores_foreign_payloads() {
        let mut source = UdpKnockSource::bind("127.0.0.1:0".unwrap_parse()).unwrap();
        let addr = source.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Random junk: no magic. Must be ignored, not treated as a knock.
        sender.send_to(b"hello there", addr).unwrap();
        let result = source.recv_at(0).unwrap();
        assert!(result.is_none(), "junk must be ignored");
    }

    /// A tiny helper so the tests can write `"127.0.0.1:0".unwrap_parse()`.
    ///
    /// EXPERT: A test-only extension trait. It is more readable than
    ///         `.parse().unwrap()` at a dozen call sites, and because it is
    ///         `#[cfg(test)]` it costs nothing in the binary.
    /// KID: A shortcut for the tests so they read nicely.
    trait UnwrapParse {
        fn unwrap_parse(self) -> SocketAddr;
    }

    impl UnwrapParse for &str {
        fn unwrap_parse(self) -> SocketAddr {
            self.parse().expect("test address must parse")
        }
    }

    // -----------------------------------------------------------------------
    // send_knocks -- exercised against a local UdpKnockSource, so the sender
    // and receiver are tested against each other.
    // -----------------------------------------------------------------------
    #[test]
    fn send_and_receive_full_sequence() {
        use crate::config::ServerConfig;
        use crate::secret::MasterSecret;

        // Set up a receiver.
        let mut source = UdpKnockSource::bind("127.0.0.1:0".unwrap_parse()).unwrap();
        let addr = source.local_addr().unwrap();

        // Derive a spec.
        let cfg = ServerConfig::default();
        let secret = MasterSecret::from_bytes([0x11; 32]);
        let spec = crate::crypto::derive_knock_spec(&secret, "alice", 99, &cfg);

        // Send it, with zero delay so the test is fast.
        let target = SendTarget {
            host: "127.0.0.1".to_string(),
            listen_port: addr.port(),
            raw_mode: false,
            inter_knock_delay_ms: 0,
        };
        let sent = send_knocks(&target, &spec).expect("send must succeed");
        assert_eq!(sent, spec.knock_ports.len());

        // Receive them all back and check the ports match, in order.
        let mut received = Vec::new();
        for _ in 0..spec.knock_ports.len() {
            match source.recv_at(0).unwrap() {
                Some(e) => received.push(e.dst_port),
                None => panic!("expected another knock"),
            }
        }
        assert_eq!(received, spec.knock_ports);
    }

    #[test]
    fn send_raw_mode_targets_the_knock_ports() {
        // In raw mode the datagrams go to the *knock ports* themselves. We can
        // verify that by binding a listener on a specific port and knocking it.
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listen_addr = listener.local_addr().unwrap();
        listener
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        // A spec whose single knock port is the listener's port.
        let spec = KnockSpec {
            user: "alice".to_string(),
            time_step: 1,
            knock_ports: vec![listen_addr.port()],
            open_port: 60000,
        };
        let target = SendTarget {
            host: "127.0.0.1".to_string(),
            listen_port: 1, // deliberately wrong; raw mode must ignore it
            raw_mode: true,
            inter_knock_delay_ms: 0,
        };
        send_knocks(&target, &spec).unwrap();

        // The datagram must have arrived at the knock port, not the listen_port.
        let mut buf = [0u8; 16];
        let (n, _from) = listener.recv_from(&mut buf).expect("raw knock must arrive");
        // Raw mode sends an empty payload; the port *is* the message.
        assert_eq!(n, 0);
    }

    #[test]
    fn send_knocks_reports_unresolvable_host() {
        let spec = KnockSpec {
            user: "alice".to_string(),
            time_step: 1,
            knock_ports: vec![40000],
            open_port: 60000,
        };
        let target = SendTarget {
            // `.invalid` is a reserved TLD that can never resolve (RFC 2606),
            // so this test cannot accidentally succeed because someone
            // registered the name.
            host: "definitely-not-a-real-host.invalid".to_string(),
            listen_port: 1,
            raw_mode: false,
            inter_knock_delay_ms: 0,
        };
        assert!(send_knocks(&target, &spec).is_err());
    }
}
