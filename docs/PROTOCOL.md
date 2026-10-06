# The `otkp` wire protocol (v1)

This document is the *normative* description of what goes on the wire and how the
two sides derive the same numbers. If the code and this document disagree, the
document is wrong -- but please fix one of them.

EXPERT: This is a specification document. It is written so that a second,
independent implementation (in Go, Python, whatever) could interoperate with
ours. That is the real test of whether a protocol is understood.
KID: This is the rulebook of a secret handshake. Anyone who follows these rules
exactly will be let in; anyone who improvises gets caught.

---

## 1. Vocabulary

| Term | Type | Meaning |
|---|---|---|
| `secret` | 32 bytes | Per-user random key. Never transmitted. |
| `user_id` | UTF-8 string | Stable name of the user, e.g. `alice`. |
| `step_seconds` | integer | Length of one time window. Default **30**. |
| `time_step` | integer | `floor(unix_time_seconds / step_seconds)`. |
| `knock_ports` | list of `u16` | The ordered sequence to send. Length 3..5 by default. |
| `open_port` | `u16` | The port the daemon opens for that IP on success. |

---

## 2. The keyed function

Everything is derived from one HMAC-SHA256 call:

```
digest = HMAC-SHA256(
    key  = secret,
    msg  = "otkp-knock-v1"        // 13 ASCII bytes: the domain-separation label
         || 0x00                   // 1 byte NUL: a separator, so
         || user_id_utf8           //   "alice"+"bob" cannot equal "aliceb"+"ob"
         || 0x00                   // 1 byte NUL
         || time_step_be64         // 8 bytes, big-endian
)
```

`digest` is 32 bytes. We read it as a stream of big-endian `u16` values, starting
at byte index **1** (byte 0 is reserved for the knock count).

### 2.1 Source-address binding (optional)

When `bind_to_source_ip` is enabled, the observed source address is appended to
the message and a *different* label is used:

```
digest = HMAC-SHA256(
    key  = secret,
    msg  = "otkp-knock-v1-ipbind"   // 19 ASCII bytes: the bound-variant label
         || 0x00
         || user_id_utf8
         || 0x00
         || time_step_be64
         || family_byte            // 4 for IPv4, 6 for IPv6
         || address_bytes          // 4 or 16 bytes, raw (network order)
)
```

Two consequences, both deliberate:

- **A sequence matches only when replayed from the same address.** An attacker
  who captures Alice's knock and replays it from their own address causes the
  server to derive the expectation for *their* address, which is a different
  sequence, so nothing matches. This defeats passive replay *and* the active race
  (injecting the captured packets before Alice's own arrive).
- **The label differs from the unbound variant.** A client and server that
  disagree about binding mode derive different sequences and fail loudly, rather
  than half-working. A client with binding off talking to a bound server simply
  never matches.

Cost, stated plainly: **binding breaks NAT and mobility.** The client must know
the address the server will observe, which behind NAT is not its local address.
The client therefore takes an explicit `--bind-ip <addr>`. This is why binding is
off by default.

The `family_byte` exists so an IPv4 address cannot collide with a prefix of an
IPv6 address; the realistic case is an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`),
which is a *different* input and therefore a different sequence.

EXPERT: Including `user_id` in the message is *domain separation* -- it guarantees
two users with the same secret (e.g. after a botched copy-paste) still get
different sequences, and it prevents cross-user confusion.
KID: We write the person's name on the envelope, so two people's letters can
never be swapped by accident.

---

## 3. Deriving the sequence

Let `digest[0..32]` be the bytes above. Define `be16(i)` as the big-endian
`u16` formed from `digest[i]` and `digest[i+1]`, and `map(v, lo, hi)` as
`lo + (v mod (hi - lo + 1))`.

```
count      = knock_count_min + (digest[0] mod (knock_count_max - knock_count_min + 1))
for i in 0..count:
    raw_i  = be16(1 + 2*i)
    port_i = map(raw_i, knock_port_min, knock_port_max)
    if i > 0 and port_i == port_{i-1}:        // avoid a repeated port
        port_i = port_{i-1} + 1  (wrapping to knock_port_min at the top)
open_port  = map(be16(1 + 2*count), open_port_min, open_port_max)
```

Bounds: byte 0 is the count, knock `i` uses bytes `1+2i` and `2+2i`, and the
open port uses bytes `1+2*count` and `2+2*count`. The highest byte index touched
is `2 + 2*count`, which must be `<= 31`; hence **`count <= 14`**. The default
config caps `knock_count_max` at 5 and the validator enforces the 14 limit.

EXPERT: Using a fixed HMAC output as a *key stream* and slicing `u16`s out of it
is the same trick as HOTP's dynamic truncation, just simpler because we need
several independent values rather than one 31-bit integer.
KID: The HMAC gives us a big bag of random-looking numbers. We reach in and pull
out one handful per knock, plus one extra for the door we open.

---

## 4. Sending the knocks

### 4.1 `udp` mode (development / containers)

The client sends `count` UDP datagrams, in order, to the daemon's listener
address. Each datagram's payload is:

```
offset  size  field
0       4     magic = "OTKP"  (0x4F 0x54 0x4B 0x50)
4       2     intended destination port, big-endian u16
------  ----
total   6 bytes
```

The daemon treats the *payload's* port as if it had been the real destination
port of the packet. This lets the whole protocol be exercised without root.

EXPERT: This is a deliberate testing seam. It keeps `--source udp` and
`--source raw` feeding identical `KnockEvent`s into identical logic.
KID: Instead of knocking on different doors, we slip a note under one door that
says "pretend I knocked on door number 41231".

### 4.2 `raw` mode (production)

The client sends `count` ordinary UDP datagrams to
`server:port_0`, `server:port_1`, ... `server:port_count-1` -- real ports, which
are **closed**, because nothing is listening. The daemon's `AF_PACKET` socket sees
the packets go by and reads the destination port straight out of the IPv4/UDP
header. Nothing needs to be listening for this to work.

EXPERT: Using UDP rather than TCP avoids leaving half-open connections in the
server's conntrack table and avoids the client blocking on SYN retries. The
knock is fire-and-forget; the client learns success by *connecting to the opened
port*, not by an acknowledgement.
KID: You tap on the wall three times. Nobody answers the tap -- but the person
inside hears it and unlocks the front door.

### 4.3 Timing

The client sends knocks back-to-back with a small delay (`inter_knock_delay_ms`,
default 80 ms) so that ordering is preserved and the server's per-IP state is not
confused by reordering. The whole sequence must fit inside one `step_seconds`
window.

---

## 5. Server-side matching (the state machine)

For each source IP the daemon keeps:

```
candidates:  map (user_id, time_step) -> matched_so_far   (integer)
failures:    integer
last_seen:   unix time
```

On every observed packet `(src_ip, dst_port)`:

1. If `dst_port` is outside the configured knock range -> **ignore** (and do NOT
   count it as a failure; otherwise a port scan would ban the whole internet).
2. If `src_ip` is banned -> ignore.
3. If `src_ip` currently has an open port -> ignore.
4. Let `now_step = floor(now / step_seconds)`.
   Candidate steps are `now_step - skew ..= now_step + skew` (default `skew = 1`).
   Prune candidates whose `time_step` is outside that range.
5. For each enrolled user `u` and each candidate step `s`, compute the spec and
   look up `done = candidates[(u,s)]` (default 0).
   If `done < len(knock_ports)` and `knock_ports[done] == dst_port`, then
   `candidates[(u,s)] = done + 1`. If that reaches `len(knock_ports)`, the
   sequence is **complete**.
6. If exactly one sequence completed -> authorise `src_ip` for `open_port`, open
   it in the firewall for `open_ttl_seconds`, clear that IP's candidates, done.
7. Else if at least one candidate advanced -> log progress, wait for more packets.
8. Else (nothing matched) -> record the failure time; let
   `failures_in_window` be the number of recorded failures no older than
   `ban_window_seconds`. If `failures_in_window >= ban_fail_threshold`, ban
   `src_ip` and clear its state.

   The window is *rolling*: the count is always "failures in the last
   `ban_window_seconds` seconds", so an attacker cannot time bursts around a
   periodic reset. Failures older than the window are forgotten, which is what
   distinguishes this from a fixed-bucket counter.

EXPERT: Step 1 is the load-bearing one. Without it, step 8 would ban any host
that ever scanned a port. Step 8's rate limit is the second load-bearing one:
with a one-strike rule, an attacker could get *your* address banned by sending a
single spoofed packet to a knock-range port. N failures per rolling window makes
that attack expensive, though not yet impossible (see the README roadmap).
KID: If you tap the wrong number of times, the guard crosses your name off the
guest list before you get a second try. But he only listens to taps on the secret
doors, not to people knocking on the front door for normal reasons.

---

## 6. Failure, expiry and cleanup

- **Open window** -- an opened port is closed again after `open_ttl_seconds`
  (default 30). A sweeper runs on every idle loop iteration.
- **Ban expiry** -- `ban_ttl_seconds = 0` means permanent. Otherwise bans lift
  after that many seconds, and the firewall rule is removed.
- **Persistence** -- the ban list is written to `banlist.json` so a daemon
  restart does not amnesty attackers, and `otkp serve` re-applies the persisted
  bans to the firewall at startup.

---

## 7. Test vectors

These vectors are asserted by `tests/protocol.rs`. If you change the derivation
and these tests still pass, you changed something that does not affect the wire
format. If they fail, you changed the wire format and must bump the label
`"otkp-knock-v1"` to `"otkp-knock-v2"`.

### HOTP compatibility vector (RFC 4226, Appendix D)

Secret = ASCII `"12345678901234567890"`, 6 digits:

| counter | HOTP |
|---|---|
| 0 | 755224 |
| 1 | 287082 |
| 2 | 359152 |
| 3 | 969429 |
| 4 | 338314 |

`otkp enroll` prints the current HOTP purely so the secret can be sanity-checked
against any standard authenticator app before you rely on the knock derivation.

### HMAC-SHA256 vector (RFC 4231, test case 1)

Key = 20 bytes of `0x0b`, message = `"Hi There"`:

```
b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
```
