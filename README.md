# otkp — One Time Knock Protocol

**A time-based, one-time port-knock sequence that opens exactly one port, for
exactly one authorised user, for a short window — and instantly bans anyone who
knocks wrong even once.**

`otkp` takes the two ideas that already protect you everywhere else and fuses
them:

| Idea | What it normally protects | What we borrow from it |
|---|---|---|
| **One-Time Password (OTP/HOTP/TOTP)** | Your login (Google Authenticator, Authy, 1Password…) | A secret + a clock → a value that changes every 30 s and can never be reused |
| **Port knocking (`knockd`)** | A hidden SSH/backup port | A *sequence* of connection attempts that a daemon watches for, and only then opens a firewall hole |

Instead of a 6-digit number, `otkp` derives a **one-time sequence of port
numbers** *and* the **one-time destination port** that sequence unlocks. Nothing
is open by default. There is no listening service to scan, no password to
brute-force, and a single wrong knock gets you firewalled off.

---

## 1. Why this exists (threat model)

| Threat | Normal firewall / SSH | With `otkp` |
|---|---|---|
| Port scan finds your SSH | Port shows `open` | No port is open; scanner sees nothing |
| Attacker brute-forces the login | Endless attempts allowed | They can't even reach the port |
| Someone replays yesterday's knock | n/a | Sequences are time-based and single-use; yesterday's is dead |
| Someone shoulder-surfs one sequence | n/a | That sequence is already burned; the next one is unrelated |
| Attacker probes many ports looking for the "knock door" | n/a | First wrong knock → IP is banned |
| You want to reach a service from a café | Open port to the world | Port opens only for *your* IP, only for 30 s |

**Non-goals / honest limitations** are listed in [§8](#8-security-notes--limitations).
Read that section before trusting this with anything important.

---

## 2. The big picture (top-down)

Read this top to bottom — this is *top-down design*: the whole machine first,
the parts second, the lines of code last.

```
                    ┌──────────────────────────────────────────────────────┐
                    │  ONE SHARED SECRET PER USER (256 random bits)        │
                    │  given out once, out-of-band, at enrolment time      │
                    └───────────────┬──────────────────┬───────────────────┘
                                    │                  │
                 ┌──────────────────┴───┐          ┌───┴────────────────────┐
                 │  CLIENT              │          │  SERVER (otkp daemon)  │
                 │  `otkp knock`        │          │  `otkp serve`          │
                 └──────────────────────┘          └────────────────────────┘
                            │                                   │
   "What is the sequence   │                                   │  "What sequence
    for RIGHT NOW?"        │                                   │   SHOULD I see
                            ▼                                   ▼   right now?"
                 ┌──────────────────────┐          ┌──────────────────────────┐
                 │ HMAC-SHA256(secret,  │          │ HMAC-SHA256(secret,      │
                 │   user ∥ time_step)  │          │   user ∥ time_step)      │
                 └──────────┬───────────┘          └───────────┬──────────────┘
                            │                                  │
                            ▼                                  ▼
                 ┌──────────────────────┐          ┌──────────────────────────┐
                 │  KnockSpec           │          │  KnockSpec (recomputed   │
                 │   • ports: [a,b,c,d] │          │   for every user, every  │
                 │   • open_port: P     │          │   ±1 time step)          │
                 └──────────┬───────────┘          └───────────┬──────────────┘
                            │                                  │
        send a,b,c,d        │                                  │  watch every
        (in order, fast)    │                                  │  inbound packet
                            ▼                                  ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  THE WIRE                                                  │
                 │   client ──► knock a ──► knock b ──► knock c ──► knock d ──► │
                 └────────────────────────────┬───────────────────────────────┘
                                              │
                                              ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  STATE MACHINE (per source IP)                             │
                 │   matches a,b,c,d against every (user, time-step) candidate │
                 │   • all four in order  ──►  AUTHORISE  ──►  open port P     │
                 │   • any packet wrong   ──►  BAN the IP immediately          │
                 └────────────────────────────┬───────────────────────────────┘
                                              │
                                              ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  FIREWALL BACKEND (pluggable)                              │
                 │   iptables │ nftables │ custom command │ dry-run (log only) │
                 └────────────────────────────────────────────────────────────┘
```

### The four moving parts

1. **Secret** — 32 random bytes per user, created by `otkp enroll`, stored in the
   server's keyring and printed once as a base32 string for the user's client.
2. **Derivation** — `HMAC-SHA256(secret, "otkp-knock-v1" ‖ user_id ‖ time_step)`
   produces a 32-byte blob. From that blob we read out *how many* knocks, *which*
   ports, and *which* port to open. Deterministic, so client and server agree
   without talking.
3. **State machine** — the server watches inbound packets and keeps, per source
   IP, a scoreboard of "how far along is this IP in each possible sequence".
   Complete a sequence → open the port. Deviate → ban.
4. **Firewall backend** — the thing that actually opens/closes/blocks. It is a
   *trait* (an interface), so the daemon doesn't care whether it's talking to
   `iptables`, `nft`, a custom script, or a dry-run logger.

---

## 3. How a knock works, step by step

Say it's `2026-10-05T14:09:00Z`, so the Unix time is `1_759_678_140`.
With a 30-second step, the time step is `1_759_678_140 / 30 = 58_655_938`.

**On the client:**

```
$ otkp knock --server vps.example.com --port 62201 --user alice --secret JBSWY3DPEHPK3PXP...
[otkp] time step      : 58655938 (t+0s into the window)
[otkp] derived knocks : 41231, 58802, 19904, 33710
[otkp] will open port : 27488
[otkp] sending 4 knocks to vps.example.com:62201 ...
[otkp] done. You now have ~30s to connect to vps.example.com:27488
```

**On the server, `otkp serve` is doing this every time a packet arrives:**

1. Is the source IP already banned? → drop, say nothing.
2. Is it already authorised? → drop, say nothing.
3. For every enrolled user and every time step in `{now-1, now, now+1}`
   (the ±1 is clock-skew tolerance), recompute the expected sequence.
4. Does this packet's port match the *next expected* port of any candidate?
   - **Yes** → advance that candidate by one.
   - **No candidate matched** → that is a *failed knock*: increment the IP's
     failure count and, at the threshold (default **1**), ban it.
5. If a candidate reaches the end of its sequence → open `open_port` for that IP
   for `open_ttl_seconds`, and log it.

Then a sweeper thread closes the port again when the window expires.

---

## 4. Build & install

Requires a Rust toolchain (`rustup`, stable ≥ 1.74).

```bash
git clone <this repo> otkp && cd otkp
cargo build --release
# the binary lands at ./target/release/otkp
```

Run the test suite (unit + integration + protocol vectors):

```bash
cargo test
```

---

## 5. Quick start

### 5.1 On the server — create the config and the first user

```bash
sudo ./target/release/otkp init --dir /etc/otkp
sudo ./target/release/otkp enroll --dir /etc/otkp --user alice
```

`enroll` prints (once!) something like:

```
============================================================
  Enrolment created for user 'alice'
============================================================
  Secret (base32) : JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
  Current HOTP    : 492051   (for reference only — not used to knock)
  Knock listener  : 0.0.0.0:62201
  Enrolment URI   : otkp://alice?secret=JBSWY...&server=vps.example.com:62201&step=30
============================================================
  Give this to alice ONCE, over a channel you trust.
  The server keeps only its own copy in keyring.json.
============================================================
```

### 5.2 On the server — start the daemon

```bash
# Safe first run: log what WOULD happen, touch no firewall rules.
sudo ./target/release/otkp serve --dir /etc/otkp --firewall dry-run

# Real run with iptables:
sudo ./target/release/otkp serve --dir /etc/otkp --firewall iptables
```

### 5.3 On the client — knock, then connect

```bash
otkp knock --server vps.example.com --port 62201 \
           --user alice --secret JBSWY3DPEHPK3PXP...
# then, within the window:
ssh -p 27488 alice@vps.example.com
```

### 5.4 Sanity-check the derivation without touching the network

```bash
# On the server, see exactly what alice's sequence is right now:
sudo otkp verify --dir /etc/otkp --user alice
```

---

## 6. Command reference

| Command | Where | What it does |
|---|---|---|
| `otkp init --dir DIR` | server | Writes `config.json`, empty `keyring.json`, empty `banlist.json` |
| `otkp enroll --dir DIR --user NAME` | server | Creates a per-user secret and prints the one-time enrolment URI |
| `otkp serve --dir DIR` | server | Runs the daemon: listens for knocks, opens/closes ports, bans failures |
| `otkp verify --dir DIR --user NAME` | server | Prints the current (and neighbouring) knock sequence, for debugging |
| `otkp knock --server H --port P --user U --secret S` | client | Derives the sequence for *now* and sends it |
| `otkp help` | both | Usage |

Useful flags:

| Flag | Applies to | Meaning |
|---|---|---|
| `--firewall dry-run\|iptables\|nftables\|command` | `serve` | Which backend to drive |
| `--source udp\|raw` | `serve` | How knocks are observed (see §7) |
| `--step-offset -1\|0\|1` | `knock` | Try the previous/next time step if your clock is off |
| `--mode udp\|raw` | `knock` | How knocks are *sent* (must match the server's `--source`) |
| `--ban-threshold N` | `serve` | Failures before a ban (default `1`, i.e. ban on first failure) |
| `--open-ttl SECS` | `serve` | How long an opened port stays open |
| `--ban-ttl SECS` | `serve` | `0` = permanent ban |

---

## 7. Two ways to watch for knocks (`--source`)

The classic `knockd` design sniffs raw packets, because the whole point is that
the knocked-on ports are **closed** — nothing is listening. That needs
`CAP_NET_RAW`/root, so `otkp` offers both:

| `--source` | How it works | Needs root? | Use it for |
|---|---|---|---|
| `raw` | `AF_PACKET` socket captures every IPv4 packet and reads the destination port out of the TCP/UDP header. True port knocking: knock any closed port. | yes | Production |
| `udp` | A single UDP socket listens on `listen_addr`; the client sends tiny datagrams whose payload carries the intended port number. | no | Development, tests, containers, CI |

Both feed the **exact same** state machine and derivation code — only the
`KnockSource` implementation differs. That is the point of programming against a
trait: the interesting logic is written once and tested once.

---

## 8. Security notes & limitations

**What it gets right**

- The secret never crosses the wire. Only *derived* values do.
- Sequences are single-use in practice: they're bound to a 30-second time step.
- Nothing listens on the protected port until an authorised knock completes.
- Constant-time-ish comparison is not needed here (we compare derived port
  numbers that are already one-time), but we do compare HMACs with `==` only on
  values that never leave the machine.
- Secrets are zeroised on drop.

**What you must know before trusting it**

- **`ban_threshold = 1` is deliberately aggressive.** Any packet to a knock-range
  port that doesn't fit a live sequence bans that IP. On a busy host, innocent
  scanners will populate the ban list. Keep `--ban-ttl` finite, or whitelist your
  management IPs, or raise the threshold. This is a real operational trade-off,
  not a bug.
- **The client and server clocks must agree** to within ±1 time step. Use NTP.
- **The knock sequence is low-entropy.** Ports are drawn from the configured
  range, so an attacker who can observe the wire can replay *within the same
  time step*. Mitigation: don't knock over a channel an attacker can sniff, and
  keep the time step short. A future version will add an HMAC-carrying knock
  payload for `udp` mode (see roadmap).
- **The protected service must be bound to the opened port and must still
  authenticate you itself.** `otkp` is a *second* lock, not a replacement for
  SSH keys or application auth.
- **This is v0.1.0.** It has not been audited. Do not put it in front of anything
  whose loss would ruin your week.

---

## 9. Architecture (top-down module map)

```
src/
├── main.rs          ← the thinnest possible shell: parse argv, call the CLI
├── lib.rs           ← the library's front door: declares modules, re-exports
├── error.rs         ← OtkpError + Result<T> alias (one error type for the lib)
├── logging.rs       ← a tiny dependency-free timestamped logger
├── secret.rs        ← MasterSecret (zeroising 32 bytes) + base32/hex codecs
├── config.rs        ← ServerConfig / ClientConfig / FirewallConfig (serde)
├── keyring.rs       ← Enrollment + Keyring: who is allowed, and their secrets
├── crypto.rs        ← HMAC-SHA256, HOTP (the OTP heritage), and KnockSpec
├── engine.rs        ← the state machine: observe(packet) → Outcome  ★ the core
├── auth.rs          ← who currently has an open port, and until when
├── banlist.rs       ← banned IPs, optionally persistent, optionally expiring
├── firewall.rs      ← `trait Firewall` + iptables/nftables/command/dry-run
├── net.rs           ← `trait KnockSource` + UDP listener + AF_PACKET sniffer
├── daemon.rs        ← wires a KnockSource to the Engine, plus the sweeper
└── cli/
    ├── mod.rs       ← argument parsing (no external crate) + dispatch
    ├── init.rs      ← `otkp init`
    ├── enroll.rs    ← `otkp enroll`
    ├── knock.rs     ← `otkp knock`   (the client)
    ├── serve.rs     ← `otkp serve`   (the daemon launcher)
    └── verify.rs    ← `otkp verify`  (debug: print the current sequence)
```

**Design style used throughout**

- **Top-down.** Every file opens with a `//!` module doc that says *what this
  part is for* in plain language, then drills into details. `main.rs` is the
  highest level; `crypto.rs` is the lowest.
- **Object-oriented, the Rust way.** Data + behaviour live together in `struct`s
  with `impl` blocks; fields are private and reached through methods
  (encapsulation). Variation is expressed with **traits** (`Firewall`,
  `KnockSource`, `Clock`) instead of class hierarchies (polymorphism).
  Composition beats inheritance: `Engine` *has a* `Keyring`, *has a* `Firewall`.
- **Commentary for two audiences.** Nearly every item carries an `EXPERT:` note
  and a `KID:` analogy. That is not decoration — writing the kid version is how
  you discover you didn't actually understand the expert version.

---

## 10. Roadmap

Ordered by what actually closes the largest security gap first, not by what is
easiest. Items marked **[planned path]** are the agreed design direction; the
reasoning for each is recorded so a future reader does not have to re-derive it.

### Security gaps, in priority order

- [ ] **Fix the spoofed-source ban (critical).** `ban_threshold = 1` currently
  lets an off-path attacker ban an arbitrary address by sending one packet with
  a spoofed source. Fix: require a MAC-valid attempt (or at least some correct
  progress) before a failure may count toward a ban. *This is the one real flaw
  in the current design; everything else is hardening.*
- [ ] **Bind the sequence to the source address (high).** Include `src_ip` in the
  HMAC input, so a replay from a different address derives a different sequence
  and matches nothing. This defeats both passive replay *and* the active race
  (see the burn, below). Cost: breaks NAT and mobility, because the client must
  know the egress address the server sees. Popeea et al. (2011) list client IP as
  a sequence input, so this is a correct, known fix rather than a new idea.
- [ ] **[planned path] Single-use sequences — the "burn" (high).** Once a
  `(user, time_step)` sequence has authorised anyone, mark it used and never
  accept it again for the rest of its window. This is the standard replay cache
  (Kerberos; fwknop tracks SPA digests the same way) and it is purely
  server-side: no protocol, client or payload change.
  - Keying the burn per `(user, step, src_ip)` is a trap: it gives *no* replay
    protection, because an attacker replaying from their own address finds an
    unburned entry. Burn per `(user, step)` and bind to `src_ip` in the
    derivation instead — then per-IP burns are safe, because each address has its
    own sequence anyway and multi-device keeps working.
  - Costs, all real: in-memory state that a restart forgets; a rollback on
    firewall failure must *un*-burn or the user is locked out for the window; and
    one knock per window per user unless combined with the `src_ip` binding.
  - Note what it does *not* buy: an on-path attacker can inject or drop packets
    and win the race. The burn narrows replay to "attacker must beat Alice",
    which is a real narrowing but not replay resistance. The `src_ip` binding is
    what removes the race.
- [ ] **[planned path] HMAC-authenticated knock payload (high).** `AF_PACKET`
  captures the whole frame including the UDP payload, so a `raw`-mode knock *can*
  carry a MAC. (An earlier note in this file wrongly claimed headers-only; the
  limitation is a definitional one inherited from `knockd`, not a technical one.
  This is precisely why fwknop left header-based knocking behind and invented
  SPA.) Payload: `HMAC(secret, user ‖ step ‖ src_ip ‖ nonce) ‖ nonce`. The
  `src_ip` binding means a replay from another address fails the MAC outright.
  Cost: per-user anti-replay memory that must survive restarts, or it desyncs.
- [ ] **Detection: three alerts (medium).** With the burn and the authorising-IP
  log in place, the daemon becomes a *sensor*, which is arguably its most
  valuable property — it is the only component that can tell you an on-path
  adversary exists.
  1. Burned sequence reused → an on-path observer is present.
  2. Same user authorised from two IPs in one window → relay or key compromise.
  3. Authorised IP outside the user's known set → key compromise or stolen
     credential.
  - **A replayed sequence is NOT evidence of key compromise.** An observer
    captures ports, not the key; HMAC is one-way, so they cannot compute the next
    window. Key compromise shows up as *fresh* sequences from an unexpected IP,
    never as a replay. Do not rotate the key in response to alert 1 — that leaves
    the actual problem (someone reading your traffic) untouched.
- [ ] **Correlate with the service's own logs (medium).** "Port opened" plus
  "service authentication failed from that same IP" is a strong forged-knock
  signal. The daemon cannot see this alone — it opens a hole and its knowledge
  ends there — so it needs the two log sources joined outside the daemon.

### Features and packaging

- [ ] Multi-port open (open a *set* of services per user).
- [ ] Key rotation and per-user revocation with a generation counter. (Bounds the
  blast radius of a leaked key and enables revocation. Note it does **not** help
  with replay: a replay happens inside one rotation period exactly as it happens
  inside one time step.)
- [ ] `--source raw` support for IPv6.
- [ ] Prometheus metrics endpoint (loopback-only).
- [ ] systemd unit + `CAP_NET_RAW`/`CAP_NET_ADMIN` drop-in hardening.
- [ ] Fuzzing (`cargo-fuzz`) on `parse_ipv4_dest_port` and the payload codec, plus
  a MIRI run over the test suite to check the `unsafe` in `net.rs`.
- [ ] Formal verification: the engine is already a pure function, so Kani could
  prove authorisation soundness, ban-policy safety and bounded state.

### Documentation

- [ ] An honest comparison against fwknop/SPA, including when *not* to use OTKP.
  A portfolio artifact that knows its own replacement reads as senior.

---

## 11. What this does and does not protect against

Stated plainly, because a security tool that oversells itself is worse than one
that is merely weak.

**It does:** hide the protected service from scanners (no port answers), make a
captured knock a short-lived one-shot credential rather than a permanent one, and
give you a sensor for on-path observers.

**It does not:** stop a determined on-path attacker from racing a replay (until
the `src_ip` binding lands), replace the protected service's own authentication,
or protect you if the secret leaks *and* the attacker is at a network position
you trust.

**It is not a substitute for the service's authentication.** The knock opens a
door; the service still asks for ID. That layering is the point — a knock-secret
compromise is survivable precisely because sshd (or whatever is behind the port)
asks for something the attacker does not have.

---

## License

Dual-licensed under either of **MIT** or **Apache-2.0**, at your option — the
standard Rust convention.
