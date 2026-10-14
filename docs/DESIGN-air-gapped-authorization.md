# Design note: air-gapped authorization

**Status:** design note, not implemented. Covers a component that is *separate*
from the knock daemon in this repository.

**Scope.** This note describes how to authorise access using a key that never
touches a networked machine, and how to record that authorisation so it can be
audited. It is deliberately *not* about the knock protocol in `src/` — that
protocol's secret must live on an online client, or the client cannot knock.
These are two different keys with two different purposes, and they must stay
separate (see §6).

---

## 1. What the air gap buys, stated precisely

An air gap protects **key confidentiality**. A signing key that never touches a
networked machine cannot be exfiltrated by remote malware. That is a real and
valuable property, and it is why HSMs, offline root CAs, and hardware wallets
exist.

It does **not** protect **system integrity**. An attacker who owns your online
host still owns your online host. They cannot steal the key, but they can use
the system, submit their own requests, replay old ones, or refuse service. The
air gap hardens one asset; it does not shrink the perimeter.

Conflating those two is the most common mistake in this design space, so keep
them apart:

| Property | Air gap helps? |
|---|---|
| Remote attacker cannot steal the signing key | **Yes, fully** |
| Remote attacker cannot *use* the system | No |
| Authorisation cannot be forged without the key | Yes |
| The online host cannot trick the user into signing something else | **No — see §4** |

---

## 2. Threat model

Assume:

- **The online host is hostile or already compromised.** Design as if it is lost.
  This is the whole premise; if you cannot assume it, the air gap is unnecessary.
- **The offline device is trusted**, including its supply chain. If it was
  compromised before it reached you, nothing here helps.
- **The user can be deceived** but will read a display if it is unambiguous and
  they are not habituated to clicking through.
- **The transport between the two is observable** (QR codes are photographed,
  screens are filmed). Everything crossing it must be safe to publish.

Not assumed: that the network is safe, that the online host is honest, or that
the offline device is physically secure (that is a physical-security problem,
out of scope here).

---

## 3. The three components

```
┌──────────────────────┐         ┌───────────────────────┐        ┌──────────────────┐
│ OFFLINE SIGNER       │  QR /   │ VERIFIER              │        │ AUDIT LOG        │
│ (air-gapped)         │◄───────►│ (online, untrusted)   │───────►│ (append-only)    │
│                      │  camera │                       │  write │                  │
│ one seed, derived    │         │ verifies the token    │        │ Merkle tree,     │
│ subkeys per purpose  │         │ LOCALLY, no network   │        │ signed tree head │
└──────────────────────┘         └───────────────────────┘        └──────────────────┘
        ▲                                    ▲
        │ user reads the display             │ never in the
        │ and confirms the semantics         │ auth decision path
        └────────────────────────────────────┘
```

### 3.1 Offline signer

Holds one master seed. Derives **purpose-specific subkeys** — one hardened path
for access authorization, a different one for anything financial. Never the same
key bytes for two purposes; a weakness in one use must not reach the other.
BIP-32 does this for Bitcoin, SLIP-0010 generalises it, and any KDF with
domain separation achieves the same result.

What it signs is an **authorization token**, not a raw request:

```
AuthorizationToken {
    version:     1,
    subject:     "alice",            // who this authorises
    purpose:     "access:ssh",       // what it authorises; a closed vocabulary
    audience:    "host-42",          // which verifier must accept it
    not_before:  1791230000,         // validity window, not an instant
    not_after:   1791230300,
    nonce:       0x9f3c...           // unique; replay protection
}
```

Serialised canonically (a deterministic encoding — CBOR with a defined key
order, or a fixed field layout). Canonical serialisation is load-bearing: two
different byte strings for the same logical token means two different signatures,
and signature verification then depends on which encoder ran.

Signed with Ed25519. The output is `token || signature`, small enough for a QR
code (a few hundred bytes; a single QR at low error-correction holds ~1 KB).

**The display requirement is not optional.** The device must show the *semantic*
content — subject, purpose, audience, validity — not a hash and not a hex blob.
A human cannot verify a hash, so a hash-only display reduces the air gap to
theatre. This is the same reason hardware wallets show the destination address
and amount, and it is why blind signing is treated as dangerous.

### 3.2 Verifier

The online side. Given a token and the signer's public key:

1. Parse canonically. Reject anything that does not re-serialise to the same
   bytes.
2. Check the signature against the public key **for that purpose**.
3. Check `audience` matches this verifier. Without this, a token for host A is
   replayable against host B.
4. Check the clock is inside `[not_before, not_after]`.
5. Check the nonce has not been seen before, and record it. This is the only
   stateful step, and it is the one that makes the token single-use.
6. Only then authorise.

**Steps 1–6 are local.** No network call, no chain read, no consensus. The
verifier needs exactly one thing from outside: the public key, which is
configured once. This is why the design has no availability dependency and no
meaningful latency.

Replay protection requires per-subject state: a highest-seen counter, or a
window of recent nonces. That state must survive restarts or a restart re-permits
an old token. Persist it.

### 3.3 Audit log

An **append-only, tamper-evident log**, not a blockchain. See §5.

Purpose: answer "what was authorised, when, by whom, and can we prove the record
was not edited afterwards?" — including against ourselves. A Merkle tree with
signed tree heads and inclusion proofs (RFC 6962, the Certificate Transparency
construction) gives exactly that:

- **Append-only:** entries are leaves; you cannot rewrite a leaf without changing
  every subsequent hash.
- **Verifiable:** a client can hold an inclusion proof showing its own
  authorisation is in the log, without trusting the log operator.
- **Auditable:** signed tree heads let an observer detect a split view.

Google's Trillian implements this as a library; you do not need to write it.

**The log is never in the authorization decision path.** It records what the
verifier already decided. If the log is down, authorisation still works; you
queue the record.

---

## 4. The failure mode that decides whether any of this works

The online host constructs the request. The offline device signs it. So the
**compromised** machine chooses what gets signed, and the air gap is defeated
unless the human verifies the semantics on the offline device's own display.

Concretely: the attacker's payload says "authorise access to host-42" in the
field the online host displays, while the bytes actually signed say something
else. If the user scans and confirms without reading, they have signed whatever
the attacker wanted.

Three requirements follow, and none are optional:

1. **The offline device displays semantic content**, in words the user can check.
2. **The token is non-replayable** (nonce/counter, and `audience` + validity
   window). Otherwise an old signature is reused indefinitely.
3. **The online host is treated as hostile.** It is the attacker's foothold.

The security boundary here is a human reading a screen. That is a weaker
boundary than a cryptographic guarantee, and it degrades with habituation — a
user who signs ten times a day stops reading. Design for that: make the display
short, make the important field visually dominant, and make unusual requests
look unusual.

---

## 5. On using a ledger for authorisation

The shape under discussion pre-commits authorisations — "subject S may knock
during window W" — to a ledger, and the verifier accepts a knock only once the
authorising entry is confirmed.

Two of the usual objections do **not** apply to that shape, and it is worth
saying so plainly:

- **Latency.** Because the authorisation is *pre-committed*, the confirmation
  wait happens before access is needed, not at the moment of it. The knock's
  30-second window is therefore not in tension with block times. This is a real
  property of pre-commitment and it deserves credit.
- **Reorganisation.** Waiting for N confirmations before treating an entry as
  final is the standard mitigation and the correct one. An entry N blocks deep is
  not realistically reorged. "A certain time after the block is accepted" is
  exactly this, and it is the right answer.

Two things remain. They are not objections to the idea; they are decisions that
have to be made explicitly, because the design is ambiguous without them.

### 5.1 Either the verifier caches, or it has an availability dependency

There is no third option, and this is the crux:

- **If the verifier caches the authorisation locally**, then the ledger is a
  *distribution mechanism* for authorisations — it gets them from the signer to
  the verifier once. But a signed token does that job better: it is
  self-verifying, needs no ledger liveness, and needs no confirmation wait. The
  ledger would then be a slower, more complex transport for something a
  signature already provides.
- **If the verifier reads the ledger at knock time**, then ledger availability
  gates every access. An unreachable, partitioned, or rate-limiting ledger means
  nobody authenticates. Every design of this shape eventually has that outage.

Pick one and write down why. The common answer is "cache, and treat the ledger as
the record" — which is fine, but it means the ledger is an *audit* mechanism, not
an authorisation mechanism, and §3.3 is the relevant part.

### 5.2 If the ledger authorises, the knock stops authorising

If acceptance depends on an entry saying "S may knock during W", then the knock
secret is no longer what grants access — anyone could knock. The knock becomes
**concealment only**.

That is a legitimate architecture; concealment and authorisation are different
properties and separating them is often the right call. But it changes what the
knock is *for*, and it means the knock secret no longer needs to be secret.
Decide which of these you mean:

- **Knock authorises, ledger records.** The knock is the boundary; the ledger is
  audit. §3.3 applies, and a transparency log is the right tool.
- **Ledger authorises, knock conceals.** The ledger is the boundary and needs the
  §5.1 answer; the knock hides the port, and its secret can be published without
  weakening authorisation.

Having *both* authorise is two mechanisms for one job, with the weaker one still
in the path.

### 5.3 When a permissioned ledger is the right choice

A permissioned ledger earns its cost in exactly one situation: **several mutually
distrusting organisations must all write to one shared, ordered, tamper-evident
log, with no central operator.**

That is a consortium, and it is an organisational decision before it is a
technical one — governance, membership, liability, and dispute resolution all
have to exist first. No code bootstraps it. This is why permissioned ledgers in
the wild (trade finance, interbank settlement) all began as organisations that
added a ledger, not the reverse.

If a **single party** writes the authorisations, the consensus the ledger existed
to provide has been removed, and what remains is a hash chain: a data structure,
implementable over any database. A transparency log (RFC 6962; Trillian as a
library) gives tamper-evidence plus inclusion proofs without consensus, and is
orders of magnitude faster.

So the question to answer is not "chain or no chain" but: **who writes the
authorisations, and do they trust each other?**

### 5.4 If the ledger is public

A public ledger publishes every authorisation permanently and correlatably — who
may access what, and when, for all time. For a system whose point is concealment,
that is the opposite of the goal. It may still be a deliberate trade, but it
should be a deliberate one.


---

## 6. Why this must not share a key with the knock protocol

The knock protocol in this repository requires its secret on an **online** client
— otherwise the client cannot knock. An air-gapped signing key must never touch a
networked machine.

So they are not merely different keys by good practice; they are different by
construction. If you use one key for both:

- The online copy defeats the air gap entirely — the leak path is the networked
  machine, which is the one thing the air gap was protecting against.
- A compromise of the concealment layer reaches the authorisation layer. The
  cheap thing breaks the expensive thing.

If you want the ergonomics of "one key", use **one seed with derived subkeys**,
not one key with two purposes. Same device, same backup, different key bytes.

---

## 7. What this does not protect against

Stated plainly, because a control that oversells itself stops being monitored.

- **A compromised offline device**, including supply chain. Nothing here helps.
- **A user who does not read the display.** The confused deputy (§4). This is the
  most likely real-world failure.
- **Physical access to the offline device.** That is physical security.
- **An online host that is compromised.** It cannot forge authorisations, but it
  can deny service, replay within the validity window if nonces are mishandled,
  or deceive the user (§4). It is assumed lost.
- **Side channels.** Air gaps leak — Stuxnet crossed one via USB, and there is a
  body of research on acoustic, electromagnetic, thermal and optical
  exfiltration. Mostly low-bandwidth and lab-demonstrated, but real. An air gap
  raises cost; it does not seal.
- **Anything requiring fiat movement.** Converting crypto to cash is licensed
  activity — MSB registration and state money-transmitter licences (US), CASP
  authorisation under MiCA (EU), FCA registration (UK), plus AML programmes,
  transaction monitoring and sanctions screening. That is a compliance
  obligation, not a protocol feature, and no cryptographic design substitutes for
  it.

---

## 8. Summary

| Concern | Mechanism | Why not a chain |
|---|---|---|
| Key confidentiality | Air-gapped signer | — |
| Authorisation | Signed token, verified locally | Verification needs a public key, not a ledger |
| Replay protection | Nonce/counter + audience + window | — |
| Audit | Merkle transparency log | Tamper-evidence without consensus |
| Multi-party authorisation | Permissioned ledger — *only* if several mutually distrusting orgs all write (§5.3) | — |
| Concealment | The knock protocol (separate) | — |

Four rules, if you remember nothing else:

1. Decide the §5.1 question explicitly: does the verifier cache, or does it
   depend on the ledger being up? There is no third option.
2. Decide the §5.2 question explicitly: does the knock authorise, or only
   conceal? Two authorisers for one job means the weaker one is still in the path.
3. Display semantics. A hash the user cannot read is not a control.
4. Separate keys per purpose. One seed, many derived keys — never one key, many
   purposes.
