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

## 5. Why not a blockchain

A blockchain is a **hash chain plus distributed consensus**. The hash chain gives
tamper-evidence; the consensus gives agreement among parties who do not trust
each other.

- **If you control who may write** ("only authorised parties validate"), you have
  removed the consensus. There is nothing to agree on. What remains is a hash
  chain — a *data structure*, implementable in fifty lines over any database.
- **If you need agreement among mutually distrusting organisations**, that is a
  consortium, and it begins as an organisational agreement — governance,
  membership, liability, dispute resolution. No code bootstraps it.
- **If the goal is auditability**, a transparency log (§3.3) gives strictly more:
  tamper-evidence plus cryptographic proofs, without consensus, mining, or a
  chain, and orders of magnitude faster.

**And never put the authorization decision behind a chain read.** Two concrete
reasons, both fatal to an access-control gate:

- **Availability.** If the chain is unreachable, partitioned, or rate-limiting
  you, nobody authenticates. Every such design eventually has that outage.
- **Reorganisations.** A chain can retroactively drop a block. An authorisation
  you already acted on can become "not on the chain" after the fact — you granted
  access based on a fact that later stopped being true.

A public chain also publishes your access patterns permanently and correlatably.
That is the opposite of what a concealment layer is for.

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
| Concealment | The knock protocol (separate) | — |

Three rules, if you remember nothing else:

1. Verify locally. Never gate authorisation on a network round-trip.
2. Display semantics. A hash the user cannot read is not a control.
3. Separate keys per purpose. One seed, many derived keys — never one key, many
   purposes.
