# Design note: a deception layer (future project)

**Status: future project note. Not part of `otkp`, and not implemented.**
This records the design, what is sound, what remains dangerous, and the
constraints that make the difference between a control and a liability.

---

## 1. The idea

Present services on the VPN interface that *announce* as known-vulnerable software.
Nothing is exploited and nothing is vulnerable — the banner is the whole of it.
The purpose is **detection, not entrapment**: when a decoy is touched, an attacker
is inside, and the credential in use at that moment belongs to a compromised
account.

This is a **tripwire**, and the distinction is the whole design:

| | Trap | Tripwire |
|---|---|---|
| Purpose | Catch and exploit | Detect |
| Runs vulnerable code | Yes | **No** |
| Legal exposure | Real | Low |
| If it fails | Attacker gains a foothold | You miss a signal |

This design is a tripwire. That is the right choice, and it removes the most
dangerous property of the naive version: running real known-CVE software as bait
means running a real CVE and building a real foothold.

---

## 2. What it buys: the detection gap, closed

§11.2 of the main README names a gap: *attribution is not detection.* Knowing whose
credential was used is not the same as knowing a credential has been compromised.

A tripwire closes that gap, and it is the strongest part of this design:

1. An attacker who has compromised a session explores the interface.
2. They touch a decoy.
3. The decoy records the event, **silently**.
4. The credential in use is known — so **the account is known**.
5. A separate responder revokes it.

That converts "something may have leaked" into "account X is compromised, now."
It is a capability the rest of this architecture does not otherwise have.

---

## 3. Provable synthetic data

Decoy data must be *provably* fake, for two audiences: the attacker (who must
believe it) and a regulator or auditor (who must be able to see that no real data
was ever at risk). Three mechanisms, and all three are needed.

**3.1 Cryptographic provenance.** Generate each decoy, hash it, and sign a
manifest of what was generated and when. Any file can then be proven to have come
from your generator, so "this is synthetic" becomes a verifiable statement rather
than an assertion. The generation manifest is an append-only log — the same shape
as the audit stream in `src/audit.rs`.

**3.2 Reserved namespaces — the part that makes it airtight.** Do not merely
*label* data synthetic; draw it from ranges that are structurally incapable of
being real:

| Field | Source |
|---|---|
| Domain names | `.example`, `.invalid`, `.test` (RFC 2606, RFC 6761) |
| IP addresses | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737) |
| Email | `@example.com` and reserved subdomains |
| Names / identifiers | Generated from patterns, never sampled from a real dataset |

This is the difference between "we say it's fake" and "it cannot be real." A
reviewer holding a decoy record sees documentation-range addresses and reserved
domains, and the question answers itself. Label-based synthetic data can
accidentally collide with a real person; reserved-namespace data cannot.

**3.3 Generation method: templates, not models.** A small language model generating
decoys is *your* per-token bill, in the same currency the design is trying to make
the attacker spend. Deterministic templates are:

- free per file, versus a model inference cost
- reproducible, so a regenerated decoy is byte-identical and therefore verifiable
- auditable, so a reviewer can read exactly what can be produced
- non-hallucinating, so they cannot accidentally emit a real identifier

The attacker cannot tell a templated record from a generated one — both read as
plausible data. So the model buys nothing and costs money.

---

## 4. What remains dangerous

**4.1 A banner-only decoy catches shallow scanners, not careful ones.** Modern
tooling fingerprints by *behaviour* — probe responses, timing, TLS quirks — not by
reading banners. A decoy that announces `OpenSSH 7.4` and then behaves like nothing
at all will be identified as a decoy by anyone competent. That is acceptable: the
tier it catches is the automated one, which is the tier that matters most. But do
not claim it catches a targeted attacker.

**4.2 Auto-revocation is a denial-of-service vector unless it is session-scoped.**
This is the same failure class as the one-strike ban that had to be fixed in
`7e98249`. If a decoy is reachable *before* authentication, an attacker can trip it
deliberately to cause revocations. The constraint: **a trip may only revoke the
credential of the session that tripped it.** Never a credential inferred from a
source address, and never a shared credential.

**4.3 The decoy must be silent.** If it reveals that it has been tripped — an error,
a delay, a disconnect — the attacker learns they have been detected and changes
behaviour. Record, do not react in-band.

**4.4 The responder must be separate.** Same principle as the rest of this
architecture: the daemon emits an event, separate software decides and acts. A
component that both detects and revokes is one whose compromise both blinds you and
revokes your users.

**4.5 Revocation latency is bounded by the window, not the trip.** With an
air-gapped CA (§5.5.2 of the authorisation note), revocation takes up to one
validity window. The trip gives you the signal immediately; the revocation is slow
by design. Do not build a responder that assumes otherwise.

**4.6 False positives have a cost.** A backup job, a configuration scanner, or a
curious administrator can touch a decoy. If the response is automatic revocation, a
legitimate user is locked out by their own monitoring. Either scope decoys so
legitimate tooling cannot reach them, or make the first trip an alert and a repeat
trip a revocation.

---

## 5. On the justification

"It harms criminals" is a *motive*, and a regulator does not evaluate motives. The
compliance case is mechanical, and it is the one to make:

> The data is generated by us, drawn exclusively from reserved namespaces, and
> cryptographically attested by a signed generation manifest. It is structurally
> incapable of being, or containing, real data. Here is the manifest, and here is
> the proof for the file you are holding.

That is a defensible position. "We wanted to waste the attacker's time" is not, on
its own.

One further point: decoy data served to someone who turns out *not* to be an
attacker is false data served to a legitimate party. The tripwire's value depends
on the decoy being somewhere only an intruder would go.

---

## 6. What to build, in order

1. **Tarpits on unused ports.** `endlessh`-style: announce, then never complete. No
   protocol, no parser, no exploitability, real cost to a scanner or an agent.
2. **Honeytokens where an attacker looks first** — a fake `.aws/credentials`, a fake
   `~/.ssh/id_rsa`, a fake `.env`. Alert on use.
3. **One or two banner decoys** inside the authenticated interface, scoped so
   legitimate tooling cannot reach them, silent on trip.
4. **A signed generation manifest** for any decoy data, with reserved-namespace
   sources and templated generation.
5. **A separate responder** that consumes trip events and revokes, with the
   session-scoping constraint of §4.2 enforced in code and asserted in a test.
6. **Measure it.** If the decoys do not measurably cost the attacker and cost you
   nothing, remove them. A deception layer that cannot be evaluated is decoration.

---

## 7. Scope

A **separate project** from `otkp`. OTKP conceals a port and authenticates a user; a
deception layer detects an intruder who is already inside. They share a threat model
but no code, and combining them would put the bait in the component that
authenticates users — the concentration mistake the other notes exist to avoid.

If it is built: its own daemon, its own ports, its own privileges, and it must be
possible to switch it off without affecting access control at all.
