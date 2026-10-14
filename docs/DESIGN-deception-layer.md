# Design note: a deception layer (future project)

**Status: future project note. Not part of `otkp`, and not implemented.**
This records the design, what is sound, what remains dangerous, and the
constraints that make the difference between a control and a liability.

---

## 1. The idea

Present services inside the authenticated perimeter that *announce* as
known-vulnerable software. Nothing is exploited and nothing is vulnerable — the
banner is the whole of it. The purpose is **detection, not entrapment**: when a
decoy is touched, the credential in use belongs to a compromised account or a
malicious insider.

**The decoys are reachable only on the VPN, after access has been granted.** This
is not an implementation detail; it is what makes the design safe. A decoy inside
the perimeter is, by construction, only reachable by a session that has already
authenticated — so a trip can only ever implicate the credential that tripped it.
See §4.2.

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

## 2. Why it works: detection by negative space, not by deception

An earlier draft of this note argued that a banner-only decoy is weak because a
competent attacker fingerprints by *behaviour* and spots the decoy. That argument
was wrong, and the reason it was wrong is the principle the whole design rests on:

> **The detection does not depend on the attacker believing the bait.**

It depends on the decoy having **no legitimate use**. Inside the authenticated
perimeter, with exactly one permitted action per user, *any* interaction with a
decoy is anomalous by definition — reading a banner, connecting to the service,
sending anything at all. Whether the attacker sees through the pretence is
irrelevant. They have already revealed that they are probing somewhere they have
no business being.

So the mechanism is a **defined negative space**: a place where legitimate
activity never occurs, and therefore any activity is signal. The deception is
secondary — it wastes the attacker's time — while the negative space is what
detects.

This also means the design does not degrade as attackers get smarter. A better
attacker detects the decoy faster and trips it sooner. The signal is produced by
the *probe*, not by the *belief*.

### 2.1 What it buys: the detection gap, closed

§11.2 of the main README names a gap: *attribution is not detection.* Knowing whose
credential was used is not the same as knowing a credential has been compromised.

A tripwire closes that gap:

1. A compromised session — or a malicious insider — explores the interface.
2. They interact with a decoy.
3. The decoy records the event, **silently**.
4. The credential in use is known, so **the account is known**.
5. A separate responder acts, on the graduated scale of §3.

That converts "something may have leaked" into "account X is compromised, now."
It is a capability the rest of this architecture does not otherwise have.

### 2.2 The limit, stated honestly

It catches everything that **touches** a decoy — which is everything that
enumerates the interface. It does not catch an attacker who never probes: one who
compromises a session and goes directly to the one legitimate service they know
about, using it exactly as intended. A tripwire detects exploration; it cannot
detect an intruder who does not explore.

It is a supplement to detection, never a replacement.

---

## 3. The graduated response

Interaction escalates, and the response escalates with it. A single automatic
punishment for every touch would lock out legitimate users over a typo — the same
mistake as a one-strike ban.

| Interaction | Reading | Response |
|---|---|---|
| Reading a decoy banner | Probing — the user is somewhere they have no reason to be | Reject the connection, **warn the user**, record. A warning first, because a typo and a probe look identical from here. |
| Connecting to a decoy service | Intent — they are trying to use a service that does not exist for them | Revoke the credential, force disconnect, investigate |
| Sending exploit-shaped data | Attack — unambiguous | Revoke, disconnect, investigate, alert |

**The response is credential-scoped, never address-scoped.** This is the one place
the design must not copy the knock layer's behaviour. A knock failure bans an
*address* because it happens before authentication and the address is all you have.
A decoy trip revokes a *credential* because it happens after authentication and the
credential is exactly what you have. Banning an address here would be wrong twice:
the address is the legitimate user's, and an attacker riding a stolen session is
*at* a legitimate address. It would punish the victim's network.

**Warn the user, and mean it.** The warning is not decoration. It is what makes the
false-positive case survivable: a user who typo'd a port can say so, and a user
whose credentials were stolen learns they were stolen — which is the §2.1 payoff
delivered to the person it matters to.

---

## 4. Provable synthetic data

Decoy data must be *provably* fake, for two audiences: the attacker (who must
believe it) and a regulator or auditor (who must be able to see that no real data
was ever at risk). Three mechanisms, and all three are needed.

**4.1 Cryptographic provenance.** Generate each decoy, hash it, and sign a
manifest of what was generated and when. Any file can then be proven to have come
from your generator, so "this is synthetic" becomes a verifiable statement rather
than an assertion. The generation manifest is an append-only log — the same shape
as the audit stream in `src/audit.rs`.

**4.2 Reserved namespaces — the part that makes it airtight.** Do not merely
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

**4.3 Generation method: templates, not models.** A small language model generating
decoys is *your* per-token bill, in the same currency the design is trying to make
the attacker spend. Deterministic templates are:

- free per file, versus a model inference cost
- reproducible, so a regenerated decoy is byte-identical and therefore verifiable
- auditable, so a reviewer can read exactly what can be produced
- non-hallucinating, so they cannot accidentally emit a real identifier

The attacker cannot tell a templated record from a generated one — both read as
plausible data. So the model buys nothing and costs money.

---

## 5. What remains dangerous

**5.1 The decoy does not need to be believed — but it does need to be unreachable by
legitimate tooling.** See §2 for why detection survives a suspicious attacker. The
real risk is the opposite one: a backup job, an inventory scanner or a monitoring
agent wandering into a decoy and tripping it. Decoys must sit where no legitimate
automated process goes, and the permitted-use policy must be enforced by
configuration rather than merely documented.

**5.2 Auto-revocation is a denial-of-service vector unless it is session-scoped.**
This is the same failure class as the one-strike ban that had to be fixed in
`7e98249`. If a decoy is reachable *before* authentication, an attacker can trip it
deliberately to cause revocations. The design already answers this: decoys are reachable **only after
authentication** (§1), so a trip can only ever implicate the credential that tripped
it. The constraint is therefore structural rather than procedural — but it must be
*enforced* rather than assumed: **a trip may only revoke the credential of the
session that tripped it.** Never a credential inferred from a source address, never
a shared credential. Assert it in a test.

**5.3 The decoy must be silent.** If it reveals that it has been tripped — an error,
a delay, a disconnect — the attacker learns they have been detected and changes
behaviour. Record, do not react in-band.

**5.4 The responder must be separate.** Same principle as the rest of this
architecture: the daemon emits an event, separate software decides and acts. A
component that both detects and revokes is one whose compromise both blinds you and
revokes your users.

**5.5 Revocation latency is bounded by the window, not the trip.** With an
air-gapped CA (§5.5.2 of the authorisation note), revocation takes up to one
validity window. The trip gives you the signal immediately; the revocation is slow
by design. Do not build a responder that assumes otherwise.

---

## 6. On the justification

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

## 7. The deception ratchet

Same principle as the security levels in the main README: start at the rung that
delivers the most for the least, and climb only as budget and threat model permit.

| Rung | Name | Adds | Cost to you |
|---|---|---|---|
| 0 | *nothing* | No deception. The interface exposes the legitimate service and nothing else. **This is the default, and it is not a failure.** | None |
| 1 | `probe-detect` | Banner decoys inside the perimeter. Any interaction is signal. Reject, warn, record. | A handful of static listeners |
| 2 | `graduated` | Connect- and payload-aware escalation: revoke the credential, force disconnect, investigate | A responder, and an investigation process to actually run |
| 3 | `tarpit` | Decoys that accept and stall rather than reject, costing the attacker time instead of one error | Careful implementation — a stalling service is a service with a parser |
| 4 | `fountain` | Provable synthetic data: records from reserved namespaces, signed manifests, canary markers | A generator, a manifest log, and the compliance story of §6 |

Two things about the ordering:

- **Rung 1 is where almost all the value is.** It detects every probe, costs almost
  nothing, and cannot be exploited. Most deployments should stop here, and that is a
  legitimate engineering decision rather than an unfinished one.
- **Rung 4 is the only rung carrying a compliance burden**, and it is the one people
  reach for first. It is also the only rung that serves *false data to a party who
  might not be an attacker*, which is why §6 exists.

---

## 8. What to build, in order

1. **Tarpits on unused ports.** `endlessh`-style: announce, then never complete. No
   protocol, no parser, no exploitability, real cost to a scanner or an agent.
2. **Honeytokens where an attacker looks first** — a fake `.aws/credentials`, a fake
   `~/.ssh/id_rsa`, a fake `.env`. Alert on use.
3. **One or two banner decoys** inside the authenticated interface, scoped so
   legitimate tooling cannot reach them, silent on trip.
4. **A signed generation manifest** for any decoy data, with reserved-namespace
   sources and templated generation.
5. **A separate responder** that consumes trip events and revokes, with the
   session-scoping constraint of §5.2 enforced in code and asserted in a test.
6. **Measure it.** If the decoys do not measurably cost the attacker and cost you
   nothing, remove them. A deception layer that cannot be evaluated is decoration.

---

## 9. Scope

A **separate project** from `otkp`. OTKP conceals a port and authenticates a user; a
deception layer detects an intruder who is already inside. They share a threat model
but no code, and combining them would put the bait in the component that
authenticates users — the concentration mistake the other notes exist to avoid.

If it is built: its own daemon, its own ports, its own privileges, and it must be
possible to switch it off without affecting access control at all.
