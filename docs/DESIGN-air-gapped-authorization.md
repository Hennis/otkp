# Design note: air-gapped authorization

**Status:** design note, not implemented. Covers a component that is *separate*
from the knock daemon in this repository.

**Scope.** This note describes how to authorise access using a key that never
touches a networked machine, and how to record that authorisation so it can be
audited. It is deliberately *not* about the knock protocol in `src/` — that
protocol's secret must live on an online client, or the client cannot knock.
These are two different keys with two different purposes, and they must stay
separate (see §6).

**The layering, stated once.** The knock opens the keyhole: it reveals the port,
and nothing more. It does not authorise. Authorisation is a separate layer — a
signed attestation, verified before access is granted. Concealment and
authorisation are different properties, and collapsing them is the mistake this
note exists to prevent. See §5.2.

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
| The online host cannot trick the user into signing something else | **Yes, if the device originates the request — see §4** |

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

## 2.1 The end-to-end flow

Four layers, each proving a different thing. Naming them separately is what keeps
the design honest — collapsing any two is where these systems usually go wrong.

| Layer | Mechanism | What it establishes |
|---|---|---|
| **Authorization** | Air-gapped attestation, committed to a shared ledger by several parties | That the subject is *permitted* to access, and when |
| **Concealment + authentication** | The knock (per-user, per-use) | That the knocker knows the subject's secret — so it both conceals and identifies (§2.2) |
| **Authentication** | An exchange over an encrypted connection, firewall-scoped to the knocking address | That the peer *is* the subject |
| **Session** | VPN, with a one-time key issued over the authenticated channel | Confidentiality and integrity for the session |

The flow:

1. **Pre-authorize, offline.** The user originates the request **on** the
   air-gapped device — selecting the purpose from a closed menu — which builds and
   signs the attestation: subject, service, validity window, nonce. The device
   receives nothing from the network side (§4.3). Several parties commit it to the
   ledger. Wait N confirmations before treating it as final.
2. **Knock.** The client derives the OTP-style sequence and the auth-port number.
   The server consults its view of the ledger; with no valid attestation, it
   ignores the knock and opens nothing.
3. **Auth port opens**, scoped to the knocking address. (Deriving the port
   number from the secret is harmless but adds nothing here: once the firewall
   scopes the port to the knocking address, no one else can reach it, so the
   number is not protecting anything. Kept as a deliberate choice, not a
   control.)
4. **Authenticate** over the encrypted channel.
5. **One-time key issued** over the authenticated channel; receipt confirmed.
6. **VPN access granted.**

Note what layer 1 buys that no other layer can: it is the only place where *more
than one party agrees* that access is permitted. Layers 2–4 are all pairwise
between the subject and the verifier. If the requirement really is multi-party
agreement, layer 1 is load-bearing and the ledger is earning its cost.

## 2.2 The concealment secret: per user, per use

Settled: **per-user and per-use.** Each subject has their own secret, and each use
consumes a fresh derivation, so the knock both identifies the subject and cannot
be replayed.

The consequence to state plainly: **the knock is an authentication factor.**
"Does not authorize" remains true — the ledger supplies authorization — but the
knock *does* authenticate, because only the subject can produce the subject's
sequence. So layer 3 of §2.1 is confirming an already-identified subject, not
establishing one.

That is a stronger position than pure concealment, and it is worth claiming
precisely rather than understating. It also means the two layers fail
independently: compromising the knock secret exposes the auth port but does not
grant access, and compromising the ledger does not let an attacker knock.

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

## 4. The failure mode, and the fix that removes it

The naive shape has the **online host construct the request** and the offline
device sign it. That is the confused deputy: the compromised machine chooses what
gets signed, and the air gap is defeated unless the human reads the offline
device's display carefully, every single time.

Concretely: the attacker's request says "authorise access to host-42" on the screen
the user is looking at, while the bytes actually signed authorise something else.
A user who scans and confirms without reading has signed whatever the attacker
wanted — and the audit record will show a genuine signature by the victim.

### 4.1 The fix: make the offline device the originator, not the signer

Do not send a request *to* the offline device. Let the user originate the request
*on* it.

1. The user selects the purpose on the offline device itself (see §4.2).
2. The offline device constructs the token and signs it.
3. It displays the token as a QR.
4. The online side scans and submits it. It never constructs anything.

Now there is nothing to confuse. The compromised host has no say in what was
requested, so it cannot ask for one thing while obtaining another. This does not
make the confused deputy *harder* — it removes the class.

### 4.2 A closed vocabulary

The device signs only purposes from a fixed, pre-provisioned list. It cannot be
asked to sign arbitrary content, because it does not accept content — it accepts a
*selection* from a menu it already knows.

This is what stops "just sign this one thing for me" from working. The attacker
can at most induce the user to choose a legitimate but unwanted option from the
list.

### 4.3 One-way by construction

If the device originates requests, it never needs to receive anything from the
network side. The QR flow becomes one-directional: **offline → online only.**

Worth stating as a property rather than an implementation detail: **the offline
device has no input channel from the attacker's foothold.** There is no data path
by which the compromised host can influence it. The air gap becomes a diode.

### 4.4 What remains

Two things, stated honestly.

- **Social engineering within the menu.** The attacker cannot forge a request, but
  they can try to talk the user into selecting the wrong option — "select 'rotate
  credentials', we need it for the audit". The deception surface shrinks from
  *anything at all* to *the legitimate menu items*. A large reduction, not zero.
- **Denial of service.** The compromised host can decline to forward a valid
  token. It cannot forge one.

### 4.5 The requirements that still apply

1. **The offline device displays semantic content** — what it is about to sign, in
   words the user can check. With §4.1 this becomes a *confirmation of the user's
   own selection*, which is far easier to verify than an unfamiliar request
   arriving from elsewhere.
2. **The token is non-replayable** — nonce/counter, plus `audience` and validity
   window.
3. **The online host is treated as hostile.** It can now only deny or forward. It
   cannot authorise.

### 4.6 The cost

A few more button presses on the offline device per authorisation. In exchange, a
control that depended on human vigilance is replaced by one that depends on the
device having no input channel.

That is a good trade, and it is the single highest-value change to this design.

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

Pick one and write down why. **For this design the answer is "cache" — and since
§5.5 air-gaps the CA, it is not a preference but a forced consequence.** The
attestations are *pre-committed*, so the verifier holds the subset that concerns
it and refreshes it on the cycle, with a short TTL to pick up revocations. Ledger
availability stays off the critical path while the ledger remains the shared
record of agreement.

The trade to be explicit about: a cached attestation is trusted locally until the
TTL expires, so a *revocation* takes up to one TTL to take effect. And because the
CA is offline, that TTL cannot be shorter than the cycle — see §5.5.2, where
window length is the revocation SLA.

### 5.2 The knock does not authorise — it opens the keyhole

Correcting an earlier draft of this note: **the knock never authorised.** It opens
the port. Something else is the key — the signed token, the ledger attestation,
or the VPN handshake. Concealment and authorisation are different properties, and
this design separates them deliberately. The knock is the keyhole, not the key.

Two consequences worth being explicit about.

**The knock secret is a concealment secret, not a credential.** It still has to be
secret — a published sequence would let anyone open the port — but a compromise of
it does not grant access. It only exposes the authentication layer to the
attacker, who then faces the second factor like anyone else. That is a real
downgrade in blast radius, and it is the main argument for keeping the two layers
separate rather than collapsing them.

**This is a change to what the built daemon means, not a description of it.** In
the code in this repository, the knock *is* the credential: there is no second
layer, and knowing the secret is sufficient to be granted access. The architecture
described here adds that second layer. Until it exists, the knock's role is
credential, not keyhole — so the distinction is a target, not a current property.
Say which one you mean when you describe the system, because an interviewer will
ask.

### 5.3 The purpose stated: an attestation record

The stated purpose of the ledger here is to **assert who securely agreed to
access, and when**, and to permit access on the strength of that. That is an
*attestation*, and the design question sharpens to one thing:

> Does the attestation need to be **agreed** by more than one party, or only
> **verifiable** by more than one?

- **Agreed by several mutually distrusting parties** → a shared append-only log
  with consensus is doing real work, and a permissioned ledger is a reasonable
  choice. **This is the case here: the design is multi-party by intent**, so the
  ledger is earning its cost and this is the right tool for layer 1 of §2.1. Worth
  stating plainly rather than hedging.
- **Written by one party, verifiable by anyone** → the attestation is a signed
  record, and a transparency log (RFC 6962; Trillian as a library) gives
  tamper-evidence plus inclusion proofs without consensus, and orders of magnitude
  faster.

Note what makes the first case real: the parties must be mutually distrusting *and*
all writing. A permissioned ledger where one party writes and others merely read
has removed the consensus it existed to provide, and what remains is a hash chain
— a data structure, implementable over any database.

And the first case is a consortium, which is an organisational decision before it
is a technical one: governance, membership, liability, and dispute resolution all
have to exist first. No code bootstraps it. That is why permissioned ledgers in
the wild — trade finance, interbank settlement — began as organisations that added
a ledger, not the reverse.

**Since the multi-party case is the one being built, that prerequisite is now on
the critical path.** The technical design is settled; the organisational one is
not, and it is the harder of the two. Concrete questions that need answers before
any code is worth writing:

- **Who are the parties, and what does each one attest to?** If they all attest to
  the same fact, one of them is redundant.
- **Who may admit a new validator, and by what process?** This is the governance
  question, and it is the one that decides whether the ledger is trustworthy.
- **What happens on disagreement?** A ledger orders facts; it does not resolve
  disputes about them.
- **Who is liable if a party attests falsely?** Without an answer, the multi-party
  property is decorative.

### 5.3.1 The governance answers, and what each implies

Recorded, with the consequence of each. Two of these settle the design; one is a
gap.

**Who are the parties, and what does each attest to?**
*"Centrally authorised men; the men attest the legitimacy."*
This does not yet say what *distinguishes* the attestations. If every party
attests the same fact, only one is needed and the rest are decoration. The
multi-party property holds only if each party attests something the others
cannot — e.g. one attests employment, one attests that the service is permitted,
one attests regulatory standing. Name the distinct claim per party, or reduce to
one party and drop the ledger.

**Who admits a new validator?**
*"The central authority, the boss."*
This is the decisive answer, and it changes what the ledger is. **Governance is
centralised; integrity is distributed.** Several parties hold and extend the log,
so no single *writer* can rewrite another's entry — but one party controls who may
write at all.

That is a legitimate architecture; it is what Fabric-style permissioned networks
are. It is not a trustless one. Say **"centralised governance, distributed
integrity"** and not "no central authority," because the second claim will not
survive a five-minute interview question.

Consequence: the ledger's consensus is doing less work than it appears to. The
precise question becomes — **must the log survive a compromised operator?**
- If yes → several independent validators are worth their cost, and the ledger is
  the right tool.
- If no → a transparency log with signed tree heads and gossip gives the same
  tamper-evidence behind a trusted operator, far more cheaply.

**What happens on disagreement?**
*"We may determine one of us is compromised, maybe."*
This is a wish, not a mechanism, and it is **the most important gap in the
design.** Split view is precisely the failure a shared log exists to detect: two
validators report different histories. The log can *prove* the split; it cannot
tell you which side is honest. That requires an out-of-band process — a named
arbiter, an arbitration clause, evidence handling — and it is a legal and
organisational artefact, not code.

Write down, before building: when two validators disagree, which view is
authoritative for the next 24 hours, and who decides?

**Who is liable if a party attests falsely?**
*"The trustee who holds the authority we issue."*
A role is not a mechanism. Liability needs a legal entity, a contract that names
it, and usually a bond or insurance. Answer: which entity, in which jurisdiction,
bound by what instrument, and is it good for the loss?

### 5.3.2 The parties, and what each attests to

**The rule: each party attests only what is within its own authority and
knowledge.** If two parties attest the same fact, one of them is redundant and the
multi-party property is decorative.

Applying it to "is this access legitimate?" yields a decomposition where each
attestation is uniquely held:

| Party | Attests | Why only it can |
|---|---|---|
| **Principal** (the subject) | "I hold this key and I intend this use" | Only the key holder can sign. It is the sole attestation of *intent* — no one else can speak to it. |
| **Identity authority** | "This principal is who they claim, and is affiliated with us" | It holds the identity proofing and the affiliation records. Nobody else can attest to them. |
| **Resource owner** | "This principal is permitted to access this resource" | It owns the resource and sets the access policy. Permission is its to give. |
| **Independent attestor** | "This grant complies with the governing policy" | It has **no stake in the grant** — and that is the point. |

**The fourth is load-bearing, and it is the one most often omitted.** Without a
party that gains nothing from the grant, you have interested parties agreeing with
each other, which is a contract, not a distributed trust system. The independent
attestor is what makes "several parties agree" mean anything at all. It is also
the hardest to obtain, because a party with no stake has no reason to participate
except duty, regulation, or payment.

**Design rule:** if you cannot name what distinguishes each party's attestation
from every other's, you have fewer parties than you think — and the ledger is
carrying weight it does not need to.

### 5.3.3 Liability

**The rule: liability follows the attestation.** Each party is liable for the truth
of its own attestation and for nothing else.

This is the *second* thing the decomposition buys, and it is easy to miss: it is
not only a technical partition, it is a **liability partition**. If identity and
permission were attested by a single party, you could not tell which failure
produced a bad grant. By separating them, every failure has an owner.

For that to be real rather than decorative, six things must exist:

1. **A legal entity behind each attesting party.** You cannot sue a node.
2. **A participation agreement** binding each party to the truth of its
   attestations — and binding the principal too, who is a person rather than an
   entity and is covered by the same instrument.
3. **Several liability, not joint.** Each party bears only its own exposure. Joint
   liability makes every party a guarantor of every other, which deters precisely
   the independent attestor you most need.
4. **Financial responsibility** — a bond or insurance per party — so liability is
   not theoretical against a counterparty with nothing to lose.
5. **A governing law and a forum.** Which jurisdiction, which courts or which
   arbitration seat.
6. **A defined process for determining that an attestation was false.** This is
   the same arbiter as the split-view question in §5.3.1, and it is the same gap:
   it needs a named decision-maker, not a mechanism.

**On the trustee.** The earlier answer — "the trustee who holds the authority we
issue" — is half right, and the useful half is worth keeping. A trustee is a real
legal structure and it is the right *mechanism* for (4): it administers the bond
pool and holds the security on behalf of the beneficiaries.

But the trustee does not *bear* the liability. Liability attaches to each
attesting party, per its own attestation. The trustee holds the money that makes
that liability enforceable. Both roles are needed; conflating them leaves you
unable to say who is answerable when an attestation turns out false.

### 5.4 If the ledger is public

A public ledger publishes every authorisation permanently and correlatably — who
may access what, and when, for all time. For a system whose point is concealment,
that is the opposite of the goal. It may still be a deliberate trade, but it
should be a deliberate one.

### 5.5 The central authority: offline, and distributed

The CA resolves to two properties, and both follow from one requirement: **no
single party should be able to authorise or deanonymise on its own.**

#### 5.5.1 Offline — the CA is never in the online path

The CA is air-gapped, so it cannot be consulted during an access. It therefore
cannot answer "is this within the window?" — the verifier answers that from
material the CA issued in advance.

This is the **offline root CA pattern**: a root that signs grants periodically,
with the grants doing the work online.

Consequences:

- **No availability dependency.** The CA being offline, down, or absent does not
  block access. This settles §5.1 in favour of caching — it is not a preference,
  it is forced.
- **No real-time observation.** The CA does not see accesses as they happen. A
  privacy gain and a detection loss, and both are worth naming.
- **Issuance is batched.** The CA acts in cycles, not on demand. Access must be
  planned, not granted impulsively. A real operational constraint, not a defect.

#### 5.5.2 The revocation answer is short windows

An air-gapped CA cannot revoke live. Revocation requires a cycle: sign, transport,
distribute.

The resolution is not fast revocation — it is **short validity windows.** Revoking
means declining to renew, so the worst-case revocation delay is the *window*
length, not the cycle length.

Design constraint: **cycle length ≤ window length.** The window length *is* the
revocation SLA, and should be chosen as one rather than discovered as one.

#### 5.5.3 Distributed — threshold signing

Air-gapping protects the CA's keys from remote compromise. It does not protect
against physical seizure, supply chain, or compulsion — and the CA holds three
roots: validator admission, identity mapping, and window decryption.

Split the CA's signing key **k-of-n** across n parties, requiring k to co-sign.
Then:

- No single device can issue an attestation.
- No single party can deanonymise a subject.
- Seizure or subpoena of one share is insufficient.
- The shares can each sit on their own offline device, so air-gapping composes
  rather than conflicts.

Cost: one more ceremony per cycle, and share custody is real operational burden —
who holds them, where, under what controls, and what happens when a holder leaves.
Suggested starting point: **3-of-5**, which survives one loss and one absence
without making collusion easy.

#### 5.5.4 The four parameters that *are* the design

| Parameter | Meaning | Consequence |
|---|---|---|
| **Cycle length** | How often the ceremony runs | Issuance latency; must be ≤ window length |
| **Window length** | How long an attestation is valid | Worst-case revocation delay |
| **Batch size** | Attestations issued per cycle | Issuance ceiling |
| **Threshold k-of-n** | Shares required to sign | Collusion resistance vs operational friction |

Everything else in this note is implementation.

#### 5.5.5 What this resolves, and what it does not

**Resolved:** the CA cannot be a live dependency; no single party can authorise
unilaterally; no single party can deanonymise unilaterally; remote compromise of
the CA no longer yields the keys.

**Not resolved, and worth stating plainly:**

- **Metadata.** The ledger still shows *how many* commitments exist and *when*
  they were made. Count and timing are intelligence. If commitments are made
  shortly before use, timing reconstructs the schedule.
- **Traffic correlation.** A pseudonym with a schedule can still be linked to a
  source address by anyone with network visibility. Pseudonymity is not anonymity
  when the actions are observable.
- **The verifier.** A compromised verifier sees its own slice, and can link its
  own pseudonyms to addresses it observes. Per-verifier scoping bounds this to one
  service — the right bound, but not zero.
- **The online host.** Still assumed hostile, still able to deny service. It can
  no longer authorise.


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
- **A user who does not read the display.** The confused deputy — *structurally
  removed* by §4.1, provided the device originates the request and signs only from
  a closed menu (§4.2). The residual is social engineering *within* the menu: the
  user can still be talked into selecting a legitimate but unwanted option.
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
| Multi-party authorisation | Permissioned ledger — several parties each attest a distinct fact (§5.3.2) | A single writer needs a transparency log, not consensus |
| Accountability | Liability follows the attestation: several liability per party, bonded, under a participation agreement (§5.3.3) | — |
| Authorising root | Air-gapped CA, **never in the online path**, with its key split k-of-n across parties (§5.5) | An online CA is an availability dependency and a single point of both authorisation and deanonymisation |
| Concealment **and** authentication (opens the keyhole, identifies the subject) | The knock protocol (separate; per-user, per-use) | — |
| Who agreed to access, and when | Attestation: signed record, or shared ledger if several mutually distrusting parties must agree (§5.3) | A single writer needs a transparency log, not consensus |

Seven rules, if you remember nothing else:

1. **The knock conceals and authenticates; it does not authorise.** It opens the
   keyhole. Keep the layers separate, and note that the built daemon currently has
   only this first layer — the distinction is a target, not a current property
   (§5.2, §2.2).
2. **The offline device originates; it does not merely sign.** A signer can be
   confused; an originator with a closed menu and no input channel cannot (§4).
3. **Every party must attest something no other party can.** If two attest the
   same fact, one is redundant. The party with no stake in the grant is the one
   that makes "several parties agree" mean anything (§5.3.2).
4. **Liability follows the attestation.** Several, not joint, bonded, under one
   instrument, with a named arbiter for disputes (§5.3.3).
5. **The authorising root is offline and distributed.** Air-gap it so it cannot be
   a live dependency, and split its key k-of-n so no single party can authorise or
   deanonymise. Window length then *is* your revocation SLA (§5.5).
6. **Display semantics.** A hash the user cannot read is not a control.
7. **Separate keys per purpose.** One seed, many derived keys — never one key,
   many purposes.
