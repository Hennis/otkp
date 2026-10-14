# Design note: a deception layer (future project)

**Status: future project note. Not part of `otkp`, and not designed in detail.**
This records an idea, the parts of it that are sound, the parts that are
dangerous, and the established techniques that already do most of what it wants.

---

## 1. The idea, stated fairly

Attract an automated attacker into spending time and money on decoys: expose
services on the VPN interface that *appear* to be vulnerable software, and serve
data that looks valuable but is worthless — cheaply generated files that cost the
attacker tokens to read, parse and exfiltrate, while yielding nothing.

The cost model being targeted is real and specific: an LLM-driven agent pays per
token, so making it read plausible garbage is a genuine economic attack on the
attacker. That is a legitimate and fairly novel framing, and it is the strongest
part of the idea.

---

## 2. The principle it should be built on — which is already the design

**The VPN interface should expose the legitimate service and nothing else.**

That is not a new idea; it is the default, and it is the right one. Every port you
open is attack surface, every decoy service is code you must keep secure, and a
honeypot that is itself exploitable is a foothold you built on purpose.

So a deception layer is a **deliberate exception** to the minimisation rule, and
exceptions need justification. The justification is: it costs the defender almost
nothing and costs the attacker something. If either half fails, the exception is
not worth making.

---

## 3. What is sound

- **Tarpits.** Holding a connection open indefinitely costs the attacker a socket
  and, for an agent, a timeout and a retry. `endlessh` does this for SSH and is a
  good model: near-zero cost to the defender, real cost to the attacker, and it
  cannot be exploited because it never speaks a real protocol.
- **Honeytokens.** Fake credentials, API keys or documents that do nothing except
  alert when touched. Established, cheap, and they convert "something might have
  leaked" into "this specific decoy was accessed at this specific time."
- **Canary markers.** Unique, per-instance markers embedded in decoy data, so
  exfiltrated material can be *proven* to have come from you and traced to the
  instance it was taken from. This is the part that turns decoy data into
  evidence rather than merely noise.
- **Deterministic decoy generation.** Template-driven fake records are cheap,
  fast, reproducible and auditable. They cost the defender nothing per file.

---

## 4. What is dangerous

- **Real vulnerable software.** Running an actual known-CVE service as bait means
  running an actual known CVE. If it is exploitable, the attacker who takes the
  bait gets a foothold. Bait must be a *facsimile* — banners, headers, and
  behaviour — never the vulnerable code itself.
- **Decoy services are attack surface.** Every one is a program with a parser, a
  network stack, and bugs. A decoy that can be crashed or overflowed is worse than
  no decoy.
- **Fake data that looks like real personal data is a compliance problem.** Decoy
  customer records are indistinguishable from a data breach to a regulator or an
  auditor, and "it was fake" is a bad position to argue from. Decoys should be
  obviously synthetic to *you* — via canary markers — while looking plausible to
  the attacker.
- **Anything that strikes back is illegal.** Serving real malware, attacking the
  source, or degrading the attacker's system crosses from defence into offence in
  most jurisdictions. Decoys observe and waste time; they do not retaliate.
- **Attribution of the decoy's own traffic.** A honeypot that phones home can be
  identified as a honeypot by that traffic alone.

---

## 5. The AI-generated-decoys part is the weakest link

Using an LLM to generate plausible decoy files is spending money to save money.

- Deterministic templates produce equally plausible synthetic records at
  effectively zero marginal cost, with no model to host, no latency, and no
  non-determinism.
- An LLM generating decoys is *your* per-token bill, in the same currency the
  idea is trying to make the attacker spend.
- The value is not in the files' realism — an agent reading a fake record learns
  the same lesson whether a template or a model wrote it. The value is in the
  **canary markers** (§3), which cost nothing to add and are what make the decoy
  useful rather than merely decorative.

If the goal is "make the attacker spend tokens," templates achieve it. If the goal
is "make the attacker spend *more* tokens," the lever is *volume and plausibility
of structure*, not generation method.

---

## 6. What I would build instead

1. **Tarpits on the ports you are not using.** `endlessh`-style: no protocol, no
   parser, no exploitability, real cost to a scanner or an agent.
2. **Honeytokens in the places an attacker looks first** — a fake `.aws/credentials`,
   a fake `~/.ssh/id_rsa`, a fake `.env`. Cheap, and they alert on use.
3. **Canary markers in any decoy data**, so exfiltration is provable.
4. **Nothing that executes, parses, or responds with real software.** Every decoy
   is a tarpit or a static artefact.
5. **Measure it.** If the decoys do not measurably cost the attacker and cost you
   nothing, remove them. A deception layer that cannot be evaluated is decoration.

---

## 7. Scope

This is a **separate project** from `otkp`. OTKP conceals a port and authenticates
a user; a deception layer attracts and wastes an attacker's resources. They share
a threat model but no code, and combining them would mean the component that
authenticates users also runs the bait — which is the concentration mistake the
rest of these notes exist to avoid.

If it is built, it should be its own daemon, on its own ports, with its own
privileges, and it should be able to be turned off without affecting access
control at all.
