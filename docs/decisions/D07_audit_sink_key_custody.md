# D07 — external audit sink and key custody: decision pack

**Decision pack. Nothing here is a decision.** D07 belongs to the platform lead with
an assurance reviewer. This pack prepares its five required evidence elements, reports
one measured constraint on what a sink must be able to return, and names one thing the
decision core cannot express at all.

| | |
|---|---|
| Decision | Select the external audit sink and key custody arrangement (Integrated Baseline v1.6, Appendix E.3, D07) |
| Accountable role | Platform lead with assurance reviewer |
| Required evidence | "Independent administration, retention lock, signing/key rotation, anchor acknowledgment and failure behavior; no claim of external trust from a local mock" |
| Also to resolve here | Appendix E.4's audit implementation list: restricted procedure interface, revoked public execution, ownership out of runtime roles, transaction boundaries and outbox/retry handling |
| Blocks | F07, and with it every High/Critical closure, since `Closure awaiting anchor` cannot finalise without a verified receipt |
| Drafted | 2026-10-15, by Claude Opus 5 at the owner's instruction |
| Status | **Unconfirmed / Blocked. §14's decision record is unsigned.** |

## 1. The decision as the documents state it

**The sink is outside the platform's administrative control, by design.** Baseline §8:
"The assurance domain verifies external anchors separately from platform
administration." §9.1 requires that Seal "signs the current chain head and writes it to
an append-only external sink controlled by a separate assurance role", and that the
sink "may be object storage with retention lock or an equivalent write-once log
service."

**Anchoring has a schedule and an event-triggered set.** §9.1: "At least every fifteen
minutes and at scan completion", plus immediate anchoring for authorization approval or
revocation, priority override, High/Critical closure, incident declaration or status
change, and any audit-role ownership, privilege or procedure-definition change.

**The receipt is what closure waits for.** Baseline §6.8 and spec §5: High and Critical
closure enters `Closure awaiting anchor` after proof review, and finalises "only after
an independently verified receipt binds the closure-intent event to the signed external
chain head" — with the instruction to "never fabricate a receipt."

**Failure is specified, not left to implementation.** §9.1's U07 semantics: "Signature
failure, chain mismatch or an overdue fifteen-minute anchor blocks new jobs and
High/Critical closure, stops active assessment under C02 and alerts assurance."
Alongside it: "Revocation and emergency stop remain effective during sink outage."

**And the pack's own warning:** the D07 row ends "no claim of external trust from a
local mock." F07's acceptance evidence repeats it — "real separated sink verified
before trust claims."

## 2. What is already built, and what it settles

`src/seal/core/audit.py` models the ledger, the outbox, the receipt and the anchor
clock. `integrity.py` models what an overdue anchor does. `closure.py` models the
finalisation that waits on a receipt. Between them they settle the *shape* of the
problem and settle none of the decision:

- `AuditLedger.append` returns the event **and** its `OutboxItem` together, so a caller
  cannot acknowledge an event without taking the outbox item. "Commit both together" is
  structural rather than a comment.
- `OutboxItem.idempotency_key` is a digest over `(organization, sequence, head)`, which
  is the retry identity §9.1 asks for.
- `ANCHOR_INTERVAL` is 15 minutes, and `IMMEDIATE_ANCHOR_KINDS` holds seven event
  kinds. Five of §9.1's categories map directly; closure is split into
  `CLOSURE_INTENT` and `CLOSURE_FINALIZED`, which is a reading of "closure of a High or
  Critical finding" rather than a second requirement. **`INTEGRITY_STATE` is not in
  §9.1's list at all** — anchoring an integrity transition immediately is a
  strengthening the code chose. It is defensible, since C02's whole point is that an
  integrity change must be externally evident, but it is an addition and the reviewer
  should either ratify it or strike it rather than inherit it unnoticed.
- `AnchorReceipt.verified` is documented in the module as "a trusted-service input, not
  something this module establishes."

That last point is the honest centre of this pack. **The property D07 exists to
procure — external trust — is the one property the code deliberately does not
implement.** Everything below says what a sink must supply so that flag can ever
legitimately be true.

## 3. The constraint that decides the sink (measured)

`AuditLedger.record_receipt` and `closure.finalize` both reconcile a receipt against
the exact `(sequence, head)` the ledger produced, and both refuse a receipt whose
`verified` flag is false. A probe ran the real decisions with the receipt each
candidate sink could actually return:

```
signed inclusion proof naming the head, verified         -> PERMIT
write acknowledged (HTTP 200), nothing to verify against -> DENY  ('RECEIPT_UNVERIFIED',)
sink returns its own object id, not the chain head       -> DENY  ('RECEIPT_AUDIT_MISMATCH',)
sink returns a head the ledger never produced (replay)   -> DENY  ('RECEIPT_AUDIT_MISMATCH',)
right head, wrong sequence (reordering)                  -> DENY  ('RECEIPT_AUDIT_MISMATCH',)
receipt issued for another tenant's chain                -> DENY  ('CHAIN_TENANT_MISMATCH',)

first delivery                                           -> PERMIT
same receipt delivered again                             -> PERMIT('ALREADY_FINALIZED',)
```

The same receipts run through `closure.finalize`, which is the decision that actually
holds a finding, with everything else about the closure valid — reviewed, complete
coverage, right build, no contradicting observation:

```
signed inclusion proof naming the head, verified         -> Closed
write acknowledged (HTTP 200), nothing to verify against -> Closure awaiting anchor
sink returns its own object id, not the chain head       -> Closure awaiting anchor
sink returns a head the ledger never produced (replay)   -> Closure awaiting anchor
right head, wrong sequence (reordering)                  -> Closure awaiting anchor
receipt issued for another tenant's chain                -> Closure awaiting anchor
```

**A sink that only acknowledges a write cannot operate this decision.** Not less
verifiably — High and Critical findings never leave `Closure awaiting anchor`, because
`verified` has no basis and the receipt is refused outright. Two capabilities are
therefore mandatory, and they are separable:

1. **The sink must let something read back the exact chain head it holds**, so a
   receipt can name `(sequence, head)` rather than an opaque storage identifier.
2. **That read-back must be performed under different credentials from the ones that
   wrote it.** This is what makes the receipt independent rather than Seal marking its
   own homework. The code cannot enforce it — `verified` is an input — so it is an
   arrangement to be procured, which is exactly why D07 is a decision and not a ticket.

The replay and reordering rows matter for a second reason: a sink that returns receipts
asynchronously and out of order is fine, because reconciliation is by `(sequence,
head)` and duplicates are idempotent no-ops. **Ordering is not a sink requirement.**
Addressability is.

### 3.1 The sink is an availability dependency of assessment itself

The same probe on the anchor clock, and what an overdue anchor does downstream:

```
sink responded 1 minute ago                              -> PERMIT
sink unreachable for 14 minutes                          -> PERMIT
sink unreachable for 16 minutes                          -> DENY  ('ANCHOR_OVERDUE',)
sink unreachable for 2 hours                             -> DENY  ('ANCHOR_OVERDUE',)

integrity admission after ANCHOR_OVERDUE                 -> Untrusted
grant generation, before -> after                        -> 1 -> 2
a scanner request under that state                       -> DENY  ('INTEGRITY_UNTRUSTED',)
```

**Sixteen minutes of sink unavailability stops assessment.** The generation increment
is what revokes grants already issued, so recovery is not "the sink came back" — C02
requires an explicit authorised resume. A sink's availability figure is therefore a
safety parameter for this platform, not an operations footnote, and it belongs in the
selection criteria at §10 rather than in a runbook written afterwards.

Seven of the twelve event kinds cannot wait for the interval at all. Summarising the
probe's third section, which prints them one per line:

| | Event kinds |
|---|---|
| Immediate, event-triggered | `authorization`, `priority_override`, `closure_intent`, `closure_finalized`, `incident`, `audit_control`, `integrity_state` |
| Base schedule — every 15 minutes **and** at scan completion | `scope_denial`, `scan_complete`, `coverage_manifest`, `disposition`, `evidence_disposal` |

So the sink must accept low-latency out-of-band writes. A batch-oriented archive that
accepts a bundle once an hour satisfies none of the seven.

### 3.2 What the chain proves on its own, and where that stops

```
chain verified against the sink-held checkpoint          -> PERMIT
same chain, checkpoint from a stale sink copy            -> DENY  ('CHECKPOINT_MISMATCH',)
a payload altered after the fact                         -> DENY  ('CHAIN_EVENT_TAMPERED',)
```

Tamper detection works today and needs no sink. What needs the sink is the answer to
"tampered *relative to what*" — a checkpoint Seal holds alone proves only that Seal is
consistent with itself.

The probe is at `tools/d07_anchor_probe.py`. Like its D04 and D06 counterparts it
reports and asserts nothing.

## 4. The gap the model cannot express: key identity

`AnchorReceipt` carries exactly these fields:

```
organization, sequence, head, sink_id, received_at, verified
```

**There is no key identity and no signature among them.** The chain proves internal
consistency and records that *a* sink acknowledged a head. It cannot express which key
signed that head, which means the decision core currently has no way to answer:

- After a rotation, is a head signed by the retired key still verifiable, or does
  verification of historical anchors fail?
- If a key is compromised, which anchors are repudiated — all of them, or those after a
  known-bad timestamp?
- Does `sink_id` change on rotation, or is it stable across keys?

This is not a defect to fix in this pack. It is **the modelling consequence of D07
being unmade**: the core cannot name a custody arrangement nobody has selected. But it
does mean the decision must settle rotation semantics *before* F07 writes the receipt
type, because adding key identity afterwards changes a persisted record and every
historical verification path. §13 Q3 carries it.

## 5. Element 1 — independent administration

The requirement is structural, and the word is *administration*, not *hosting*. A sink
in a different cloud account that the platform team also administers satisfies the
letter and defeats the point: baseline §9.1's residual risk names "collusion across the
operational and assurance domains" as the surviving threat precisely because
independence is an arrangement between people.

**Proposed as the minimum testable form of independence:**

| Property | Requirement | How it is checked |
|---|---|---|
| Credential separation | The write credential cannot delete, overwrite, or change retention settings | Attempt each from the Seal credential; all must fail |
| Administrative separation | Nobody who administers Seal's platform account can alter the sink's retention policy or its access policy | Named role list, reviewed by the assurance reviewer |
| Verification credential | Read-back and receipt issuance use a third credential held by assurance, not by Seal's runtime | The receipt-issuing path runs outside Seal's deployment |
| Break-glass | Any change to sink administration is itself a two-person action and an `AUDIT_CONTROL` event, which anchors immediately | §9.1's event-triggered list already requires this |

The existing `seal_audit_owner` NOLOGIN role (spec §7) protects the *local* chain. It
has no authority at the sink and must not be reused there — a single role spanning both
domains would collapse the separation this element exists to create.

## 6. Element 2 — retention lock

Baseline §9.1 permits "object storage with retention lock or an equivalent write-once
log service." The lock must cover three things, and the third is routinely missed:

1. **Objects cannot be overwritten** for the retention period.
2. **Objects cannot be deleted** for the retention period, including by the account
   root or an administrator.
3. **The retention period itself cannot be shortened.** A governance-mode lock that a
   sufficiently privileged operator can relax is not a lock against the operator, and
   baseline §9.1's residual risk is specifically about a "sufficiently privileged
   operator."

**A conflict to resolve with D08, not here.** §11.1 requires a disposal schedule and
states that "unnecessary personal data must not be retained merely because another
project record remains in scope." A retention-locked sink cannot delete. These coexist
only if the anchored payload contains no personal data at all.

What would actually be written is the outbox item's `(organization, sequence, head,
created_at)` — a tenant identifier, a counter, a hash and a timestamp. No finding
content, no evidence, no actor. **That is compatible with a permanent retention lock**,
and the pack proposes writing nothing else to the sink for exactly this reason.

It is not, however, free of disclosure: the sink's administrator learns which tenants
exist, how many audit events each generates and when. That is a minimisation question
for D08's data inventory rather than a blocker here, and §13 Q5 refers it.

## 7. Element 3 — signing and key rotation

Unmodelled today (§4). The decision must fix at least:

| Question | Why it cannot be deferred to F07 |
|---|---|
| Where the signing key lives — HSM, cloud KMS, or software key | Changes the threat model's "sufficiently privileged operator" row directly |
| Whether Seal's runtime can *use* the key without being able to *export* it | A exportable key makes every anchor forgeable by one compromised host |
| Rotation interval and trigger | Determines whether receipts need key identity, which changes the persisted record |
| Verification of pre-rotation anchors | Decides whether the historical chain stays verifiable or is re-anchored |
| Who holds the verification public key | If it is Seal, the "independent" verification is circular |

**Proposed:** a managed KMS key that Seal's runtime may invoke for signing but cannot
export, rotated on a fixed schedule with the retired public key retained indefinitely
for historical verification, and `key_id` added to `AnchorReceipt` so a head is always
verifiable against the key in force when it was signed. That is a proposal. §14 decides.

## 8. Element 4 — anchor acknowledgment

§3 established what a receipt must contain. This element is the protocol around it.

**The sequence, as the code already shapes it:**

1. `append` commits the event and its outbox item in one transaction. A non-durable
   append raises rather than returning a half-written event — there is no partial
   success to acknowledge.
2. The submitter writes `(organization, sequence, head, created_at)` to the sink.
   Retries reuse `idempotency_key`, so a retried submission is the same item.
3. Assurance reads the head back under its own credential and issues a receipt with
   `verified=True`.
4. `record_receipt` reconciles it against the outbox. Duplicates are no-ops; mismatches
   are refused.

**Two failure cases the protocol must name, because the code refuses both rather than
guessing:**

- A receipt arriving for a head the ledger never produced is `RECEIPT_AUDIT_MISMATCH`.
  The pack proposes treating it as an integrity incident, not a transient error — it
  means the sink holds something Seal did not write.
- A late receipt for a superseded closure intent is rejected as stale by C01 and "must
  be preserved without closing the finding." The sink's receipt retention must therefore
  outlive the intent it names.

## 9. Element 5 — failure behaviour

§9.1's U07 semantics and C02 already specify this; the sink decision has to be
compatible with it rather than redefine it. Stated as what must remain true:

| Condition | Required behaviour | Already modelled? |
|---|---|---|
| Anchor overdue beyond 15 minutes | Integrity `Untrusted`, generation increments, new jobs denied, active assessment stopped | Yes — `integrity.detect`, measured at §3.1 |
| Signature failure or chain mismatch | Same | Yes — both are `Trigger` members |
| Sink unavailable, briefly, within the interval | May stay Trusted **only while** local durable auditing and trusted health hold; receipt-dependent approvals and closures stay pending | Partly — the interval is modelled; "local durable auditing available" is an F07 runtime condition |
| Primary audit path fails | Approved restricted durable emergency journal; **do not acknowledge undurable events** | Partly — `append` refuses a non-durable write; the journal is F07's |
| Any of the above | **Revocation and emergency stop still work** | Yes — `apply_stop` does not depend on anchoring |
| Recovery | Explicit authorised resume, new integrity generation, fresh scope/revocation/profile/budget checks | Yes — `integrity.resume` refuses without both a named authority and a completed reconciliation of the journal and external anchors |

The line that most constrains sink selection: **stop enforcement must not depend on
successful journaling or anchoring.** Any sink integration that sits in the stop path —
a synchronous write before a stop takes effect, say — violates C02 regardless of how
good the sink is.

## 10. Sink options

| | A — Object storage with retention lock, assurance-administered | B — Managed write-once log service | C — Verifiable/transparency log | D — Second database under assurance control |
|---|---|---|---|---|
| Write-once enforced against an administrator | Yes, in compliance mode | Depends on the service; often governance-grade only | Yes, by construction | **No** — a DBA can rewrite |
| Head is addressable for read-back | Yes — the object *is* the head | Yes | Yes, with an inclusion proof | Yes |
| Receipt supports independent verification | Via assurance-credentialled read-back | Via read-back | **Strongest** — a signed proof verifiable without trusting the operator | Only as much as the DBA is trusted |
| Low-latency out-of-band writes for the 7 immediate kinds | Yes | Yes | Yes | Yes |
| Retention period immutable | Yes, if set in compliance mode | Service-dependent | Yes | No |
| Operational cost and complexity | Low | Low | **Highest** — key management, proof verification, possibly a third party | Low |
| Independence from platform administration | Account and credential separation required | Same | Can be a genuinely third-party operator | Weakest — same DBA culture |
| Verdict | **Satisfies the modelled decision** at modest cost | Satisfies it if the service's lock is genuinely immutable — verify, do not assume | Satisfies it most strongly; the question is whether the assurance burden is proportionate to a Class 3 lab platform | **Does not satisfy** independent administration or retention lock |

A and C are both defensible, and the choice is a judgement about how much the
"collusion across domains" residual risk is worth spending to reduce. B is A with the
lock property delegated to a vendor's configuration, which is fine *if someone checks
it*. D is listed because it is the thing most likely to be built by accident under
schedule pressure, and it fails two required elements outright.

## 11. Recommendation (a proposal, not a decision)

**Option A**, with compliance-mode retention lock, a KMS-held non-exportable signing
key, and receipt issuance performed by an assurance-held credential outside Seal's
deployment. It satisfies every required element, and its weakness relative to C —
verification requires trusting that the sink operator honoured the lock — is the
weakness baseline §9.1 already documents as residual rather than eliminated.

**Add `key_id` to `AnchorReceipt` as part of F07's first commit**, whichever option is
chosen. §4's rotation questions cannot be answered later without migrating a persisted
record.

This is the pack's reading. The platform lead and assurance reviewer decide.

## 12. What must be verified before §14 is signed

None of this is verifiable in this repository, and a local mock is excluded by the
decision's own wording.

1. The selected sink's lock is tested by **attempting** an overwrite, a delete and a
   retention-period reduction with the most privileged credential available, and all
   three fail.
2. A receipt round-trip is demonstrated against the real sink, including the assurance
   read-back under a separate credential.
3. Receipt loss, replay, reordering, duplicate delivery and concurrent append are
   exercised — §9.1 requires these tested "before claiming integrity" — against the
   real sink, not the in-memory ledger.
4. A sink outage is injected and the measured behaviour matches §3.1: Untrusted within
   the interval, grants revoked, stop still effective, resume requires authorisation.
5. Rotation is exercised end to end, including verification of a pre-rotation head.
6. The administration separation at §5 is confirmed against a named role list by the
   assurance reviewer, not inferred from account structure.

## 13. Open questions for the deciding authorities

Numbered so the sections above can refer to one question rather than restate it.
Each belongs to the platform lead with the assurance reviewer, except where noted.

| # | Question | Raised in |
|---|---|---|
| Q1 | Which sink option — A (object storage, retention lock), B (managed write-once log) or C (verifiable/transparency log)? §11 proposes A on proportionality grounds; C is defensible if the assurance burden is judged worth it | §10, §11 |
| Q2 | Where does the signing key live, and can Seal's runtime use it without being able to export it? An exportable key makes every anchor forgeable by one compromised host | §7 |
| Q3 | Rotation interval, and whether a head signed by a retired key stays verifiable. This decides whether `key_id` is added to `AnchorReceipt`, which cannot be deferred: adding key identity after F07 writes the type migrates a persisted record | §4, §7 |
| Q4 | Who holds the verification public key and issues receipts? If Seal holds it, the "independent" verification is circular | §5, §8 |
| Q5 | The sink's administrator learns which tenants exist, how many audit events each generates and when. Does that disclosure need a contractual term, a privacy-notice entry, or both? D08's §14 Q4 asks the same question from the privacy side, and the two answers must match | §6 |
| Q6 | `IMMEDIATE_ANCHOR_KINDS` includes `INTEGRITY_STATE`, which baseline §9.1 does not list. Ratify the strengthening or strike it — but decide it rather than inherit it | §2 |
| Q7 | A receipt naming a head the ledger never produced is refused today. Is that an integrity incident or a transient error? §8 proposes incident, because it means the sink holds something Seal did not write | §8 |
| Q8 | What retention period is set at the sink? Anchors contain no content and never need disposal, so an indefinite period is available in a way it is not for evidence — but it should be chosen, not defaulted | §6 |
## 14. Decision record — unsigned

| Field | Value |
|---|---|
| Sink option selected (§10) | |
| Retention mode and period | |
| Key custody arrangement (§7) | |
| Rotation interval and pre-rotation verification policy | |
| Receipt issuance credential holder | |
| Administration separation confirmed (§5) | |
| §13's open questions answered and recorded | |
| §12 verification completed and evidenced | |
| Decided by — platform lead (named) | |
| Assurance reviewer (named) | |
| Date | |
| Review period | |

Until this is completed, F07 stays blocked, no anchor claim may be made, and
`Closure awaiting anchor` is where every High and Critical finding stops.

## 15. Provenance and limits

- **Drafted by an AI agent**, requiring competent human review. The same agent wrote
  the decision core this pack measures, so §3's probe is not independent verification
  of that code — it is a reading of what the code requires.
- **Nothing here is tested against a real sink**, because none exists and none is
  selected. Every row in §10 beyond the measured columns is an assessment of product
  categories, not of a procured service.
- **No gate item is closed.** D07 remains Unconfirmed / Blocked, F07 remains blocked,
  and SDLC G2 stays at 0/11.
- Sources: Integrated Baseline v1.6 §§8, 9, 9.1, 11.1, Appendix E.3 (D07), Appendix E.4
  (F07); Engineering Specification v1.6 §§5, 7; C01 and C02 amendments. Code read:
  `audit.py`, `integrity.py`, `closure.py`.
