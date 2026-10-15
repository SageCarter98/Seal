# D08 — privacy and evidence handling: decision pack

**Decision pack. Nothing here is a decision, and nothing here is an approved privacy
impact assessment.** D08 belongs to the privacy reviewer. This pack prepares the
artefacts that decision needs, reports two things the decision core does not enforce
that the documents assume it would, and marks every determination that cannot be made
without counsel.

| | |
|---|---|
| Decision | Approve privacy and evidence handling (Integrated Baseline v1.6, Appendix E.3, D08) |
| Accountable role | Privacy reviewer |
| Required evidence | "Seal PIA, data inventory, processing roles, minimization, access, retention/hold/disposal map; required before real personal data or external evidence" |
| Blocks | F08, the admission of any real personal data or external evidence (`PROHIBITED_CAPABILITIES.md` B4), and the privacy half of SDLC G2.06 |
| Depends on | D09 for every determination under Ghana's Data Protection Act, 2012 (Act 843) — §11 |
| Drafted | 2026-10-15, by Claude Opus 5 at the owner's instruction |
| Status | **Unconfirmed / Blocked. §14's decision record is unsigned.** |

## 1. The decision as the documents state it

**The duty is Seal's own, not the target's.** Baseline §11.1 opens by separating them:
"Seal's privacy duty is separate from the target organization's obligations." Seal
processes personal data about its *own* users — assessors, reviewers, remediation
owners — as well as whatever personal data turns up inside assessment evidence.

**It is a standing gate, not a one-off.** §11.1: "Before any real personal data or
externally sourced assessment evidence enters the platform, Phase 0 must complete and
approve a privacy impact assessment for Seal's own processing and assess the applicable
duties under Ghana's Data Protection Act, 2012 (Act 843)." And at the end of the same
section: the PIA, data inventory and retention/disposal map "are also standing gates on
external assessment and on the admission of real personal data."

**The PIA's required contents are enumerated, not left open.** §11.1 lists: the
controller/processor position, lawful and approved purposes, data subjects, evidence
and audit categories, sources, recipients, access roles, storage locations, transfers,
minimization and sanitization controls, data-subject handling, deletion method, breach
response and residual risk — and requires that it "specifically cover response
metadata, repository excerpts, dependency manifests, actor audit records, incident
evidence and chain-of-custody records."

**Reassessment is triggered, not scheduled.** "A material change in evidence
collection, tenancy, external hosting, automated decision support or target class
requires reassessment."

**Until then, the repository's position is already set:** "development and testing use
owned laboratory targets and synthetic or properly de-identified data only." That is
the state today, and §15 confirms it.

## 2. What is already built, and what it settles

`audit.EvidenceRecord` models sanitization flags, legal and incident holds, a disposal
timestamp and an access log. `export.py` models which roles may receive which fields.
Between them they settle part of the *access* element and part of the *hold* element,
and settle nothing else:

- `may_dispose` refuses disposal of held evidence, of unsanitized evidence, of evidence
  with no content digest, and of evidence already disposed.
- `may_export` refuses person fields to any role outside `PERSON_FIELD_ROLES`.
- `secret_quarantined` exists as a distinct flag from `sanitized`, so a credential
  found in evidence is not conflated with ordinary minimisation.

**What the core cannot do is establish that any of it is true.** `sanitized` is a
recorded flag, exactly as `verified` is in D07: the core refuses to dispose of evidence
not marked sanitized, but it cannot determine whether sanitization happened. **The
standard is D08's and the mechanism is F08's** — this pack's job is to say what the
flag must mean before anyone sets it.

## 3. The retention floor nothing enforces (measured)

Baseline §11.1 sets retention in years — "seven years after PM Gate 6", "life of the
product or service plus three years", and for raw evidence containing personal data,
"only while necessary for the approved assessment and verification purpose". A probe
asked the real disposal decision at a range of ages, with everything else valid:

```
legal hold set                                     -> DENY  ('HOLD_PREVENTS_DISPOSAL',)
incident hold set                                  -> DENY  ('HOLD_PREVENTS_DISPOSAL',)
not marked sanitized                               -> DENY  ('EVIDENCE_NOT_SANITIZED',)
no content digest                                  -> DENY  ('EVIDENCE_REQUIRED',)
already disposed                                   -> DENY  ('ALREADY_FINALIZED',)
sanitized, no hold, eight years old                -> PERMIT
sanitized, no hold, one day old                    -> PERMIT
sanitized, no hold, one second old                 -> PERMIT
```

**`may_dispose` has no concept of elapsed time.** Its `now` parameter is used only to
reject a naive datetime. The holds work; the floors do not exist.

This cuts in the direction people do not expect. The familiar privacy failure is
keeping data too long, and §11.1's "unnecessary personal data must not be retained"
guards that. But the schedule is a *minimum* retention for a reason — audit-chain
records, authorization records and sanitized findings are evidence that gate decisions
rest on, and the PM Framework requires them for seven years after Gate 6. As modelled,
**nothing prevents those being disposed of the day after they are written.** A record
that must be kept and a record that must go are not distinguishable to this decision.

Three ways to resolve it, and D08 picks:

| | Where the floor lives | Consequence |
|---|---|---|
| A | In the decision core: `may_dispose` gains a retention class and refuses early disposal | The floor is enforced wherever the decision is used; requires adding a record category to `EvidenceRecord`, which D08 must define anyway for the inventory |
| B | In F08's storage layer only | The core stays silent on it, and anything bypassing F08's workflow bypasses the floor |
| C | By process — a documented schedule and a periodic review | Matches the framework's own wording, enforces nothing, and is what exists today by default |

The pack proposes **A**, because the record category is an inventory output rather than
new modelling work, and because C is the status quo that produced this finding.

## 4. The role vocabulary nothing reconciles (measured)

Access is one of D08's five required elements. The same probe asked `may_export` for
person fields under each baseline §5 role identifier, then under each identifier the
core actually knows:

```
platform_owner                                     -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')
security_administrator                             -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')
authorized_assessor                                -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')
system_or_code_owner                               -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')
reviewer_or_auditor                                -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')
legal_compliance_adviser                           -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')
incident_coordinator                               -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')
executive_viewer                                   -> DENY  ('ROLE_NOT_PERMITTED', 'PERSON_FIELDS_NOT_PERMITTED')

assessor                                           -> DENY  ('PERSON_FIELDS_NOT_PERMITTED',)
manager                                            -> PERMIT  (person-cleared)
remediation_owner                                  -> DENY  ('PERSON_FIELDS_NOT_PERMITTED',)
reviewer                                           -> PERMIT  (person-cleared)
security_lead                                      -> PERMIT  (person-cleared)
```

**Not one baseline §5 identifier is recognised.** This is the gap
`FRONTEND_DESIGN_SPEC.md` raised as its Q1, reached from the privacy side: the eight
roles the baseline names and the five the core enforces are different vocabularies with
no mapping between them. For a design document that is an inconsistency. For an access
decision it is the whole control — an access rule that denies everything because it
recognises no identifiers is not a safe default, it is an unimplemented rule that has
not failed loudly yet.

Note also that `manager` is person-cleared in the core and **is not a baseline §5 role
at all**. D08 cannot approve an access map that grants person fields to a role the
governing document does not define. §14 Q2.

## 5. Element 1 — the PIA, and which parts can be written now

§11.1's required contents, with an honest status for each. "Draftable" means this pack
or a successor can write it from approved documents; "needs counsel" means D09; "needs
a decision" means another D-decision must land first.

| PIA content (§11.1) | Status | Note |
|---|---|---|
| Controller/processor position | **Needs counsel** | Turns on whether Seal acts for itself or on a client's instruction per target — §7 |
| Lawful and approved purposes | **Needs counsel** | Act 843 lawful basis; the *approved* purpose is in each authorization record |
| Data subjects | Draftable | §6 |
| Evidence and audit categories | Draftable | §6 — the core's record types enumerate these |
| Sources | Draftable | Scanner output, user actions, target responses |
| Recipients | **Needs a decision** | D07 fixes the audit sink operator, who becomes a recipient of tenant metadata |
| Access roles | **Blocked on §4** | Cannot be written against two unreconciled vocabularies |
| Storage locations | **Needs a decision** | D03/D05 have not fixed hosting; D07 adds the sink |
| Transfers | **Needs counsel** | Cross-border transfer is an Act 843 question if any component is hosted outside Ghana |
| Minimization and sanitization controls | Draftable as a standard | §8; the mechanism is F08's |
| Data-subject handling | **Needs counsel** | Access, correction and objection rights under Act 843 |
| Deletion method | Draftable | §10; "securely delete or anonymize and record the action" |
| Breach response | Partly draftable | The incident path exists in `incident.py`; notification duties need counsel |
| Residual risk | Draftable once the above resolve | Cannot be honest while half the rows are open |

**Six of fourteen need counsel and three need another decision.** That is the finding
of this element: the PIA is not a document someone has merely failed to write. It is
mostly unwritable today, and the critical path runs through D09's unissued counsel
instruction.

## 6. Element 2 — data inventory

Draftable now, and drafted here as a proposal. Categories follow §11.1's explicit list
plus what the core's record types actually hold.

| Category | Contains personal data? | Source | Where it lives |
|---|---|---|---|
| Response metadata | Possibly — headers, cookies, error bodies may carry identifiers | Target responses via scanner | Evidence store |
| Repository excerpts | Possibly — author names, comments, test fixtures | Source adapter | Evidence store |
| Dependency manifests | Unlikely, but maintainer names occur | Source adapter | Evidence store |
| Actor audit records | **Yes, inherently** — actor identity is the point | Platform users | Audit chain |
| Incident evidence | Possibly, and under hold when it exists | Incident path | Evidence store, held |
| Chain-of-custody records | Indirectly — who handled what, when | Platform | Audit chain |
| Finding person fields | **Yes** — `assessor`, `remediation_owner` | Platform users | Finding records, export-gated |
| Anchor payload | Tenant identifier, counter, hash, timestamp | Audit outbox | External sink (D07) |

Two rows deserve the privacy reviewer's attention specifically. **Actor audit records
cannot be minimised away** — the audit chain's entire purpose is attributing actions to
people, and it is retention-locked at the sink under D07. And the **anchor payload**
row means the sink operator learns which tenants exist and their event rates; D07's §6
refers that here, and it is a disclosure to a third party even though it contains no
content.

## 7. Element 3 — processing roles

**Needs counsel, and the pack will not guess.** The question is whether Seal is a
controller for its own processing (it decides purposes and means for its user records
— likely controller) while simultaneously a processor for assessment evidence
belonging to a client target (acting on the client's authorization — likely processor),
and whether that dual position holds under Act 843 as it does under comparable regimes.

That distinction determines who answers a data-subject request, who notifies a breach,
what the contract with each target organisation must contain, and whether the
authorization record doubles as a processing instruction. None of it is an engineering
judgement, and D09's instruction already has the shape to carry it — §11.

## 8. Element 4 — minimization and sanitization

The core's `sanitized` flag needs a definition before anyone can set it honestly.
Proposed as the standard, subject to the privacy reviewer:

1. **Minimise at collection, not after.** Evidence capture records the smallest
   response fragment that supports the finding — not whole response bodies by default.
   This is cheaper than sanitising later and is the only version that survives a storage
   compromise.
2. **Sanitisation removes**, at minimum: authentication material (cookies, tokens,
   `Authorization` headers), request and response bodies outside the matched fragment,
   and any field matching the personal-identifier patterns the inventory names.
3. **Credentials quarantine rather than sanitise.** `secret_quarantined` is already a
   separate flag; a discovered credential is an incident input, not something to scrub
   and forget.
4. **A sanitisation failure fails closed** — evidence that cannot be sanitised is not
   stored in the ordinary path. F08 implements; D08 approves the rule.
5. **The flag is set by the sanitiser, never by a caller.** Today nothing enforces
   this, because nothing sets it at all.

## 9. Element 5 — access

Blocked on §4's reconciliation. What can be stated now:

- Person fields are already gated, and the gate works for the identifiers it knows.
- Evidence *read* access has no decision at all. `EvidenceRecord.access_log` exists,
  nothing appends to it, and the only code that reads it renders its length as
  `access_count` in an export. So "who may read evidence containing personal data, and
  under what purpose" — which is the access element D08 must approve — is not merely
  unimplemented, it is unmodelled.
- **Proposed:** evidence read access becomes a decision in the core taking the actor,
  role, organisation and the record's category, with the access log written by that
  decision rather than by its callers. Making the log a by-product of the decision is
  what stops it drifting into decoration.

## 10. Element 6 — retention, hold and disposal map

§11.1's schedule, restated against Seal's own record types, with the enforcement point
each would need. This is the artefact the privacy gate names; it is proposed, not
approved.

| Seal record | §11.1 category | Floor | Hold overrides | Enforcement today |
|---|---|---|---|---|
| Gate decisions, exceptions, closure records | Charter/gate | 7 years after PM Gate 6 | Yes | **None** (§3) |
| Requirements, design, config, handover | Requirements/design | Product life + 3 years, never < 7 after Gate 6 | Yes | **None** |
| Audit chain, authorization records, sanitized findings | Risk/assurance/audit | 7 years after Gate 6 or final resolution, later of | Yes | **None** in core; sink is retention-locked under D07 |
| Raw evidence containing personal data | Raw/temporary | Only while necessary; review at closure, Gate 6, annually | Yes | Holds enforced; necessity and review are not |
| Benefits evidence | Benefits | 7 years after PM Gate 7 | Yes | **None** |

**The hold column is the one that works.** Legal and incident holds are enforced by
`may_dispose` and were tested. Everything in the floor column is a document.

One interaction to record explicitly, because it looks like a contradiction and is not:
D07's sink is retention-locked and cannot delete, while this map requires disposal.
They coexist only because the anchored payload is a tenant identifier, a counter, a
hash and a timestamp — no content. If anything else is ever written to the sink, that
compatibility ends, and the reassessment trigger in §11.1 ("a material change in
evidence collection... or external hosting") fires.

## 11. The D09 dependency, stated plainly

Six of §5's fourteen PIA contents need counsel. D09's counsel instruction is drafted at
[`D09_counsel_instruction_tooling_licences.md`](D09_counsel_instruction_tooling_licences.md)
and is **unissued, with no counsel engaged** — its current scope is tooling licences,
not Act 843.

So D08 has a sequencing problem that no amount of drafting here removes:

1. D09's instruction is issued and counsel engaged, with Act 843 scope added to it.
2. Counsel answers the controller/processor position, lawful basis, transfer position,
   data-subject handling and breach-notification duties.
3. The PIA's remaining rows are completed, §4's role vocabulary is reconciled, and the
   privacy reviewer approves.
4. Only then may real personal data or external evidence enter the platform.

**Proposed:** extend D09's instruction to carry the Act 843 questions rather than
raising a second counsel engagement. They go to the same adviser, and splitting them
invites two partial answers. §14 Q1.

## 12. Recommendation (a proposal, not a decision)

- Extend D09's instruction with the Act 843 determinations and issue it (§11).
- Reconcile the role vocabulary as a single named mapping used by the core, the
  frontend spec and this inventory (§4) — one list, not three.
- Enforce the retention floor in the decision core, option A (§3), adding a record
  category to `EvidenceRecord` that the inventory defines anyway.
- Make evidence read access a decision that writes its own access log (§9).
- Adopt §8's sanitisation standard as the definition of the `sanitized` flag.

Every one of these is a proposal to the privacy reviewer. None is approved, and this
pack approves nothing.

## 13. What must be verified before §14 is signed

1. Counsel's written answers to the §5 "needs counsel" rows exist and are recorded.
2. The role mapping at §4 is agreed and implemented, and the probe's second section
   shows baseline identifiers resolving.
3. The retention floor has an enforcement point, and a test demonstrates early disposal
   refused — not merely a schedule in a document.
4. An evidence read-access decision exists and writes the access log.
5. The sanitiser sets `sanitized`, and a test shows unsanitised evidence refused by the
   ordinary storage path.
6. The data inventory at §6 is confirmed against what F08 actually stores, once F08
   exists — the inventory here is derived from record *types*, not from stored data,
   because no real data exists to inventory.
7. The privacy reviewer is named, and is not the person who drafted the artefacts.

## 14. Open questions for the privacy reviewer

| # | Question |
|---|---|
| Q1 | Extend D09's instruction to carry the Act 843 determinations, or raise a separate engagement? (§11 proposes extending) |
| Q2 | `manager` is person-cleared in the core and is not a baseline §5 role. Remove it, or add it to §5? |
| Q3 | Where does the retention floor live — core, storage layer, or process? (§3 proposes the core) |
| Q4 | Does the sink operator's visibility of tenant identity and event rate (§6) require its own disclosure or contractual term? |
| Q5 | Is the audit chain's attribution of actions to named people in scope for data-subject correction rights, given it is append-only and retention-locked? |
| Q6 | What is the review cadence for "only while necessary" on raw evidence — §11.1 says at closure, Gate 6 and at least annually; is that adopted as written? |

## 15. Decision record — unsigned

| Field | Value |
|---|---|
| PIA approved (§5 complete, including counsel rows) | |
| Data inventory approved (§6) | |
| Processing roles determined (§7) | |
| Minimisation and sanitisation standard approved (§8) | |
| Access map approved (§9), role vocabulary reconciled | |
| Retention/hold/disposal map approved (§10) | |
| §13 verification completed and evidenced | |
| Privacy reviewer (named) | |
| Date | |
| Reassessment triggers acknowledged (§11.1) | |

Until this is completed, F08 stays blocked, SDLC G2.06 stays half-open, and
`PROHIBITED_CAPABILITIES.md` B4 stands: no real personal data and no real external
evidence enters this platform.

## 16. Provenance and limits

- **Drafted by an AI agent**, requiring competent human review, and an AI agent cannot
  hold the privacy reviewer's role under any reading of §11.1. §13 step 7 exists for
  that reason.
- **This is not a privacy impact assessment.** It is a pack that prepares one and
  reports why most of it cannot be written yet. Citing it as the PIA would close
  G2.06's privacy half with a document that explicitly declines to make the
  determinations the PIA requires.
- **No legal determination is made or implied**, under Act 843 or otherwise. The
  controller/processor position at §7 is left open deliberately.
- **No real personal data exists in this repository to inventory.** §6 is derived from
  the core's record types; development and testing use synthetic data on owned
  laboratory targets, as §11.1 requires.
- **No gate item is closed.** D08 remains Unconfirmed / Blocked, F08 remains blocked,
  SDLC G2 stays at 0/11.
- Sources: Integrated Baseline v1.6 §§5, 11, 11.1, Appendix E.3 (D08), Appendix E.4
  (F08); `PROHIBITED_CAPABILITIES.md` B4; `THREAT_MODEL.md` (the threat half of
  G2.06); `FRONTEND_DESIGN_SPEC.md` Q1. Code read: `audit.py`, `export.py`.
