# D05 — baseline PRD and architecture: readiness pack

**Not the baseline.** D05 is baselining the PRD and architecture, which is the
Product/security lead's artefact and signature. This pack does three things instead:
it reports what each of D05's seven required evidence elements already has behind it,
it discharges the one duty in D05 that was mechanical rather than deliberative (the
reconciliation), and it names what only the authority can decide.

| | |
|---|---|
| Decision | Baseline PRD and architecture (Integrated Baseline v1.6, Appendix E.3, D05) |
| Accountable role | Product/security lead |
| Required evidence | "Requirement IDs, prohibited capabilities, acceptance cases, threat model, interface contracts, fingerprint and priority specifications" |
| Additional duty | "Existing PRD, source package and test results remain separately versioned and must be reconciled under D05" |
| Blocks | F01 (with D03), then F02/F03, and much of Phase 1 |
| Drafted | 2026-10-14, by Claude Opus 5 at the owner's instruction |
| Status | **Unconfirmed / Blocked. Nothing here is baselined or approved.** |

## 1. Readiness at a glance

| D05 evidence element | State | Where it stands |
|---|---|---|
| Requirement IDs | **Substantially in place** | U01–U14, C01–C03, L01 and W04 are mapped to modules and tests in `docs/TRACEABILITY.md`, which is current as of 705 tests |
| Prohibited capabilities | **Drafted here** | `docs/requirements/PROHIBITED_CAPABILITIES.md` — needs ratification, see §5 |
| Acceptance cases | **Drafted here, mostly unevidenced** | `docs/requirements/ACCEPTANCE_T01_T14.md` — the cases exist in the baseline; almost none has evidence, and the thresholds need approval |
| Threat model | **Absent. No basis at all** | §4. This is the element that blocks D05, and nothing in the repository or the document set is a threat model |
| Interface contracts | **Partially in place** | The adapter result contract is specified and enforced in `admission.py`; export and release contracts are modelled. No HTTP API contract exists, because no API exists |
| Fingerprint specification | **In place** | `identity.py`: per-family tuples, `FINGERPRINT_VERSION`, the volatile-field exclusion, organisation and target hashed into identity |
| Priority specification | **Structure in place, numbers not** | `priority.py` models the dimensions, floors and unknown-handling; the numeric thresholds are explicitly D10 policy candidates, not D05's to set |
| Reconciliation duty | **Discharged, see §3** | v0.1.0 reran and compared; one input is missing, see §2 |

## 2. An input D05 asks for does not exist

The baseline says: "Existing PRD, source package and test results remain separately
versioned and must be reconciled under D05."

The source package and test results exist and are reconciled in §3. **The PRD does
not exist in the controlled document set.** `Seal_All_Documents_2026_09_10.zip` is
tracked in this repository, and its own `README.txt` states it "includes the nine
available project/supporting files listed below". Those nine are the two governing
frameworks, the v1.5 and v1.6 specifications, the v1.5 and v1.6 baselines, the Stage
Implementation Plan v1.2, the v1.4 upgrade proposal, and the historical v0.1.0
validation ZIP. None of them is a PRD.

So one of these is true, and the owner knows which:

- **A PRD exists outside the controlled set.** Then it needs to be brought in and
  versioned before D05 can reconcile against it, and whatever it says may change this
  pack's conclusions.
- **No PRD was ever written.** Then D05 is not reconciling a PRD, it is *authoring*
  one, and the decision record should say so rather than referring to an "existing
  PRD" that nothing points to.

This is not a blocker I can resolve by looking harder; it is a question about what
exists. Flagging it is the whole of my contribution here.

## 3. The reconciliation, discharged

### 3.1 The historical suite now reruns — first time since packaging

The v1.6 baseline says of v0.1.0: "The 31 offline tests reported by the proposal are
historical synthetic-model evidence only and **were not rerun in this merge**."

They have now been rerun, on 2026-10-14, from
`03_Historical_Validation/Seal_Upgrade_Offline_Validation_v0_1_0.zip` extracted to a
scratch directory:

```
python -m unittest discover -s tests
...............................
Ran 31 tests in 0.010s
OK
```

All 31 pass on current Python. **What that establishes and what it does not:** the
historical package is internally consistent and still executes. It is not evidence
about v1.6, because it predates the C01–C03 corrections — it has no stale-intent
logic, no integrity state machine and no exposure metrics. Running old tests
successfully is not verification of new requirements.

### 3.2 Requirement-by-requirement, v0.1.0 against the current core

v0.1.0's own `docs/traceability.csv` recorded a status per requirement. Compared with
`docs/TRACEABILITY.md` as it stands at 705 tests:

| ID | v0.1.0 status | v0.1.0 tests | Current status | Movement |
|---|---|---|---|---|
| U01 | Model tested | ScopeTests | Modelled (`authorization`, 37) | Deepened |
| U02 | **Design only** | None | Modelled (`egress`, 40) | **Newly modelled** |
| U03 | Model partial | 1 test | Modelled (`coverage`, 31) | Deepened |
| U04 | Model tested | ClosureTests | Modelled (`closure`, 41) | Deepened |
| U05 | Model partial | IdentityTests + 1 | Modelled (`lifecycle` 34, `identity` 36) | Deepened |
| U06 | Model partial | PriorityTests | Modelled (`priority`, 46) | Deepened |
| U07 | Local model only | IntegrityTests | Partial (`audit`, 44) | Deepened; still no real sink |
| U08 | **Design only** | None | Partial (`audit`/`recovery`/`export`) | **Newly modelled** |
| U09 | Boundary model only | 3 suites | Partial (all modules) | Deepened; no RLS |
| U10 | **Design only** | None | Partial (`admission` 77, `ToolRevisions`) | **Newly modelled** |
| U11 | **Design only** | None | Modelled (`incident`, 38) | **Newly modelled** |
| U12 | **Design only** | None | Modelled (`recovery`, 52) | **Newly modelled** |
| U13 | **Design only** | None | Modelled (`metrics`, 32) | **Newly modelled** |
| U14 | Preparation evidence only | the 31-test report | Partial (`release`, 34) | **Newly modelled** |

Two rows exist now that v0.1.0 did not track at all: **L01** (`admission`, 77 tests)
and **W04** (`export`, 62 tests).

### 3.3 Nothing was dropped on the way

A requirement can be lost by a rewrite, so each of v0.1.0's 31 behaviours was checked
for a counterpart rather than assumed to have one. Its distinctive cases all have
current equivalents, confirmed by name in the current suite: naive-time rejection,
volatile fields excluded from identity, exact-expiry denial, EPSS freshness handling
(fresh, stale and absent all tested separately), event reorder detection,
cross-organisation denial, and distinct identity for a different route parameter.

v0.1.0's public API — `assess_scope`, `fingerprint`, `prioritize`, `closure_decision`,
`recurrence`, `append_event`, `verify_chain` — maps onto `authorization`, `identity`,
`priority`, `closure`, `lifecycle` and `audit` respectively.

### 3.4 What has not moved at all

v0.1.0's traceability carried a `remaining_implementation` column: a trusted approval
service, egress enforcement, a real coverage manifest from a scanner, trusted evidence
and external receipts, aliases and reversible merges, policy approval and threat
imports, a durable chain and signed separate sink, encryption and retention, MFA and
PostgreSQL RLS, pinned and verified scanner inputs, persisted incident handling,
lease and crash recovery, a role-based dashboard.

**None of it has been delivered.** Every item is still an F, L or W package, still
gated behind D03/D05/D06/D07/D08. The core got deeper; the system did not get built.
Anyone reading §3.2's "newly modelled" column should read this paragraph next to it.

**Reconciliation conclusion:** the current decision core supersedes v0.1.0 as the
model layer for all fourteen upgrade requirements, with no behaviour dropped, and
v0.1.0 remains unchanged historical material. The implementation gap v0.1.0 recorded
is unchanged.

## 4. The element that blocks D05: there is no threat model

D05 requires one. SDLC G2.06 ("Threat model and privacy assessment") is Not started.
Nothing in this repository or the document set is a threat model: the baseline states
threat-model *requirements* in several places, and D06 is to produce a
"data-flow/threat model" for the egress boundary specifically, but no document
enumerates assets, actors, entry points, trust boundaries, threats and mitigations.

Being precise about what exists, because it is more than nothing and less than a
threat model:

- `docs/BOUNDARY.md` documents the trust boundary and what is deliberately absent.
- `admission.py` is a working enforcement point for the primary untrusted input, with
  its reasoning written down.
- The baseline's §12 covers ethical, legal and governance conditions, and §12.1–12.3
  cover the regulatory gate, out-of-scope discovery and active-compromise escalation.

What is missing is the systematic pass: for each asset and trust boundary, which
threats apply, which are mitigated by a control that exists, which are accepted, and
which are deferred to a package that has not been built. That document is draftable
from material already in hand — the spec's trust boundaries, the modules' own
reasoning, and the prohibited-capability list in §5 — and it would serve both D05 and
G2.06. **It is the obvious next piece of work, and it is not in this pack**, because
a threat model assembled as an afterthought to something else is how threat models
become decoration.

## 5. Prohibited capabilities: a distinction worth not blurring

`docs/requirements/PROHIBITED_CAPABILITIES.md` is drafted alongside this pack. It
exists because `docs/BOUNDARY.md` answers a different question, and conflating the two
would be a real error:

- **`BOUNDARY.md` says: not built yet, and here is the decision that blocks it.** A
  FastAPI service is absent because F02–F08 are gated behind D03/D05 — it is *expected*
  to exist later.
- **`PROHIBITED_CAPABILITIES.md` says: must never exist, or must never exist without a
  specific named authorisation.** Seal autonomously filing a regulatory report is not
  a thing waiting on a work package. It is forbidden, and the spec says so.

The draft separates three tiers — never permitted, permitted only under a specific
recorded authorisation, and deferred-but-expected — and cites the source for each.
**It needs ratification**, not just review: a prohibition that nobody signed is a
preference, and the whole point of the list is that it binds later work.

## 6. What only the authority can decide

Six items. None of them is a gap in research; each is a choice.

1. **The deployment model.** Operated service, licensed deployment, or both. This was
   surfaced by the D09 instruction, which has to ask counsel about both because
   nothing has decided it — see `D09_counsel_instruction_tooling_licences.md` §3. The
   answer affects the Act 1038 characterisation, the tool-licence position, the
   tenancy architecture and the threat model. **It is the highest-value thing on this
   list**, and it is cheap to decide relative to what it unblocks.
2. **Whether the PRD exists** (§2), and if not, that D05 authors one.
3. **Ratification of the prohibited-capability list** (§5), including whether anything
   should move between its three tiers.
4. **The acceptance thresholds**, with the dataset size, workload duration,
   environmental assumptions and measurement exclusions the baseline requires approved
   before testing. The T01–T14 numbers are "proposed baseline criteria... not
   confirmed results".
5. **Which numerics belong to D10 rather than D05** — the priority tree's thresholds,
   remediation deadlines and threat-data freshness are D10's by Appendix E.3, and D05
   should state that boundary rather than quietly setting them.
6. **The repository layout deviation.** The baseline recommends `docs/requirements/`,
   `docs/decisions/`, `docs/gates/`, `services/`, `adapters/`, `web/`,
   `db/migrations/`, `infra/lab/`, and `tests/{unit,integration,safety,acceptance}/`
   "once implementation is authorized". This repository has `src/seal/core/` and a flat
   `tests/`, because it holds a pure decision core and nothing else. The deviation is
   deliberate and documented, but it is D05's job to confirm it rather than let it
   stand by default.

## 7. What this pack is not

- **Not the baselined PRD or architecture.** It is the readiness assessment and the
  reconciliation, plus two drafted artefacts that need ratification.
- **Not a threat model**, and it says so loudly in §4 rather than implying the
  existing documents add up to one.
- **Not an approval.** D05 stays Unconfirmed / Blocked. F01 stays blocked behind D03
  and D05.
- **Not a claim that the core's depth is progress toward delivery.** §3.4 is there to
  prevent exactly that reading.
- **Drafted by an AI agent**, and requiring competent human review before it informs
  the baseline decision.
