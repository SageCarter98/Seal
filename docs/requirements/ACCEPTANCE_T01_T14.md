# Acceptance cases T01–T14 — requirement-to-test mapping

**Draft mapping for D05. Almost nothing here has acceptance evidence, and that is the
honest state of the project, not a gap in this document.**

Two rules govern how to read it, both from approved documents:

- The thresholds are "proposed baseline criteria derived from v1.3... not confirmed
  results", and "dataset size, workload duration, environmental assumptions and
  measurement exclusions require approval before testing."
- Spec §2: "Passing a model test is not acceptance of the corresponding production
  control." So the **Model coverage** column below never belongs in the **Acceptance
  evidence** column. Everything in this repository is the former.

| ID | Threshold (proposed, from v1.3) | Model coverage today | Acceptance evidence | Blocked on |
|---|---|---|---|---|
| T01 | 100% executed jobs linked to valid authorization; zero successful scope-bypass | `authorization` (37 tests): revalidation per request, revocation, expiry, window, naive-time refusal | **None.** No job has ever executed | F02–F05, a recorded authorisation service |
| T02 | Zero successful cross-organization access in the release suite | Organisation carried and hashed into every identity; `admission` refuses a result claiming another tenant; `export` refuses a foreign-tenant row | **None.** The API, worker, cache and export paths the test requires do not exist | F02, F03, W04's platform half |
| T03 | Stop new outbound requests within 5s; workers terminate within 30s, every test | `recovery` models both targets as arithmetic over supplied measurements | **None.** Nothing can make an outbound request to stop | D06, F05 |
| T04 | ≥90% of selected seeded vulnerabilities detected | None possible — detection needs a scanner | **None** | D04, then L03/L05 |
| T05 | ≥95% same-finding identity stability and correct aliases; zero silent distinct merges | `identity` (36) and `lifecycle` (34): per-family tuples, volatile-field exclusion, alias and recurrence separation | **None.** `tools/d04_identity_probe.py` reports a signal on **simulated** fixtures and says so; that is a design input, not acceptance evidence | A versioned mutation set and real tool output (D04 §11 step 6) |
| T06 | 100% of defined significant events recorded; evidence mutation and chain tampering detected | `audit` (44) and `integrity`: chain, reorder/edit/delete detection, outbox and receipt semantics | **None.** No durable chain, no independent anchor verification | D07, F07 |
| T07 | 100% of closed high-risk findings contain verification evidence | `closure` (41): proof review, stale-intent rejection, reviewer independence | **None.** There is no population of findings to audit | W01–W03 |
| T08 | ≤5% of assigned findings later invalidated | `lifecycle` state separation | **Not measurable.** The baseline is explicit: "No assignments means not measurable, not 0%" | W02, and an observation period |
| T09 | Dispatch p95 ≤30s at 10 concurrent lab jobs; dashboard/API p95 ≤2s at 25 viewers and 100,000 findings | None — latency is not a decision | **None.** No dispatcher, no API, no dashboard | F02–F04, W04, H02 |
| T10 | Worker failure detection ≤30s; safe fail/resume ≤5 minutes | `recovery` (52): lease singularity, idempotent delivery, five-way retry revalidation, the v1.3 targets as arithmetic | **None.** No worker to kill | F03, H02 |
| T11 | Queue/worker-service recovery ≤15 minutes; zero loss of acknowledged audit events | `recovery` and `audit` outbox semantics | **None.** No queue, no persistence. The baseline warns: "do not infer durability from a healthy-run test" | F03, F07, H02 |
| T12 | Passive web ≤60 min; source ≤45; dependency ≤30, or a lower approved limit | None — these are measured, not decided | **None.** The measurement sheet is prepared and empty at `docs/decisions/D04_pinning_record.md` §5 | D04, then a laboratory run |
| T13 | 99.5% control-plane availability during approved pilot windows | None | **None.** No control plane and no pilot. The baseline requires the denominator and planned-window treatment defined *before* the pilot | Pilot authorisation (H05), F02–F08 |
| T14 | Privacy, safe-active allowlist, roles and incident controls pass approved cases | `incident` (38): halt, hold, routing from recorded contacts, no autonomous external contact, undetermined legal duty that escalates. `export`: role gate and allowlisted columns | **None.** The "approved cases" do not exist yet, and neither does the privacy assessment (D08) | D08, D09, L02, W02 |

## What D05 needs to decide about this table

1. **Approve or amend each threshold**, and with each one the dataset size, workload
   duration, environmental assumptions and measurement exclusions. The baseline forbids
   deciding those after the fact: "No cherry-picking or post hoc denominator changes
   are permitted."
2. **Confirm T08's and T13's measurability rule** — both have a defined "not
   measurable" state that must not collapse into a passing number. The decision core
   already enforces the same discipline elsewhere (`metrics` reports a zero denominator
   as unavailable rather than as one).
3. **Confirm that model coverage never counts toward acceptance**, which is what keeps
   this table's third column honest as the project grows.

## Status

Draft, unratified, prepared 2026-10-14 by an AI agent as part of the D05 readiness
pack. Counts are from `python -m pytest --collect-only -q` at 705 tests; see
[`../TRACEABILITY.md`](../TRACEABILITY.md) for the per-requirement map this table sits
alongside.
