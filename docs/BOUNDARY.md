# What this repository is, and what it is not

**Status: controlled Phase 0 preparation only.** Nothing here asserts an
institutional approval, a gate decision, or an implemented security control.

## What exists

One Python package, `seal.core`: pure, offline models of the engineering
contracts in **Seal Integrated Engineering Specification v1.6** (7 September
2026), including the three v1.5 review corrections C01–C03.

Every function in it is a function of its arguments. There is no I/O at all —
and that is enforced, not promised. `tests/test_boundary.py` parses every core
module and fails the build if any of them imports a network, database,
filesystem, subprocess or web-framework library, reads the wall clock, calls a
random source, opens a file, or evaluates code. `now` is a parameter everywhere.

## What does not exist

Quoting spec §"Source delivery and current revision" directly:

> This is not a deployed security system. It has no live scanner, service API,
> database, user login or target-changing capability.

Concretely absent, and absent **deliberately**:

| Not here | Why | Blocked on |
|---|---|---|
| FastAPI service, PostgreSQL, Redis/Celery | F02–F08 foundation work | D03, D05 |
| ZAP or Trivy/Semgrep adapter | L01–L03 | D04 (adapter not selected) |
| Any outbound network capability | F05 | D06 (egress design unapproved) |
| External signed audit sink, key custody | F07 | D07 |
| Evidence storage, retention, disposal | F08 | D08 |
| Web dashboard, HTTP export endpoint, signed downloads | W04's platform half | W01–W03, F08 |

A decision pack for D04 — the unselected Trivy/Semgrep adapter — is at
[`docs/decisions/D04_scanner_adapter_selection.md`](decisions/D04_scanner_adapter_selection.md),
with the empty pinning and evidence form it will need at
[`docs/decisions/D04_pinning_record.md`](decisions/D04_pinning_record.md) and the
identity probe behind its §5 at [`tools/`](../tools/README.md). It is a pack, not a
decision: the selection is unrecorded and the adapter row above stays blocked until a
named authority signs §13. The pinning form is empty, and the probe's fixtures are
simulated, because populating either requires running a scanner — which is exactly
what this repository cannot do.

D05's readiness pack is at
[`docs/decisions/D05_baseline_readiness.md`](decisions/D05_baseline_readiness.md),
with two drafted artefacts under `docs/requirements/`: a
[prohibited-capability specification](requirements/PROHIBITED_CAPABILITIES.md) and the
[T01–T14 acceptance mapping](requirements/ACCEPTANCE_T01_T14.md). **Read the
prohibited-capability list against this file, not as part of it** — this document says
"not built yet, and here is the blocking decision"; that one says "must never exist, or
only under one named authorisation". D05 itself is blocked: there is no threat model,
and the pack says so rather than implying these documents add up to one.

The licence question that pack's §6.1 raises is drafted for counsel at
[`docs/decisions/D09_counsel_instruction_tooling_licences.md`](decisions/D09_counsel_instruction_tooling_licences.md).
That instruction is **unissued and no counsel is engaged**, so the Semgrep rule-licence
position is Undetermined — in the sense `incident.DutyStatus.UNDETERMINED` means it,
which is deliberately not a synonym for permitted. Until it is answered, no Semgrep
rule content enters this repository, as a fixture or otherwise.

The `release` module decides whether a claim's evidence supports it and who may accept it. It cannot accept anything: there is no `approve` or `sign_off` function, no module-level structure to write a decision into, and a test parses the module to keep it that way. Gate decisions stay where the PM Framework puts them.

The `export` module decides which rows and columns may leave the system and how a cell or a display string is rendered. It cannot write a file, serve a download or learn who is asking — the role and the organization are inputs supplied by a caller, which is why a cross-tenant export attempt is testable here as a row whose organization differs from the authenticated one.

The `egress` module decides whether a request *would* be permitted. It cannot
make one. Address resolution is an input supplied by a caller, which is exactly
why DNS rebinding is testable here as two different address lists for one host.

## Why the core is pure

Not stylistic. The adversarial scenarios spec §10 requires are only expressible
as fixtures if the decisions are pure:

- a **DNS rebind** is two resolved-address lists for the same host;
- a **late anchor receipt** is a receipt with a later `received_at`;
- a **crash between receipt verification and commit** (C01-D) is simply not
  calling `finalize`, then calling it later against moved-on state;
- a **stop budget** is arithmetic on two supplied timestamps.

A core that read its own clock or opened its own sockets could not test any of
these without a running system — and the running system is what is gated.

## How to read a passing test here

A passing test in this repository demonstrates that **the modelled decision
behaves as the specification describes**. It is not acceptance evidence for a
production control, and the specification says so in its own words:

> Passing a model test is not acceptance of the corresponding production
> control. None of the rows constitutes an approval signature.

C01 and C02 each add their own version of the same caveat — "acceptance awaits
real integration tests" and "acceptance awaits runtime evidence".

The boolean attestations in `VerificationResult` (`authorized`,
`integrity_valid`) and `PolicyState` (`phase0_approved`, `integrity_trusted`)
are **test inputs**. In the real platform each is derived from the trusted
service that owns that answer. Setting `phase0_approved=True` in a fixture
grants nothing; spec §3 is explicit that "no flags in this package grant
institutional authority."

## Relationship to the historical v0.1.0 package

`Seal_Upgrade_Offline_Validation_v0_1_0.zip` contains an earlier offline
decision model (`seal_spec/policy.py`, 31 tests). Its own README notes it
predates the v1.6 corrections. It has no C01 stale-intent logic, no C02
integrity state machine and no C03 exposure metrics.

This package supersedes it as a working reference. It is not a revalidation of
it, and the v0.1.0 ZIP remains unchanged historical material.

## Governance

Both KenAddme institutional frameworks apply: **PM Class A** and **Software
Class 3**, as *proposed* in Stage Implementation Plan v1.2 decision D02 — that
classification is not yet signed, and blocker 2 remains open.

Gate status is tracked outside this repository, in the `pm-sdlc-tracker`
database for `C:\Projects\Seal`. No code change in this repository can record a
gate decision; that remains a named human authority's action under PM Framework
§3.3.
