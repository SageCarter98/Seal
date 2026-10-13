# Seal 🦭

**Find the crack. Close the weakness. Prove it is sealed.**

An authorized vulnerability assessment and closure system. The hard part is not
finding weaknesses — it is *proving* one was actually closed. Seal is built
around that proof, which is why its engineering specification spends most of its
length on what each component must demonstrate before another trusts it.

> Owner: Freston Kenny Adedeme
> Controlling document: Seal Integrated Concept and Implementation Baseline
> v1.6, 7 September 2026

## Status — read this first

**Controlled Phase 0 preparation only.** Stage Implementation Plan v1.2 records
the project as *HOLD / not gate-ready for implementation commitment, laboratory
scanning, external pilot or production use*, with all eleven Phase 0 decisions
(D01–D11) open.

This repository contains **one Python package of pure decision logic** and
nothing else. There is no scanner, no API, no database, no login, and no ability
to send a single packet to any target. See [`docs/BOUNDARY.md`](docs/BOUNDARY.md)
for exactly what is and is not here, and why.

A passing test here shows that a *modelled decision* behaves as the
specification describes. It is not acceptance evidence for a production control.

## What this increment delivers

| | |
|---|---|
| Tests | **427**, all passing |
| Lint | `ruff check` and `ruff format --check` clean |
| Runtime dependencies | **zero**, enforced by test |
| Python | 3.10+ |

The nine contract modules, and the requirement each one implements:

```
src/seal/core/
  authorization.py   U01  scope and revocation at four checkpoints; execution grants
  egress.py          U02  destination and redirect decisions at the boundary
  coverage.py        U03  manifests; Complete/Partial/Failed/Stopped/Not assessed
  identity.py        U05  versioned fingerprints; reviewed reversible aliases
  lifecycle.py       U05  work state, recurrence and dispositions on separate axes
  priority.py        U06  the SSVC-style tree, four dimensions kept apart
  audit.py       U07/U08  hash chain, anchor outbox, evidence custody
  integrity.py       C02  admission state, generation, stop budgets
  closure.py     U04/C01  proof review, then stale-intent finalization
  metrics.py     U13/C03  exposure measures with visible denominators
```

[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) maps every requirement to its
tests and states honestly which are only partially modelled.

## The four contracts worth understanding

**Closure is a proof decision, not an absent alert.** A finding closes only on
the same organization, target, finding identity and tested control; the approved
profile; *Complete* coverage; a scan after the recorded fix; the repaired
revision; valid authorization; a sanitized evidence digest; and a reviewer who
is neither the assessor nor the fixer. Anything less is *inconclusive*, and the
decision says what evidence is missing.

**A late receipt cannot close a finding (C01).** High and Critical closure waits
in `Closure awaiting anchor` for an independently verified external receipt.
When that receipt arrives, finalization re-checks everything: the intent is
still the active one, the finding is still at its expected version
(compare-and-swap), the evidence revision is unchanged, and no contradictory
observation was admitted after the intent's watermark. A receipt that arrives
after a recurrence is *stale* — it is preserved, and the finding stays open.

**Losing integrity stops work already running (C02).** A broken chain, a failed
durable append, or an anchor more than fifteen minutes overdue flips admission
to `Untrusted` and increments a generation counter. Every outstanding execution
grant then fails validation on next use — nothing has to be hunted down and
cancelled. Measured ceilings: no new egress after 5 s, workers terminated within
30 s. Requests already transmitted cannot be recalled, so residual exposure is
recorded rather than papered over.

**Accepted risk is still exposure (C03).** The verified closure rate is
currently-verified Closed over *all* confirmed findings. Risk accepted and
Suppressed stay in the denominator permanently and never enter the numerator;
so do Reopened and Closure awaiting anchor. No filter, override or display
change can reduce reported exposure. Zero confirmed findings reports
`Not available`, never 100%.

## Running it

```bash
python -m pip install -e ".[dev]"
python -m pytest                       # 427 tests
python -m pytest tests/test_boundary.py -v   # the purity boundary
python -m ruff check src tests
```

No dependency installation beyond pytest and ruff, no credentials, no network
access, and no services to start.

## The purity boundary, enforced

Every contract is a function of its arguments. `now` is always a parameter —
nothing reads a clock. `tests/test_boundary.py` parses each core module and
fails the build if one imports a network, database, filesystem, subprocess or
web-framework library, reads the wall clock, calls a random source, opens a file
or evaluates code.

That constraint is what makes the adversarial scenarios testable at all: a DNS
rebind is two resolved-address lists for one host, a late receipt is a later
timestamp, and a crash between receipt verification and commit is just calling
`finalize` later against state that has moved on.

## Governance

Both KenAddme institutional frameworks apply. Proposed classification: **PM
Class A / Software Class 3** (Stage Plan D02 — not yet signed). Gate status
lives in the `pm-sdlc-tracker` database for this project, not in this
repository, and no code change here can record a gate decision.

## Documents

| Document | Version | Location |
|---|---|---|
| Integrated Concept and Implementation Baseline | v1.6 | `Seal_Integrated_Baseline_v1_6.docx` |
| Integrated Engineering Specification | v1.6 | `Seal_Engineering_Specification_v1_6.docx` |
| Stage Implementation Plan | v1.2 | inside `Seal_All_Documents_2026_09_10.zip` |
| Governing PM / SDLC frameworks | v1.0 / v1.1 | inside the same ZIP |
| Historical offline validation | v0.1.0 | inside the same ZIP — predates the v1.6 corrections |
