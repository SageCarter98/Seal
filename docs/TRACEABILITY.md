# Requirement traceability — v1.6 contracts to modelled checks

Maps each v1.6 upgrade requirement (U01–U14) and v1.5 review correction
(C01–C03) to the module that models it and the tests that exercise it.

**Read the status column carefully.** "Modelled" means the pure decision has
executable checks. It does **not** mean the production control exists, has been
built, or has been accepted. Spec §2: *"Passing a model test is not acceptance
of the corresponding production control."*

Counts below are from `python -m pytest --collect-only -q`, run 12 October 2026.
Total: **427 tests, all passing**; `ruff check` and `ruff format --check` clean.

## Upgrade requirements

| ID | Required outcome | Module | Tests | Status |
|---|---|---|---|---|
| U01 | Revalidate scope and revocation at execution and every request | `authorization` | `test_authorization.py` (37) | Modelled |
| U02 | Enforce destinations and limits outside the scanner | `egress` | `test_egress.py` (40) | Modelled (decision only — no network capability exists) |
| U03 | Record successful, skipped, failed and unsupported checks | `coverage` | `test_coverage.py` (31) | Modelled |
| U04 | Bind closure to the repaired revision and independent proof | `closure` | `test_closure.py` (41) | Modelled |
| U05 | Separate lifecycle state from recurrence and exceptions | `lifecycle`, `identity` | `test_lifecycle.py` (34), `test_identity.py` (36) | Modelled |
| U06 | Version an explainable priority tree and expiry rules | `priority` | `test_priority.py` (46) | Modelled |
| U07 | Reconcile external anchors and gate high-risk closure | `audit` | `test_audit.py` (44) | **Partial** — chain, outbox and receipt semantics modelled; no real separated sink, no signature verification |
| U08 | Minimize evidence and enforce holds and disposal | `audit.EvidenceRecord` | `test_audit.py::TestEvidenceCustody` | **Partial** — hold and disposal decisions modelled; no storage, encryption or key administration |
| U09 | Derive identity and tenant context from trusted services | all modules | throughout | **Partial** — the organization boundary is carried through and hashed into every identity; PostgreSQL RLS, connection-pool reuse and worker paths are untested because none exist |
| U10 | Pin tools, rules, data and transformation versions | `coverage.ToolRevisions` | `test_coverage.py::TestPinnedRevisions` | **Partial** — the manifest pins every required input; container admission and signature/provenance verification are absent |
| U11 | Persist incident halt, hold and notification decisions | — | — | **Not started** — needs D09/D10; `integrity` covers the halt, not the incident path |
| U12 | Recover without duplicate or unauthorized execution | `integrity`, `closure` | `test_integrity.py::TestC02C`, `test_closure.py::TestC01D` | **Partial** — resume authorization and stale-decision rejection modelled; no queue, lease or checkpoint persistence |
| U13 | Show exposure, coverage, aging and reopen rates | `metrics`, `coverage` | `test_metrics.py` (32) | Modelled (measures only — no dashboard) |
| U14 | Bind release claims to evidence and authority | — | — | **Not started** — a gate record is a human authority's action, not code |

## v1.5 review corrections

Each correction's own named acceptance scenarios are implemented as test classes
with matching names.

| ID | Correction | Scenario | Test |
|---|---|---|---|
| C01 | Reject stale closure intents | C01-A delayed receipt after recurrence or replacement evidence | `test_closure.py::TestC01A` (5 tests) |
| | | C01-B racing intents, reordered and duplicate receipts | `TestC01B` (4) |
| | | C01-C both serial orders of recurrence and finalization | `TestC01C` (4) |
| | | C01-D crash between receipt verification and commit | `TestC01D` (2) |
| C02 | Stop active assessment when integrity is unavailable | C02-A ten active jobs, each trigger, 5 s / 30 s budgets | `test_integrity.py::TestC02A` (8) |
| | | C02-B partitioned state, cached grants expire in budget | `TestC02B` (6) |
| | | C02-C restore with queued retries, stay stopped until resume | `TestC02C` (6) |
| | | C02-D lose both sink and primary audit path | `TestC02D` (2) |
| C03 | Keep accepted and suppressed risks in exposure measures | C03-A ten-finding fixture including recurrence | `test_metrics.py::TestC03WorkedFixture` (6) |
| | | C03-B disposition filters leave overall totals unchanged | `TestC03B` (4) |
| | | C03-C approved false-positive correction and history | `TestC03C` (8) |
| | | C03-D zero denominator is Not available | `TestC03D` (3) |

### C03's worked fixture, reproduced exactly

Spec C03 supplies this fixture and its expected values. `TestC03WorkedFixture`
asserts each one:

| Condition | Closure rate | Unresolved exposure |
|---|---|---|
| 3 Closed, 2 Risk accepted, 1 Suppressed, 4 other unresolved | 3/10 = 30% | 7 |
| …then one Closed finding recurs | 2/10 = 20% | 8 |
| An unresolved finding becomes accepted or suppressed | unchanged | unchanged |
| Zero confirmed findings | Not available | 0 |

## Work-package coverage

| Package | Deliverable | This increment |
|---|---|---|
| F01 | Repository structure, pinned dependency policy, internal CI, secret handling, controlled build | **Structural half delivered**: layout, zero-dependency policy, CI (lint + format + test on 3.10/3.13 + purity boundary + credential guard), `.gitignore` excluding evidence and key material. Synthetic lab isolation and the controlled build process remain open; F01 stays **Blocked** on D03 and D05. |
| F02–F08, L01–L05, W01–W05 | — | Not started. The decision contracts several of them depend on are modelled here as reviewable design, which is what spec §5 permits as "fixtures… for permitted design work". |

## Design decisions taken here, and why

Three places where the specification's intent needed a concrete choice. Each is
a judgment that should be reviewed, not a settled requirement:

1. **`Action.TRIAGE` as a distinct priority outcome.** Spec §6 says unknown
   exposure, impact or severity "requires triage; it must not default to the
   least urgent branch". Without a separate value, `None` collapses into
   `TRACK`. The v0.1.0 model instead raised on missing context, which forbids
   expressing the honest early-triage state at all.

2. **A false positive leaves a cohort only on a recorded correction.** C03
   permits departure "only under the predeclared reviewed correction rule". A
   first pass here excluded false positives whenever a rule merely *existed*,
   which made the denominator shrink without any review having happened — and
   double-counted the removal in the adjustment log. Now both the declared rule
   and a recorded per-finding correction are required.

3. **The integrity generation increments on *entry* to Untrusted, not on
   resume.** C02 requires outstanding grants and leases revoked at detection.
   Incrementing only on resume would leave every grant minted before the
   failure valid for the whole outage — the exact window C02 closes.
