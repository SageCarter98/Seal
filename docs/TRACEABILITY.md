# Requirement traceability — v1.6 contracts to modelled checks

Maps each v1.6 upgrade requirement (U01–U14) and v1.5 review correction
(C01–C03) to the module that models it and the tests that exercise it.

**Read the status column carefully.** "Modelled" means the pure decision has
executable checks. It does **not** mean the production control exists, has been
built, or has been accepted. Spec §2: *"Passing a model test is not acceptance
of the corresponding production control."*

Counts below are from `python -m pytest --collect-only -q`, run 13 October 2026.
Total: **668 tests, all passing**; `ruff check` and `ruff format --check` clean.

## Upgrade requirements

| ID | Required outcome | Module | Tests | Status |
|---|---|---|---|---|
| U01 | Revalidate scope and revocation at execution and every request | `authorization` | `test_authorization.py` (37) | Modelled |
| L01 | Versioned adapter contract and bounded parser | `admission` | `test_admission.py` (77) | **Modelled** — malformed, oversized, over-nested, unknown-version and cross-tenant output refused before parsing; allowlisted fields; traversal and URL references rejected. No adapter exists to produce real output (D04 unselected) |
| U02 | Enforce destinations and limits outside the scanner | `egress` | `test_egress.py` (40) | Modelled (decision only — no network capability exists) |
| U03 | Record successful, skipped, failed and unsupported checks | `coverage` | `test_coverage.py` (31) | Modelled |
| U04 | Bind closure to the repaired revision and independent proof | `closure` | `test_closure.py` (41) | Modelled |
| U05 | Separate lifecycle state from recurrence and exceptions | `lifecycle`, `identity` | `test_lifecycle.py` (34), `test_identity.py` (36) | Modelled |
| U06 | Version an explainable priority tree and expiry rules | `priority` | `test_priority.py` (46) | Modelled |
| U07 | Reconcile external anchors and gate high-risk closure | `audit` | `test_audit.py` (44) | **Partial** — chain, outbox and receipt semantics modelled; no real separated sink, no signature verification |
| U08 | Minimize evidence and enforce holds and disposal | `audit.EvidenceRecord`, `recovery.checkpoint_is_safe`, `export` | `test_audit.py::TestEvidenceCustody`, `test_recovery.py::TestCheckpointSafety`, `test_export.py::TestEvidenceViews` | **Partial** — hold, disposal, checkpoint-content and export-minimization decisions modelled: an evidence view exports custody metadata only, refuses unsanitized or quarantined material, and reduces the access log to a count. No storage, encryption or key administration |
| U09 | Derive identity and tenant context from trusted services | all modules | throughout | **Partial** — the organization boundary is carried through and hashed into every identity, and `admission` refuses a result that claims a different tenant; PostgreSQL RLS, connection-pool reuse and worker paths are untested because none exist |
| U10 | Pin tools, rules, data and transformation versions | `coverage.ToolRevisions`, `admission` | `test_coverage.py::TestPinnedRevisions`, `test_admission.py` (77) | **Partial** — the manifest pins every required input and untrusted adapter output is now bounded and validated; container admission and signature/provenance verification are absent |
| U11 | Persist incident halt, hold and notification decisions | `incident` | `test_incident.py` (38) | **Modelled** — halt, hold, routing from recorded contacts, no autonomous external contact, and an undetermined legal duty that escalates rather than defaulting to "no duty". The D09 counsel determination it defers to is still outstanding |
| U12 | Recover without duplicate or unauthorized execution | `recovery`, `integrity`, `closure` | `test_recovery.py` (52), `test_integrity.py::TestC02C`, `test_closure.py::TestC01D` | **Modelled** — idempotent delivery, single current lease, five-way retry revalidation, credential-free checkpoints and the v1.3 recovery targets. No real queue or persistence, so the timings are arithmetic over supplied measurements, not measured recovery |
| U13 | Show exposure, coverage, aging and reopen rates | `metrics`, `coverage` | `test_metrics.py` (32) | Modelled (measures only — no dashboard) |
| U14 | Bind release claims to evidence and authority | — | — | **Not started** — a gate record is a human authority's action, not code |
| W04 | Tenant-filtered JSON/CSV export with guarded output | `export` | `test_export.py` (62) | **Partial** — the serialization decision is modelled: membership-derived tenant scope, role gate, allowlisted columns, CSV formula guard, display escaping, canonical JSON, and deferred formats refused *as deferred*. The dashboard, HTTP surface and signed download are absent (W01–W03, F08) |

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
| L01 | Versioned adapter input/output contracts and bounded parser | **Decision half delivered**: `admission` validates untrusted adapter output against an expected binding with size, depth, type, enumeration, allowlist and reference checks, refusing hostile input before parsing. The adapter itself cannot be built — D04 has not selected Trivy or Semgrep. |
| W04 | Role-based dashboard, evidence views, management summary and tenant-filtered JSON/CSV export | **Decision half delivered**: `export` decides which rows may leave (tenant from authenticated membership, never from a request parameter), which columns may leave (allowlists that exclude person fields unless the role permits them, and have no column raw content could occupy), and how a value from untrusted adapter output is rendered (formula guard, uniform RFC 4180 quoting, display escaping, control characters refused). The dashboard, role session, HTTP response and signed download are W04's platform half and are **not started** — they depend on W01–W03 and F08. |
| F02–F08, L02–L05, W01–W03, W05 | — | Not started. The decision contracts several of them depend on are modelled here as reviewable design, which is what spec §5 permits as "fixtures… for permitted design work". |

## Design decisions taken here, and why

Seven places where the specification's intent needed a concrete choice. Each is
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

4. **Idempotency keys are namespaced per tenant rather than globally unique.**
   A first-pass test demanded that a cross-tenant key collision be *rejected*.
   That mechanism would have created the attack the test's own rationale said
   to prevent: burn a key in tenant A and tenant B's legitimate delivery gets
   refused. Per-tenant namespaces make the collision impossible instead, so one
   tenant's key choices cannot affect another's at all.

5. **A foreign-tenant row refuses the whole export rather than being
   filtered out of it.** W04's acceptance evidence is that the server
   enforces scope. Dropping the row would satisfy the letter of that and
   hide the real fault — a query that reached across tenants — behind a
   download that looks complete. The export is therefore all-or-nothing,
   and `TENANT_MISMATCH` names the condition.

6. **The CSV formula guard applies to text, not to typed numbers.** A `-`
   prefixed onto every negative number would corrupt the figures a reviewer
   is reading, so the guard runs on string cells — the ones an adapter chose
   the contents of — and numeric fields render as themselves. The trigger
   set includes tab, CR and LF as well as `= + - @ |`, because a spreadsheet
   strips leading whitespace before deciding whether a cell is a formula.

7. **`DutyStatus.UNDETERMINED` is distinct from `NO_DUTY`, and an unsigned
   status collapses to undetermined.** Spec §8 requires pending legal guidance
   to be "visibly owned and escalated, never silently treated as approval". A
   single boolean, or a `NO_DUTY` default, would make silence read as clearance.
   Exceeding the carried-forward 24-hour clock therefore reports elapsed time
   and escalates, but never asserts a breach of a duty nobody has determined.
