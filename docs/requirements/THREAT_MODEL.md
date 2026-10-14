# Seal threat model — draft for D05 and SDLC G2.06

**Draft, unapproved, and half of G2.06.** G2.06 is "threat model and privacy
assessment". This is the threat model only; the privacy assessment is D08's, needs the
PIA, data inventory and retention map, and is not attempted here. Closing G2.06 needs
both.

| | |
|---|---|
| Purpose | Defensive. Required by D05's evidence list and SDLC G2.06 |
| Method | Asset and trust-boundary enumeration, then abuse paths prioritised by impact, each with its control state and evidence |
| Scope | The Seal system as specified in Integrated Baseline v1.6 and Engineering Specification v1.6, including components that do not exist yet |
| Drafted | 2026-10-14, by Claude Opus 5 at the owner's instruction |
| Status | **Unapproved draft. Not a security assessment, not an audit, not independent review (that is H01).** |

## 0. How to read the control-state column

Most of Seal does not exist. A threat model that says "mitigated" about a control
nobody has built would be worse than no threat model, so every row carries one of:

| State | Meaning |
|---|---|
| **MODELLED** | A pure decision exists with executable tests. Spec §2: "Passing a model test is not acceptance of the corresponding production control." It means the rule is specified and its negatives are exercised — not that anything enforces it at runtime |
| **DESIGNED** | Specified in an approved document, no implementation. The blocking package or decision is named |
| **UNDECIDED** | The mitigation depends on a decision nobody has made |
| **ACCEPTED** | Known, unmitigated, and tolerable only in the current no-deployment state |

**Untested exposure is the dominant state of this system.** Nothing here has been
exercised against a running deployment, because there is no deployment. No active
testing of any kind was performed in producing this document.

## 1. Assets, in rough order of what their loss would cost

| # | Asset | Why an attacker wants it |
|---|---|---|
| A1 | Target authorisation records and scope | Forging or widening one turns Seal into an attack tool against a system nobody authorised |
| A2 | Another tenant's findings | A list of a company's unfixed vulnerabilities is a targeting package |
| A3 | The audit chain and evidence | Rewriting it hides what was done, or manufactures proof that something was fixed |
| A4 | Scanner credentials and target access tokens | Direct access to the customer's systems |
| A5 | Seal's own worker/platform execution | A foothold that can reach customer networks from a trusted position |
| A6 | Closure and verification state | Marking exposure fixed when it is not, which is the failure the whole product exists to prevent |
| A7 | Exposure metrics and reports | Understating risk to a customer or a regulator |

## 2. Actors

| Actor | Trusted for | Assumed capable of |
|---|---|---|
| Authorised assessor (customer role) | Requesting assessments inside their own tenant | Trying to see other tenants; trying to assess systems they do not own |
| Reviewer / fixer (customer roles) | Triage, remediation, closure review | Closing findings without real proof; self-reviewing |
| Seal operator | Running the platform | **In operated-service mode, seeing every tenant.** See §5 |
| Scanner worker | Running one scanner on one authorised artefact | **Being fully compromised.** This is the architecture's central assumption |
| Adapter output | Nothing | Being hostile: malformed, oversized, nesting bombs, traversal, cross-tenant claims, content designed to act on whoever renders it |
| Target system | Nothing | Responding hostilely — redirects, DNS rebinding, oversized responses |
| External sink / anchor service | Receiving and signing audit heads | Being unavailable, or lying about receipt |
| Outsider | Nothing | Credential stuffing, exploiting the platform directly |

## 3. Trust boundaries and their enforcement points

| # | Boundary | Enforcement point | Exists? |
|---|---|---|---|
| B1 | Adapter output → trusted core | `admission.py` | Decision MODELLED (77 tests) |
| B2 | Platform → target network | `egress.py`, outside the worker | Decision MODELLED (40); no network capability at all |
| B3 | Request → authorisation | `authorization.py`, fails closed | Decision MODELLED (37) |
| B4 | Tenant → tenant | Organisation hashed into every identity; refusals in `admission`, `export` | Decision MODELLED; **no RLS, API, cache or pool** |
| B5 | Event stream → durable evidence | `audit.py` chain + outbox | Partially MODELLED (44); checkpoint unauthenticated, no external sink |
| B6 | Finding state → closure | `closure.py` two-stage proof review | MODELLED (41) |
| B7 | Data → outside the system | `export.py` | MODELLED (62); no HTTP surface |
| B8 | Running work → integrity loss | `integrity.py` generation | MODELLED |
| B9 | Crash → resumed work | `recovery.py` | MODELLED (52) |
| B10 | Internal state → external claim | `release.py`, `metrics.py` | MODELLED |

## 4. Threats

### T1 — A compromised worker reaches a system nobody authorised
**Impact: critical.** This is the threat that turns a defensive tool into an attack.
**Mechanism:** worker opens its own socket; follows a redirect off-target; the target's
DNS rebinds between validation and connection; a cached approval is reused after scope
is revoked.
**Control: MODELLED + DESIGNED.** The decision lives outside the worker by design, so
"a compromised worker cannot bypass it" (`egress.py`). A rebind is modelled as two
different address lists for one host; redirects and direct egress are prohibited
outright (Tier A2); `integrity.py`'s generation counter invalidates every outstanding
grant on its next use rather than hunting down individual leases.
**Residual: high and untested.** Nothing enforces any of it. The enforced boundary is
D06 and F05, and T01/T03's negatives have never run.

### T2 — Hostile adapter output attacks the core
**Impact: high.** **Mechanism:** nesting bomb, 12 MB payload, unknown schema version,
traversal or URL in an evidence reference, unexpected field carrying an instruction,
a result claiming a different tenant.
**Control: MODELLED, and this is the strongest-evidenced boundary in the system.**
Gates run cheapest-and-most-hostile first — byte length, then depth scanned over raw
bytes, then parse — so a nesting bomb never reaches `json.loads`. Allowlist, not
denylist: an unrecognised field is a rejection. Every rejection is a `Decision`, never
an exception. Spec §8's "a content field cannot invoke a tool or alter policy" is
structurally true because there is no channel for an unexpected instruction.
**Residual: moderate.** The validator has never seen real scanner output (D04), and
`max_payload_bytes` and `max_observations` are untested against a real noisy scan.

### T3 — Cross-tenant exposure
**Impact: critical.** T02's threshold is zero, with no tolerance.
**Mechanism:** a query that reaches across tenants; a result asserting another
organisation; a shared cache or connection pool leaking context; an export containing
a foreign row.
**Control: MODELLED + DESIGNED.** Tenant context is never taken from the payload
(U09); the organisation is hashed *into* identity, so the same weakness in two tenants
cannot collide; a foreign-tenant row refuses the **whole** export rather than being
filtered out, so a cross-tenant query surfaces as a failure instead of hiding behind a
download that looks complete.
**Residual: high and untested.** PostgreSQL RLS, the API, the worker paths and the
cache do not exist; T02 requires tenant A/B fixtures on every one of them.

### T4 — Audit chain or evidence tampering
**Impact: critical for A3 and A6.** **Mechanism:** edit, reorder or delete events;
rewrite the chain and present a matching head; claim an anchor receipt that never
existed.
**Control: partially MODELLED, with the gap stated in the module itself.** Reorder,
edit and delete are detected; the chain validates against a checkpoint held outside
the event list, because "an unauthenticated head taken from the same list it is
checking would prove nothing". But `audit.py` says plainly that it does not
authenticate that checkpoint and does not implement anchoring, and
`AnchorReceipt.verified` is an **input**.
**Residual: high.** Real integrity needs D07 and F07: a separately administered signed
sink, key custody, retention lock and receipt reconciliation. Until then, Tier A6
forbids presenting an unanchored decision as externally verified.

### T5 — False closure
**Impact: high.** The product's core promise.
**Mechanism:** close on an absent alert; close on a failed or partial scan; reuse a
pre-fix scan; self-review; land a stale closure intent after recurrence.
**Control: MODELLED, with strong negatives.** Closure is two-stage — proof review then
a compare-and-swap at finalisation that re-checks every condition against committed
state. Reviewer independence from both assessor and fixer is required. Only
`COMPLETE` coverage can prove closure, and "a failed or partial scan never implies a
finding is fixed". C01's four scenario families are implemented as named test classes.
**Residual: moderate.** The transaction that actually enforces serialisation is
F02/F03. Tier A7 and A12 carry the rules meanwhile.

### T6 — Understating exposure
**Impact: high, and the most likely to happen by accident.**
**Mechanism:** risk-accepted or suppressed findings dropped from the denominator; an
override quietly reducing reported exposure; a zero denominator rendered as 100%; an
unsupported check counted as a passed check.
**Control: MODELLED.** C03 fixes the denominator: accepted and suppressed stay in it
and never enter the numerator; a zero denominator is *unavailable*, not one;
`NOT_ASSESSED` is distinct from clean. T08's "no assignments means not measurable, not
0%".
**Residual: low at the decision layer, unknown at the presentation layer** — the
dashboard is W04 and does not exist, and this threat lands mostly in UI copy.

### T7 — Unverified scanner supply chain
**Impact: high.** **Mechanism:** a tampered scanner image; a poisoned advisory
database or rule set; an unapproved tool/DB/rule combination dispatched.
**Control: DESIGNED, barely MODELLED.** U10 requires image digest, signature and
provenance verification, rule digest, advisory DB digest and timestamp, and
adapter/schema/transformation versions, and requires an unapproved combination to be
**rejected**. `coverage.ToolRevisions` pins the manifest fields; container admission
and signature verification are entirely absent.
**Residual: high.** `docs/decisions/D04_pinning_record.md` is the empty form, and its
§1 makes the point that matters here: "Reject an unapproved combination" is a runtime
control, not a filing habit.

### T8 — Credential and secret leakage
**Impact: high.** **Mechanism:** credentials in checkpoints, logs, evidence or
diagnostics; secrets committed; raw private responses persisted.
**Control: partially MODELLED.** `recovery.py` requires credential-free checkpoints
and persists no replayable request. CI greps for obvious credential literals and
asserts the ignore rules — and the workflow itself says it is "a basic guard, not a
credential scanner".
**Residual: moderate now, high later.** There is no approved secret store; D07 covers
key custody. Nothing authenticates to anything today, which is the only reason this is
tolerable.

### T9 — Replay or duplicate execution after a crash
**Impact: moderate to high.** An automatic replay is an unauthorised action against a
customer system.
**Control: MODELLED, structurally.** There is no `replay` function and no stored
request to replay; `may_retry` answers "may a fresh attempt be made" behind five
rechecks — authorisation, revocation, profile, stop state and remaining budget. "The
automatic replay spec §8 forbids has no implementation here to call, which is a
stronger guarantee than a rule saying not to call it."
**Residual: moderate.** The lease and queue are F03; T10/T11 have never run.

### T10 — Mishandled incident, or autonomous regulatory action
**Impact: high, legal.** **Mechanism:** Seal notifies a regulator or third party by
itself; an active compromise handled as an ordinary finding; the 24-hour clock treated
as settled law.
**Control: MODELLED and prohibited.** `incident.py` halts, holds, routes only through
recorded contacts, never contacts anyone autonomously, and carries
`DutyStatus.UNDETERMINED` as distinct from `NO_DUTY` so pending counsel guidance
cannot read as clearance. Tier A1 forbids autonomous filing outright.
**Residual: moderate.** Persistence and contacts are F-package work; the duty itself
awaits D09.

### T11 — Overclaiming to a customer, a regulator or a gate
**Impact: high, institutional.** **Mechanism:** a model test cited as production
assurance; a release pack asserting a control that does not exist; an agent or hook
recording a gate decision.
**Control: MODELLED and structurally prevented.** `release.py` refuses a claim without
locatable, digest-bound, verified, same-revision evidence; a model check can never
support a production-control claim; the claimant and the evidence producer cannot
accept. There is no `approve` or `sign_off`, and an `ast` test keeps it that way
(Tier A8).
**Residual: low at the decision layer.** The risk is prose — documents and UI copy —
not code.

### T12 — Scope creep into discovered systems
**Impact: critical, legal.** **Mechanism:** an interesting finding on a neighbouring
host; a target that redirects to a system nobody authorised.
**Control: DESIGNED and prohibited.** Spec §12: "Permission to assess one asset never
extends automatically to connected or discovered systems"; §12.2 requires stopping
interaction, preserving the minimum record and routing through responsible disclosure.
Tier A9.
**Residual: high and procedural.** Nothing enforces it; it depends on the egress
boundary (D06) plus operator discipline, and no rules-of-engagement record exists yet.

### T13 — Resource exhaustion
**Impact: moderate.** **Mechanism:** a scan that never terminates; an enormous result;
a flood of concurrent jobs.
**Control: partially MODELLED.** Envelope and observation ceilings exist in
`admission`; the 60/45/30-minute maxima, five-second stop and thirty-second
termination targets are specified and modelled arithmetically.
**Residual: moderate, entirely unmeasured.** The worker bounds are F-package; the
measurement sheet is prepared and empty.

## 5. Threats that depend on the undecided deployment model

`D05_baseline_readiness.md` §6 item 1 records that nobody has decided whether Seal is
an operated service or a licensed deployment. Three threats change shape with that
answer, which is one more reason the decision is worth making early.

### T14 — The Seal operator as a privileged cross-tenant insider
**Only in operated-service mode.** The operator runs the platform and can, by
construction, see every tenant's findings — asset A2 for every customer at once.
**Control: UNDECIDED. Nothing in the current design addresses operator-level abuse.**
Every tenant control modelled so far protects tenants from *each other*, not from the
operator. What would be needed — operator access logging a tenant can see,
dual-control for cross-tenant actions, customer-held keys, or contractual limits — is
not specified anywhere.
**Residual: high and unaddressed.** In licensed-deployment mode this threat largely
disappears and is replaced by T15 and T16.

### T15 — A customer-hosted instance that does not honour its own ceilings
**Only in licensed-deployment mode.** The customer runs Seal and can change profiles,
raise ceilings, disable the egress boundary or enable a deferred scanner class.
**Control: UNDECIDED.** Tier A10 and B2/B8 assume an authority that enforces them.
When the operator *is* the customer, who refuses?
**Residual: high.** Also a reputational threat: Seal's name on an assessment it did
not constrain.

### T16 — Tampering with a distributed worker image
**Only where an image is distributed.** The image carries the scanner binary and, for
Semgrep, rule content.
**Control: DESIGNED.** The same U10 pinning and signature verification as T7, applied
in the other direction — Seal would need to sign what it ships, not just verify what
it pulls.
**Residual: high.** Also where the tooling-licence questions bite
(`D09_counsel_instruction_tooling_licences.md` Q3 and Q4).

## 6. Top residual risks

Ranked by impact × how little stands behind them today.

| Rank | Risk | Why it ranks here |
|---|---|---|
| 1 | **Nothing is enforced** — every control above is a decision, not a deployed mechanism (T1, T3, T12) | The gap is not a weak control; it is the absence of the runtime that would run it. F02–F08, D06 |
| 2 | **Operator insider access is unaddressed** (T14) | Not a gap in implementation but in specification, and it is invisible until the deployment model is decided |
| 3 | **Evidence integrity has no external anchor** (T4) | The chain detects tampering; it cannot prove it did not happen. D07 |
| 4 | **The scanner supply chain is unverified** (T7) | Rejection of an unapproved combination is specified and unimplemented. D04, F01 |
| 5 | **Cross-tenant enforcement is untested on every path that matters** (T3) | T02's threshold is zero and the paths it names do not exist yet |

## 7. What would turn this into assurance

This document identifies abuse paths and states what stands behind each. It is not
evidence that any of them is handled. What would be:

1. **The negative tests, run.** T01's expired, revoked, redirect, DNS and direct-egress
   negatives; T02's tenant A/B fixtures on every path; T03's independent boundary
   timestamps; T14's prohibited-class negatives. All blocked on F02–F05 and an
   authorised laboratory.
2. **A decision on the deployment model**, so §5 stops being conditional and T14 gets
   a specified control.
3. **Independent assessment (H01)**, which is a different thing from this document and
   cannot be satisfied by it — this was drafted by the same agent that wrote the code it
   assesses, which is precisely the conflict H01 exists to resolve.
4. **D08's privacy assessment**, without which G2.06 stays open regardless of this
   document's quality.

## 8. Status and limits

- **Unapproved draft**, prepared for D05 and the threat-model half of G2.06.
- **Not an audit, not a penetration test, not independent review.** No active testing
  was performed; none is authorised.
- **Self-assessment conflict**, stated plainly: the same agent drafted the decision
  core, the D04 and D05 packs, and this model. Treat its confidence accordingly — H01's
  independent reviewer is the control for exactly this.
- **Deployment-model-dependent**, per §5.
- Threat identifiers T1–T16 are local to this document and are not the baseline's
  T01–T14 acceptance groups. Where a threat maps to an acceptance group, the group is
  named in the text.
