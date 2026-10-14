# Seal frontend design specification — draft for W02/W04

**Draft. Unratified. Nothing here is built.** This specification describes the
interface W02 and W04 would deliver. Both work packages are **not started** and
depend on W01–W03, F02, F07 and F08 (`docs/BOUNDARY.md`), so every screen below is
a design proposal against approved documents, not a description of software that
exists.

| | |
|---|---|
| Covers | W02 (triage, assignment, remediation, exception and override screens) and W04 (role-based dashboard, evidence views, management summary, export surface) |
| Governing requirements | U13 (spec §9), U03, U04, U05, U06, U08, U09, C01, C02, C03; baseline §§5, 6.9, 13 (usability, accessibility, explainability), §14, §17, Appendix D, Appendix E.7 |
| Relevant SDLC gate | G2 design readiness — this is a design input to it, and closes none of its items |
| Drafted | 2026-10-14, by Claude Opus 5 at the owner's instruction |
| Status | **Unapproved draft.** Not a UI, not a prototype, not an accessibility assessment, and not independent design review |
| Reviewed in a browser | **No.** Nothing is implemented; §13 records exactly what was and was not checked |

## 0. How to read this document

It sits beside three siblings and overlaps none of them:

- [`BOUNDARY.md`](../BOUNDARY.md) — what is absent and which decision blocks it. The
  dashboard is one of its rows.
- [`PROHIBITED_CAPABILITIES.md`](PROHIBITED_CAPABILITIES.md) — what must never exist.
  §11 below is the frontend-specific reading of its Tier A, and cites the row each
  item derives from.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — abuse paths and control states.

Where this document proposes something the approved documents imply but do not state,
the item is marked **proposed** rather than citing wording that does not exist. Where
a choice belongs to a named authority, it is in §14 rather than decided here.

## 1. Scope

**In scope.** The screen inventory, the state coverage each screen must carry, the
visual direction and its reusable values, the status vocabulary, the accessibility
contract, the read-model shapes the frontend consumes, and the prohibitions specific
to a display surface.

**Out of scope, deliberately.** No implementation. No framework selection — baseline
§14 proposes React but requires that "exact versions and licenses must be pinned and
reviewed during implementation", and no such review has happened (§14 Q4). No HTTP
API contract: that is F02's, and F02 is blocked on D03 and D05. No component code,
no design-system package, and no typeface or icon selection that would carry a
licence question nobody has answered (§14 Q5).

**One structural constraint before any screen.** Every measure this interface
displays is computed by the server and rendered verbatim. The client never
aggregates a cohort, never derives a rate, and never recomputes a denominator from
rows it happens to hold. C03 requires that "neither an override nor a change of
display filter reduces exposure"; a client that can do arithmetic on findings is a
client that can disagree with the audited number. This single rule removes that whole
class of defect, and it shapes the data contracts in §10.

## 2. The display obligations

Most dashboards are designed to look reassuring. This one is designed so that it
*cannot* look more reassuring than the evidence. Eight obligations follow directly
from the decision core, and each is a design constraint rather than a sentiment.

| # | Obligation | Source | What the interface must do |
|---|---|---|---|
| O1 | A denial explains **every** failing condition before submission | U13: "The scope screen explains denied conditions before submission"; `decision.evaluate` collects all failures rather than stopping at the first | Render the full `reasons` tuple as a list, each with its own sentence. Never show only `Decision.reason` (the first code). Never collapse several denials into one generic message |
| O2 | A zero denominator is **Not available**, never 0% and never 100% | U13; `metrics.NOT_AVAILABLE` | The measure component has a third rendering mode beside value and loading: unavailable, with its zero denominator visible. No gauge, ring or bar may draw an empty or full track for it |
| O3 | A filtered view never replaces the totals | C03-B; `reasons.FILTERED_VIEW_NOT_LABELED` exists because the core refuses an unlabelled one | Filtered figures appear **beside** the all-disposition totals, visibly labelled as filtered. A filter control may add a view; it may never mutate the headline |
| O4 | Accepted risk and suppression are still exposure | C03; Tier A7 | Disposition counts appear as their own figures *inside* the exposure total, not as deductions from it. No control reduces `unresolved_exposure` |
| O5 | `Closure awaiting anchor` is not `Closed` | C01; `State.is_resolved` is true only for `Closed`; Tier A6 | A distinct state badge with its own non-success treatment, and no copy anywhere calling it verified or externally verified |
| O6 | Partial, failed, stopped and not-assessed work stays visibly incomplete | U03; `CoverageStatus.proves_coverage` permits only `Complete`; Tier A12 | Coverage is shown on every result surface, never summarised away. A finding list showing "no findings" must state the coverage status of the scope it covers |
| O7 | Approval can never be inferred from a page view or from the fixer's own update | U13: "Approval cannot be inferred from viewing the page or from the fixer marking work done" | The reviewer's decision is an explicit three-way choice with a mandatory reason. No default selection, no auto-advance, no "approve and next". A remediation owner's screen has no closure control at all |
| O8 | Every adapter-derived string is inert | Spec §8: "A content field cannot invoke a tool or alter policy"; Tier A4 | All such values render as text through the framework's escaping path. No raw-HTML injection API anywhere in the codebase, enforced by a lint rule, and no value from adapter output may reach an `href`, `src`, `style` or event handler |

Two of these are the design's thesis, because they are what makes the interface
unusual: **there is no all-clear screen** (O2, O4, O6), and **nothing the viewer can
click changes a number** (O3, O4).

## 3. Users, roles and the view matrix

Baseline §5 names eight roles. `export.EXPORT_ROLES` names five, three of them also
cleared for person fields. The two lists do not use the same identifiers, and that is
a real gap rather than a presentation detail — §14 Q1.

| Baseline §5 role | U13 / §9 expectation | Default landing view | Export role | Person fields |
|---|---|---|---|---|
| Platform owner | Govern use, review high-risk actions | Control health (S10) | — (not in `EXPORT_ROLES`) | — |
| Security administrator | Platform health, profile admissions | Control health (S10) | `security_lead` | Yes |
| Authorized assessor | Scope, schedule, triage, propose findings | Assessment runs (S02) | `assessor` | No |
| System or code owner | Correct findings on an assigned asset | My assigned findings (S05) | `remediation_owner` | No |
| Reviewer or auditor | Confirm authorization, risk decisions, closure | Verification queue (S06) | `reviewer` | Yes |
| Legal and compliance adviser | Recorded Phase 0 advice; approves no scan activity | Incident and duty register (S12) | — | — |
| Incident coordinator | Escalation, halt, evidence preservation | Incident and duty register (S12) | — | — |
| Executive viewer | "Read summarized dashboards and reports only" | Executive summary (S09) | **—** | — |
| *(no §5 row)* | Unresolved exposure and accountable work (§9) | Exposure dashboard (S08) | `manager` | Yes |

Three things the matrix makes visible:

1. **An executive viewer cannot export today.** `EXPORT_ROLES` omits the role, which
   is a defensible reading of "summarized dashboards and reports only" — but it means
   an executive cannot take a CSV of the summary they are shown. Decide it; don't let
   an omission in code decide it (Q2).
2. **"Manager" has no baseline §5 row.** U13 and C03 both describe a manager view;
   §5 does not list the role. Either the manager is the platform owner under another
   name, or §5 is short a row (Q1).
3. **Three roles are read-only by design** (legal adviser, incident coordinator
   outside incident surfaces, executive viewer). Their views must not render disabled
   action controls: an action a role may never take is **absent**, not greyed. A
   disabled button advertises a capability and invites a request to enable it.

**Client-side role checks are presentation only.** They decide what is worth
rendering; they never decide what is permitted. U09 requires the organization to be
derived from authenticated membership and enforced on "API access, background jobs,
object keys, caches, signed downloads and exports". The interface therefore has no
tenant selector of any kind — not a hidden one, not a developer one. `ExportRequest`
models exactly this: `requested_organization` can only ever *match* the authenticated
membership, never select.

## 4. Visual direction

**Design intent.** The audience is practitioners and reviewers doing careful work
with contested evidence — an assessor who must understand why a scope was refused, a
reviewer who will sign a closure decision an auditor reads later, an executive who
needs a number that will survive scrutiny. The tone is an instrument panel, not a
marketing dashboard: quiet, dense where density aids comparison, legible on a laptop
at the end of a long day. Density is medium-high on queues and tables, low on
decision screens where one choice matters more than throughput.

**The direction in one line: evidence-grade, not reassurance-grade.** Concretely:

- **No celebratory affordances.** No confetti, no green hero figure, no "0 issues!"
  state. The honest empty state is "No confirmed findings in this cohort — coverage
  *Complete*, assessed 14 Oct 2026"; if coverage was `Partial`, the empty state says
  that first.
- **Colour is never the only carrier of status.** Every badge pairs a colour role
  with its own text label — the enum's own string (§5) — and in dense tables a weight
  or shape difference as well. This is an accessibility requirement (§9) and an
  honesty requirement at once: a reviewer skimming for green is a reviewer who will
  miss `Closure awaiting anchor`.
- **Positive status is neutral, not green.** `Complete` coverage and `Closed`
  findings use a calm neutral-positive, used sparingly. Nothing in the product reads
  as "all good".
- **One primary action per task region.** The reviewer's screen has exactly one
  region where a decision is made, and three equal-weight choices inside it (O7).

### 4.1 Reusable values

Tokens, not CSS. Names are proposed; the structure is the point.

**Type.** One text family with good figure legibility and a tabular-figure variant
(digests, severity scores and durations are compared vertically); one monospace
family for digests, reason codes, revisions and fingerprints. Scale, 1.25 ratio off a
15px base: `xs 12 / sm 13 / base 15 / md 17 / lg 21 / xl 26 / 2xl 33`. Line height
1.5 body, 1.25 headings, 1.4 table cells. Monospace renders one step smaller than
adjacent body text to compensate for its larger x-height.

**Colour roles**, defined as roles rather than hues so the palette can be ratified
(Q6) without rework:

| Role | Used for |
|---|---|
| `surface`, `surface-raised`, `surface-sunken` | Page, card, inset digest/code block |
| `text`, `text-muted`, `text-inverse` | Body, secondary, on-accent |
| `border`, `border-strong`, `focus-ring` | Separation, table rules, focus |
| `accent` | The single primary action per region; never a status |
| `status-neutral` | `New`, `Track`, `Not assessed` |
| `status-progress` | `Assigned`, `Remediating`, `Verification pending` |
| `status-attention` | `Partial`, `Reopened`, `Attend`, expiring exception |
| `status-critical` | `Failed`, `Stopped`, `Act`, integrity `Untrusted`, incident halt |
| `status-verified` | `Closed`, `Complete` — restrained, and never applied to `Closure awaiting anchor` |
| `status-pending-proof` | `Closure awaiting anchor`, `Undetermined - pending counsel`, `Triage` — a distinct treatment that reads as *unfinished*, not as success or failure |

`status-pending-proof` is the palette's load-bearing choice. C01's substate, an
undetermined legal duty and a triage outcome share one property: the system has
deliberately refused to decide yet. They must not borrow the visual language of
either success or failure, because both would misstate the state.

Contrast: every text-on-surface pair ≥4.5:1; large text and non-text indicators
≥3:1; focus ring ≥3:1 against both the control and the adjacent surface.

**Spacing**, 4px base: `1 4 / 2 8 / 3 12 / 4 16 / 6 24 / 8 32 / 12 48`; table cell
padding `2`/`3`. **Radii**: `0` tables and badges, `4` controls, `8` cards — nothing
rounder. **Elevation**: two levels only, raised card and dialog; no decorative
shadow. **Content widths**: prose and decision screens cap at 72ch; tables use full
width, scrolling horizontally inside their own container with a sticky first column.

## 5. Status vocabulary

**The label text is always the enum's own string.** `lifecycle.State.CLOSURE_AWAITING_ANCHOR`
displays as "Closure awaiting anchor", not "Pending" or "Almost closed". The UI, the
CSV export, the audit record and the specification then share one vocabulary, which
is what lets a reviewer reconcile a download against a screen — and W04's acceptance
evidence depends on that reconciliation being possible.

| Source enum | Values | Treatment |
|---|---|---|
| `lifecycle.State` | New, Confirmed, Assigned, Remediating, Verification pending, Closure awaiting anchor, Closed, Reopened | Badge. `Closure awaiting anchor` → `status-pending-proof`; `Reopened` → `status-attention` with `reopened_count` beside it |
| `lifecycle.Disposition` | Risk accepted, Suppressed, False positive | Badge, always rendered *in addition to* the work state, never instead of it (U05 keeps the axes apart) — with the expiry date when one is set |
| `coverage.CoverageStatus` | Complete, Partial, Failed, Stopped, Not assessed | Inline chip on every result and finding-list header; only `Complete` gets `status-verified` |
| `priority.Action` | Act, Attend, Track\*, Track, Triage | Leading column of every queue, with the `ACKNOWLEDGEMENT_TARGETS` interval as secondary text, labelled "proposed target" per spec §6 |
| `priority.Confidence` | Confirmed, High, Moderate, Low | Its own column. Never multiplied into severity and never used to sort below `Act` — low confidence on a severe finding means *urgent validation*, a higher-attention state, not a lower one |
| `integrity.Admission` | Trusted, Untrusted | Not a badge — a system-wide banner (S13) |
| `incident.DutyStatus` | Undetermined - pending counsel, Duty confirmed by counsel, No duty determined by counsel | Badge; `Undetermined` → `status-pending-proof`, visibly owned and escalating per U11 |

Four dimensions stay in four columns. Spec §6 keeps severity, likelihood, action and
confidence apart; the interface must not reunite them into a single score, ring or
letter grade. A composite would destroy exactly the explainability baseline §13
requires.

## 6. Screen inventory

| ID | Screen | Primary role | Requirement |
|---|---|---|---|
| S01 | Scope request | Assessor | U13 — denied conditions explained before submission |
| S02 | Assessment runs, and one run's live monitor | Assessor | U13 — request budget, health, current authorization, accessible stop control |
| S03 | Finding queue and triage | Assessor | W02 |
| S04 | Finding detail — priority explanation, observations, coverage, history | All with access | U06, U05, baseline §13 explainability |
| S05 | My assigned findings, and the remediation record | Code owner | U13 — impact, sanitized evidence, suggested correction, due date, proof required |
| S06 | **Verification review** | Reviewer | U04, C01 — the representative journey, §7 |
| S07 | Evidence custody view | Reviewer, admin | U08 — custody metadata only; content has no column |
| S08 | Exposure dashboard | Manager | U13, C03, Appendix D |
| S09 | Executive summary | Executive viewer | Baseline §5 — summaries without unnecessary raw evidence |
| S10 | Control health | Admin, platform owner | U13 — denials, stop performance, anchor lag, integrity incidents |
| S11 | Export | The five export roles | W04 |
| S12 | Incident and duty register | Incident coordinator, legal adviser | U11 |
| S13 | Integrity banner and stop state | System-wide | C02 |

S13 is not a page. When `Admission` is `Untrusted`, a banner naming the trigger
(`chain_mismatch`, `anchor_overdue`, …) occupies the top of every view, every control
that would start or extend work is **removed** rather than disabled, and read
surfaces stay available — a reviewer must still be able to read evidence during an
integrity outage, because that is when they most need to. The banner states that
outstanding execution grants were invalidated by a generation increment, so a user
whose running job stopped understands why.

## 7. The representative journey: S06, verification review

Built and inspected first, before any pattern propagates. It is the right choice
because it contains every hard pattern in the product at once: untrusted content
rendered inertly, a four-dimension explanation, coverage that gates the decision, an
independence rule about *who is looking*, an optimistic-concurrency conflict, an
irreversible decision, a two-phase closure that may stall waiting for an external
receipt, and a denial that must list every missing piece of evidence.

### 7.1 Layout

Three regions, top to bottom, in reading order and in tab order:

1. **The claim** — finding identity, target, rule, fingerprint (monospace, with a
   copy affordance), the finding's `version`, and the current state badge.
2. **The evidence, as ten named conditions.** `review_closure` evaluates ten checks
   and the screen renders them as a checklist, each with its own status and the
   reason code it would emit: the finding is in `Verification pending`; the
   verification boundary matches (organization, target, fingerprint, rule, profile
   digest); the tested revision is the recorded repaired revision; the reviewer is
   neither assessor nor remediation owner; coverage is `Complete`; the rescan was
   authorized; integrity was valid; an evidence digest is present; a changed rule
   carries an equivalence review; and the verification ran after the fix and is not
   future-dated. **The reviewer sees the conditions, not a verdict** — the system's
   own decision is shown beside them, and the reviewer's decision is theirs.
3. **The decision** — three equal-weight choices, no default: **Close**, **Reopen**,
   **Inconclusive**. A reason is mandatory for all three (spec §9: "with a reason").
   Submission is explicit, confirms once with the consequence stated in words, and is
   never optimistic: the finding's state changes on the server's response only.
   `review_closure` may disagree with the reviewer's choice, and when it does the
   screen shows both rather than suppressing one.

### 7.2 Separation of duties, shown before it is enforced

`INDEPENDENT_REVIEW_REQUIRED` fires when the reviewer is the assessor or the
remediation owner. The screen must say so **on arrival**, not on submission: a
reviewer who reads an entire evidence pack before learning they are disqualified has
wasted their time and formed an opinion that now contaminates whoever reviews it
next. When the signed-in user is either party, the decision region is replaced by a
statement of why they cannot decide and who can.

### 7.3 The anchor wait

A Close on a High or Critical finding does not produce `Closed`. It produces
`Closure awaiting anchor`, and the screen says what that means in words: the decision
is recorded, the external receipt is outstanding, the finding is **not** verified
closed, and it still counts in exposure. The intent's pinned values — expected
finding version, evidence revision, observation watermark — are visible, because C01
re-checks every one at finalization and a reviewer who later sees
`INTENT_INVALIDATED` deserves to recognise which pin moved.

A finding in this state shows a live "awaiting receipt for Xh Ym". When finalization
is refused as stale, the outcome is a prominent, persistent explanation on the finding
— not a dismissible toast. C01's whole purpose is that a late receipt does not close
a finding; a notification that scrolls away would undo it in the one place that
matters, the user's understanding.

### 7.4 States

| State | Behaviour |
|---|---|
| Loading | Skeleton that preserves final layout. The decision region renders last and never before the evidence it depends on |
| Loaded, decidable | §7.1 |
| Loaded, not decidable by this user | §7.2 |
| Validation failure | Reason missing, or no choice selected: inline at the field, focus moved to it, every other entered value preserved |
| Server denial | The full `reasons` list rendered as sentences, each with its code in monospace (O1). An unknown code shows the raw code — never a generic failure message (§10.3) |
| Version conflict | `CONCURRENT_MODIFICATION` / `FINDING_VERSION_CONFLICT`: the submission is refused, the reviewer's typed reason is preserved verbatim, and the screen offers to reload the moved-on finding. No overwrite path exists — U05 requires optimistic concurrency "to prevent two reviewers overwriting each other's decisions" |
| Network failure | Decision not submitted, entered values preserved, explicit retry. Retry re-submits the same idempotency key; it never silently re-runs a verification job (U12: a retry "does not replay a prior HTTP request automatically") |
| Integrity untrusted | S13 banner; `INVALID_INTEGRITY` shown against that condition; decision region removed with the reason stated. Evidence stays readable |
| Incident halt | Halt banner; decision region removed; coordinator and hold state named |
| Denied access | A statement of which role may view this and who to ask — never a blank page, and never a 404 that hides whether the record exists |
| Empty queue | "No findings awaiting verification" **plus** the coverage status of the cohort behind the queue (O6) |

## 8. State coverage across the inventory

Each screen carries each state before its patterns are considered done. `—` means the
state cannot arise there.

| Screen | Loading | Empty | Validation | Network fail | Denied | Conflict | Untrusted / halt |
|---|---|---|---|---|---|---|---|
| S01 Scope request | Y | — | Y, all denied conditions pre-submission | Y | Y | — | Controls removed |
| S02 Run monitor | Y | Y | — | Y, with "last updated" age | Y | — | Stop control stays; start removed |
| S03 Triage queue | Y | Y + coverage | Y | Y | Y | Y | Actions removed |
| S04 Finding detail | Y | — | — | Y | Y | Y | Read-only |
| S05 Remediation | Y | Y | Y | Y | Y | Y | Actions removed |
| S06 Review | Y | Y + coverage | Y | Y | Y | Y | Decision removed |
| S07 Evidence custody | Y | Y | — | Y | Y | — | Read-only |
| S08 Exposure | Y | Y = *Not available* | — | Y | Y | — | Banner + measure staleness |
| S09 Executive summary | Y | Y = *Not available* | — | Y | Y | — | Banner |
| S10 Control health | Y | Y = *Not available* per component | — | Y | Y | — | Banner; the incident itself appears here |
| S11 Export | Y | — | Y | Y | Y | — | Removed while untrusted — **proposed**, see Q7 |
| S12 Incident register | Y | Y | Y | Y | Y | Y | This *is* the state |

Two rules make the empty column unusual. On measure surfaces, empty is not "no data"
— it is `Not available` with its zero denominator shown (O2). On list surfaces, empty
is never shown alone; it is shown with the coverage status of the scope it summarises
(O6).

## 9. Accessibility

W04's acceptance evidence leads with "**role scenarios work by keyboard**", and
baseline §13 requires "keyboard-accessible controls, readable contrast and structured
headings". Target: WCAG 2.2 AA, with the specifics below mattering more here than in
the general case.

- **Every role's primary journey is completable by keyboard alone**, and that is the
  acceptance test — not a component audit. Seven journeys, one per role in §3.
- **The stop control (S02) is reachable without a pointer, early in tab order, and
  never behind a menu, a hover or a scroll.** U13 calls for "an accessible stop
  control"; an assessment that needs stopping is the worst moment to hunt for a
  button. It is also the one destructive-looking action that must *not* be made hard
  to reach — confirmation is a single explicit step, never a typed phrase.
- **Structured headings**: one `h1` per view, no level skipped, landmarks for
  navigation, main and banner. The S13 integrity banner is a polite live region on
  appearance; an incident halt banner is assertive.
- **Focus is always visible** at ≥3:1, never removed, never only a colour change.
  After a dialog closes, focus returns to its trigger; after a validation failure,
  focus moves to the first invalid field; after a denial, focus moves to the reasons
  list so a screen-reader user hears all of them (O1).
- **Tables**: real `th` with `scope`, a caption naming cohort and window, sticky
  header and first column that do not cover content at 400% zoom, and no action
  reachable only by horizontal scroll.
- **Measures and charts**: every figure carries its numerator, denominator, sample
  size and window as text — `Measure.as_display()` already carries all four, so the
  text alternative is not a separate artefact to maintain. A chart is an enhancement
  of a table that is present and readable on its own. `Not available` is text, not an
  absent chart.
- **Zoom and reflow**: usable at 200%; content reflows at 320 CSS pixels with no loss
  of function; dense data tables may scroll horizontally inside their container,
  which the reflow criterion permits.
- **Reduced motion**: respected wherever motion exists. The only motion proposed is a
  progress indicator and the S02 budget meter, both with static equivalents.
- **No status by colour alone**, anywhere (§4).
- **Widths to inspect**: 390, 768 and 1440 CSS pixels, plus 320 for reflow and 1440
  at 200% zoom. Queues and the review screen are the two layouts most likely to
  break.

## 10. The read models the frontend consumes

These shapes already exist in `seal.core` and are the natural contract. **Consume
them verbatim.** A frontend that reshapes them is a frontend that can drift from the
audited record, and the display rules above are enforceable only because each figure
arrives with its context attached.

### 10.1 Shapes

| Shape | Source | Carries |
|---|---|---|
| `Decision` | `decision.py` | `allowed`, the full ordered `reasons` tuple, `detail` |
| `Measure.as_display()` | `metrics.py` | measure, value *or* `"Not available"`, numerator, denominator, sample size, window, note |
| `ExposureReport.as_display()` | `metrics.py` | cohort, closure rate, unresolved exposure, disposition counts, awaiting anchor, reopened, initial and current denominator, the full adjustment log |
| `ControlHealth.as_display()` | `metrics.py` | denial counts by reason code, worst stop-egress and stop-termination seconds, worst anchor lag, integrity incidents — each reported separately, because "a single health number is exactly the green screen that can overstate protection" |
| `finding_row()` | `export.py` | The eleven allowlisted finding fields, plus two person fields for permitted roles only |
| `evidence_row()` | `export.py` | Custody metadata only; content has no field, and the access log arrives as a count |
| `EXPOSURE_SUMMARY_FIELDS` | `export.py` | The management summary's seven columns |

The dashboard's field set is the export's field set. W04's acceptance evidence
requires a reviewer to reconcile a download against the screen; one allowlist for
both is what makes that reconciliation sound, and it also means no person field can
appear on screen for a role that may not receive it in a file.

### 10.2 What is missing, and blocks implementation

There is **no HTTP API contract** (F02, blocked on D03/D05), no session or role claim
(F02), no pagination or filter contract, and no signed-download mechanism (F08). The
read models above are Python dataclasses in a pure package, not an interface. Any
frontend work before F02 would be building against mocks, which §13 forbids
presenting as integration.

### 10.3 The reason-code catalogue

`reasons.py` holds every code the core can emit — 133 across fifteen contracts — and
its own docstring says "codes are part of the contract… treat a
rename as a breaking change". The frontend needs one message catalogue keyed by code,
under three rules:

1. **One sentence per code, in the reader's vocabulary**, saying what is missing and
   what would resolve it. `WRONG_BUILD` is "the rescan tested revision `abc123`, but
   the recorded fix is in `def456`" — not "validation failed".
2. **An unknown code renders as itself**, in monospace, noting that no message is
   written yet. Never a generic "something went wrong": a code the frontend has not
   seen usually means the core moved ahead, and swallowing it hides a real denial
   behind reassuring copy.
3. **The catalogue is reviewed with the role in mind.**
   `AUTHORIZATION_EVIDENCE_REQUIRED` means something different to an assessor
   requesting scope than to an auditor reading history. Baseline §13: findings explain
   themselves "in language appropriate to the role".

A completeness check is cheap and worth having: a test that imports `reasons` and
fails when a code has no catalogue entry. **Proposed** — nothing requires it.

## 11. Frontend prohibitions

The display-surface reading of `PROHIBITED_CAPABILITIES.md`. Each row names the Tier
A item or requirement it derives from; none is new policy.

| # | The frontend must never | From |
|---|---|---|
| P1 | Render an "all clear", "fully secure" or "0 issues" summary state | A7, C03, U13 |
| P2 | Label an unanchored decision externally verified, or style `Closure awaiting anchor` as success | **A6** |
| P3 | Let a filter, toggle, sort, override or saved view change a reported total | C03, `FILTERED_VIEW_NOT_LABELED` |
| P4 | Compute a rate, denominator or exposure count client-side | C03 (§1) |
| P5 | Use a raw-HTML injection API, or route adapter-derived text into `href`, `src`, `style` or a handler | **A4**, spec §8 |
| P6 | Offer a tenant selector, or send an organization the server did not derive from membership | U09 |
| P7 | Optimistically apply a closure, reopen, disposition or stop — or report success before the server confirms | U05 concurrency; the irreversibility of a closure record |
| P8 | Generate a download client-side from rows it holds | W04 "server enforces scope"; `export` emits nothing partial |
| P9 | Present a disabled control for an action a role may never take | §3 |
| P10 | Offer any UI to approve, sign off or record a gate decision | **A8** |
| P11 | Offer a control that contacts an external party — CERT, regulator, target owner — without a recorded named delegation; and never one labelled "send" against a `NotificationPlan` | **A1**, U11 (`NotificationPlan` has no `sent` field) |
| P12 | Let a retry re-run a scan or replay a request instead of re-submitting the same idempotency key | U12 |
| P13 | Show evidence content in an evidence view, or a person field to a role outside `PERSON_FIELD_ROLES` | U08, the `export` allowlists |
| P14 | Expose a deferred capability as a disabled or "coming soon" affordance — DOCX/PDF export, ticket creation, CI checks | Baseline §6.9; W04 "deferred capabilities absent" |
| P15 | Keep protected data in client state for a view the role may not see | Baseline §13; protected information must not be exposed through hidden UI |

P14 deserves a note: a greyed "Export PDF" button is not a neutral placeholder. W04's
acceptance evidence is the words "deferred capabilities absent", and a control that
exists but refuses is not absent.

## 12. Technology position and performance budget

**No framework is selected here.** Baseline §14 proposes React for the dashboard and
requires versions and licences to be pinned and reviewed at implementation. This
document sets the constraints any choice must satisfy and leaves the choice to
D03/D05 (Q4):

- No runtime HTML injection in the chosen rendering path, and a lint rule that fails
  the build on its injection API (P5).
- Server-side pagination and filtering; the client holds a page, never a cohort (P4).
- Virtualised rows for queues, given the 100,000-findings figure in T09.
- Every third-party dependency's licence recorded at selection, not inferred — the
  same discipline D09 is applying to scanner tooling, and the reason §4 selects no
  typeface or icon set (Q5).

**Performance.** T09's figures are "dashboard/API p95 ≤2s at 25 concurrent viewers
and 100,000 findings". `ACCEPTANCE_T01_T14.md` records these as **proposed, not
confirmed**, and D05 must approve dataset size, workload duration, environmental
assumptions and measurement exclusions before anything is measured against them. So
the budget below is a design target, not a threshold anything has passed:

| | Target | Note |
|---|---|---|
| Dashboard p95, server + render | ≤2 s at 25 viewers / 100k findings | T09, proposed |
| Queue first contentful paint | ≤1 s on a warm cache | **Proposed** — nothing requires it |
| Measure staleness | Displayed age on every measure surface | Required by O2/O3: a stale figure that looks live is the same defect class as a filtered one that looks total |

## 13. Verification status

Reading a skill or a specification proves loading, not applying, and a design is not
a rendered interface.

| Check | Status |
|---|---|
| Approved documents read for UI requirements | **Done** — baseline v1.6 §§5, 6.9, 13, 14, Appendix D, Appendix E.7; spec v1.6 §§8, 9, 10 |
| Decision-core read models and enums inspected | **Done** — `export.py`, `metrics.py`, `lifecycle.py`, `coverage.py`, `priority.py`, `closure.py`, `integrity.py`, `incident.py`, `decision.py`, `reasons.py` |
| Governance state checked before any readiness claim | **Done** — `pm-sdlc-tracker`: PM Gate 1 3/11, SDLC G2 0/11, no gate decision held on any gate |
| Visual rendering inspected at any width | **Not done, and not possible.** No implementation exists |
| Keyboard journeys exercised | **Not done.** Same reason |
| Contrast measured | **Not done.** §4 states ratios as requirements; no palette has been measured because none has been ratified (Q6) |
| Integration | **None.** There is no API to integrate with (§10.2) |
| Independent design or accessibility review | **None.** The same agent that drafted this read the code it describes; independent review is H01's |

The next concrete check, when it is authorised: build S06 against a labelled mock of
the §10 read models, then inspect it at 390/768/1440 and complete its journey by
keyboard alone. Anything beyond a mock needs W01–W03 and F02, and nothing in this
document authorises starting.

## 14. Open questions for a named authority

| # | Question | Who decides |
|---|---|---|
| Q1 | Reconcile the eight baseline §5 roles with the five `EXPORT_ROLES` identifiers. Is "manager" a §5 role, and which §5 role maps to `security_lead`? | Product/security lead (D05) |
| Q2 | May an executive viewer export the summary they are shown? `EXPORT_ROLES` currently says no, by omission | Product/security lead |
| Q3 | Does the stop control require a confirmation step at all? Confirmation protects against accident; it also costs seconds in the moment it is needed | Security administrator, with the assessor |
| Q4 | Framework, build toolchain and pinned versions. React is proposed, not selected | D03 / D05 |
| Q5 | Typeface, icon set and component-library licences — the same question D09 is asking about scanner tooling | Legal and compliance adviser |
| Q6 | Ratify the colour palette against the §4 roles, and measure every pair for contrast | Product/security lead, with an accessibility reviewer |
| Q7 | Is export suspended while integrity is `Untrusted`? C02 stops *assessment*; it does not say whether reading and exporting existing records stops too. Proposed here as suspended; it is arguable either way | Security administrator |
| Q8 | Baseline §6.9 includes "trend views" in the MVP. No trend measure is defined in Appendix D, and a trend over an unapproved window invites exactly the cherry-picking C03 forbids. Define the windows, or defer the view | Product/security lead |
| Q9 | Localisation and time display. The core requires UTC-aware datetimes (`require_aware`); this document assumes every timestamp renders with an explicit UTC offset. Confirm, including for Ghana-local reporting | Product/security lead |

## 15. Ratification — unsigned

| Field | Value |
|---|---|
| Display obligations (§2) accepted as binding | |
| Role and view matrix (§3) accepted, with Q1/Q2 resolved | |
| Visual direction and token structure (§4) accepted | |
| Status vocabulary (§5) accepted — enum strings used verbatim | |
| Screen inventory and state coverage (§6–§8) accepted | |
| Accessibility targets (§9) accepted as acceptance criteria | |
| Prohibitions (§11) accepted as binding | |
| Open questions (§14) assigned and dated | |
| Ratified by (named) | |
| Date | |
| Review period | |

Until this block is completed, this document is a draft reading of approved documents
by an AI agent. It records no approval, closes no gate item, and authorises no
implementation.
