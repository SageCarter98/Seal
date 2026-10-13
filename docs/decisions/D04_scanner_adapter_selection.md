# D04 — Select Semgrep or Trivy

**Decision pack. Nothing here is a decision.** The selection is the Product/security
lead's to make and record (Integrated Baseline v1.6, Appendix E.3). D04's status
remains **Unconfirmed / Blocked** until a named authority signs §13 of this document.

| | |
|---|---|
| Decision | Select Semgrep **or** dependency-only Trivy as the single software adapter |
| Accountable role | Product/security lead (Appendix E.3, D04) |
| Required evidence | One approved adapter decision; language/artifact coverage, licensing review, fixture suitability, capacity. "Trivy excludes configuration scanning" |
| Blocks | L03 (adapter integration), L04/L05 downstream, a documented part of Phase 2 |
| Drafted | 2026-10-13, by Claude Opus 5 at the owner's instruction |
| Status of this pack | Prepared for review. Not reviewed, not approved, not evidence of any gate |

## 1. The decision as the baseline states it

Three constraints are already fixed by approved documents and are not reopened here.

**One adapter, not two.** L03's boundary is "exactly one selected Semgrep or
dependency-only Trivy integration; authorized pinned input artifact". The baseline
is explicit that "Semgrep remains the alternative, not an additional committed
adapter". Selecting both is outside D04.

**Configuration scanning is excluded either way.** D04's own evidence line says
"Trivy excludes configuration scanning", and spec §8 says "Keep vulnerability
scanning distinct from Trivy's other scanner capabilities [R7]; configuration
coverage remains deferred."

**The baseline already carries a proposal, unconfirmed.** Both v1.6 documents say:
"Propose Trivy dependency analysis as the second adapter because it provides a
concrete package-before/package-after closure scenario; D04 must confirm this
choice; it is not selected by this merge." This pack tests that proposal rather
than assuming it.

L03's acceptance evidence sets the bar the chosen adapter must meet: "Exact
tool/rules/input revision recorded; unselected analysis classes disabled; artifact
treated as untrusted data, not executed application code."

## 2. What is already built, and what it settles

The decision core exists and is merged (705 tests, PR #1 and PR #2). Three parts of
it bear directly on D04:

- `admission.py` — the trust boundary that validates adapter output. Schema version
  `adapter-result-1`, allowlisted fields, size/depth/enumeration/tenant checks.
- `identity.py` — fingerprint identity, with the exact required fields per family:
  `source` = (`rule`, `repository`, `structural_context`); `dependency` =
  (`ecosystem`, `package`, `vulnerability`). Volatile fields — `line`, `column`,
  `layer`, `build_digest`, `commit`, `timestamp` — are rejected from identity by
  construction.
- `coverage.py` — the manifest contract. "An unsupported check is not a passed
  check", and only `COMPLETE` may prove coverage for a closure.

**What this settles:** the trust boundary is adapter-agnostic. A Trivy-shaped and a
Semgrep-shaped observation were both admitted unchanged (§5). Neither option requires
reopening `admission.py`.

**What it does not settle:** whether each tool's own output can *fill* the identity
tuple it needs. That is where the two options diverge sharply, and it is measurable
today (§5).

## 3. The two options, stated precisely

**Option A — Trivy, dependency-only.** `trivy fs --scanners vuln` (or an equivalent
pinned invocation) over an authorized, pinned input artifact: lockfiles and
dependency manifests. Misconfiguration, secret, licence and SBOM scanners disabled
and evidenced as disabled. Produces `dependency`-family observations:
"this component version is subject to this advisory".

**Option B — Semgrep OSS.** Pinned, locally vendored rules over authorized, pinned
source. Pro engine, Pro rules, registry fetches and telemetry all disabled and
evidenced as disabled. Produces `source`-family observations: "this code matches
this weakness pattern here".

They are not substitutes. Seal already covers the runtime web surface through ZAP
(L02). Option A adds *what the application is made of*; Option B adds *what the
application's code does wrong*. D04 chooses which of those two Seal can speak about
at all for the foreseeable phases.

## 4. Dimension 1 — language and artefact coverage

| | Trivy (dependency-only) | Semgrep OSS |
|---|---|---|
| Unit of coverage | A parsed lockfile / manifest, and the packages in it | A parsed file, and the rules that ran against it |
| Breadth | Broad across ecosystems (npm, PyPI, Go, Maven/Gradle, NuGet, Composer, RubyGems, Cargo and others), plus OS packages | Broad across languages, but maturity varies per language, and rule coverage varies far more than language support |
| Hard prerequisite | A lockfile or manifest must exist. No lockfile is `NOT_ASSESSED`, never "clean" | Parseable source must exist; parse failures are per-file errors to report, not silent passes |
| Finds | Known advisories against known component versions | Pattern-matched weakness classes in first-party code |
| Misses | Everything in first-party code; anything with no advisory; vendored code with no manifest | Anything no selected rule describes; flows the OSS engine cannot follow across files |
| Denominator for `coverage.py` | Countable and defensible: these N manifests, these M packages, these K skipped | Harder: "files scanned" is countable, but *weakness-class* coverage requires enumerating what the pinned rule set does **not** cover, per language |

That last row is the one that matters for Seal specifically. `coverage.py` exists to
stop "no findings" from overstating protection, and U13 requires the same honesty in
what the product claims. With Option A, the uncovered set is a list of artefacts.
With Option B, the uncovered set is a list of weakness classes per language — real,
necessary, and much harder to state truthfully or keep current. Option B is not
disqualified by this; it is made more expensive by it, and the cost lands in L05's
coverage manifest and W01's honest-unknowns handling.

## 5. Dimension 2 — fixture suitability (measured today)

This is the only dimension where evidence could be produced without running either
tool, so it was produced. A probe mapped realistic simulated output from each tool
onto the `adapter-result-1` schema and ran it through the **real** `admission.py` and
`identity.py`. Input synthetic; core genuine; no scanner was installed or executed.

### 5.1 Admission — both pass

```
trivy/dependency         -> ADMITTED
semgrep/source(path)     -> ADMITTED
```

The trust boundary is neutral between the options, as designed.

### 5.2 Identity — the options are not neutral

Trivy's three identity fields come straight out of its own JSON:
`Results[].Type` → `ecosystem`, `Vulnerabilities[].PkgName` → `package`,
`VulnerabilityID` → `vulnerability`. Nothing is derived, inferred or synthesized.

Semgrep's JSON has **no field that supplies `structural_context`**. `check_id` gives
`rule`; `repository` is Seal's own context; and then the candidates run out. Each
available substitute fails at least one L04 requirement:

| `structural_context` from | Distinct findings kept distinct? | Same finding kept stable? |
|---|---|---|
| `path` (file path) | **No — 2 distinct findings collapsed to 1 identity** | 5/6 |
| `path:line` | Yes | **3/6 (50%)** — a blank line above the finding changes identity |
| `extra.fingerprint` | Yes | **4/6 (66%)** — breaks on a local variable rename, and on a Semgrep upgrade that changes the fingerprint scheme |
| `line` as its own field | — | Rejected outright by `identity.py`: *"volatile fields are observation evidence, not identity: ['line']"* |

Trivy, over the same style of mutation set:

```
KEPT  patch revision of the installed package     KEPT  image layer digest changes
KEPT  a fix becomes available                     KEPT  package path moves
KEPT  severity re-rated by the advisory           KEPT  advisory DB refreshed
KEPT  CVSS rescored
-> trivy retained 7/7 = 100%
```

**Caveat, stated plainly:** these are hand-chosen mutation sets of 7 and 6 cases over
simulated output. The percentages are a design signal, **not** L04 acceptance
evidence — L04's ≥95% target is measured on the versioned seeded benchmark with real
tool runs, and L05's ≥90% detection target likewise. The finding that survives the
caveat is structural, not statistical: *Trivy's identity comes from the tool; Semgrep's
must be constructed by Seal.*

### 5.3 What Option B therefore requires

Choosing Semgrep means Seal must derive its own structural context — plausibly
"enclosing symbol path within file", which is stable across line shifts and distinct
per finding. Nothing in Semgrep's JSON provides it, so Seal would need per-language
symbol extraction, i.e. a new parsing capability inside the trust boundary, plus its
own versioning (`FINGERPRINT_VERSION` discipline), plus mutation benchmarking to show
it reaches L04's ≥95%. That is a material scope addition that D04 should price, not
discover during L03.

## 6. Dimension 3 — licensing review

**Flagged as unverified.** v1.6 requires exactly this: "Pin and verify current tool
behavior, versions and licenses during D04/F01/L01." Spec §8 also makes *licence
review* a recorded field per approved scanner combination. The notes below are
starting points for that review, drawn from a model whose knowledge has a cutoff; no
licence text was retrieved while drafting this pack. §11 lists the checks that must
be run before §13 is signed.

| | Trivy (dependency-only) | Semgrep OSS |
|---|---|---|
| Engine licence to confirm | Apache-2.0 expected | LGPL-2.1 expected for the OSS engine |
| Content licence to confirm | The advisory database is **aggregated** from sources with their own terms (NVD, GitHub Advisory Database, distro feeds). GHSA-derived content has an attribution condition | Community rule content carries its own terms, and some rules are not under the engine's licence |
| Commercial boundary | Dependency-only use is squarely in the open-source scope | Pro engine and Pro rules are proprietary and must be excluded, evidenced as excluded |
| External-service coupling | Advisory DB is pulled as an OCI artefact; rate limits and registry terms apply, and a mirror is needed for an isolated lab | Rule registry fetch and default telemetry both reach out; both must be disabled and rules vendored |
| Record required by spec §8 | Image digest, signature/provenance verification, licence review, advisory DB digest **and timestamp**, adapter/schema/transformation versions | Same, with rule digest in place of advisory DB digest |

Neither option is licence-blocked on the face of it. Both impose an attribution or
exclusion obligation that must be written down rather than assumed.

## 7. Dimension 4 — capacity

The ceilings are already set by v1.3 and retained in v1.6: **30 minutes maximum for
dependency assessment, 45 for source**, with bounded worker CPU, memory, disk,
process count and output size, a five-second outbound-stop target and a thirty-second
worker-termination target.

| | Trivy (dependency-only) | Semgrep OSS |
|---|---|---|
| Expected runtime driver | Number of manifests and packages; advisory DB load | Lines of code × number of rules |
| Expected order of magnitude | Seconds to low minutes | Minutes, growing with repository size and rule count |
| Memory risk | Modest and fairly flat | The real risk; large repositories with large rule sets are where out-of-memory failures appear |
| Disk | Advisory DB must be staged and refreshed | Vendored rules are small |
| Output volume | Bounded by package count | Can be large on a noisy rule set — relevant to `admission.py`'s 8 MiB envelope and 10,000-observation ceiling |
| Triage load downstream | Lower; a finding is "this package version is affected" | Higher; pattern matches need human judgement, which lands on W02 and on D10's remediation deadlines |

**All of the above is expectation, not measurement.** Nothing was measured, because
measuring means running the tools, which is L03/L05 work that D04 gates. What D04 can
do is state the pass condition: the selected tool must complete a representative
authorized artefact inside its ceiling, under the worker's bounded resources, with
termination and stop targets honoured — measured in L05 and H02, reported with the
hardware and workload described.

## 8. Fit with controls already decided or pending

| Control | Trivy (dependency-only) | Semgrep OSS |
|---|---|---|
| Worker egress denied (D06) | DB must be pre-staged and digest-recorded; no scan-time network | Rules must be vendored; registry and telemetry off |
| "Artefact is untrusted data, not executed code" (L03) | Manifest parsing only — no build, no install, no resolution step | Source is parsed to an AST, not executed — also satisfiable |
| Threat-data freshness policy (D10) | Clean fit: a dated advisory DB gives a measurable freshness signal, which is why spec §8 already demands its timestamp | Awkward fit: a rule revision is not a dated advisory feed, so "freshness" needs a different, weaker formulation |
| Closure proof (W03, `closure.py`) | Deterministic: version bump → rescan → the same identity is absent. This is the "package-before/package-after closure scenario" the baseline cites | Weaker: a pattern no longer matching can mean fixed, evaded, or a rule changed between runs — and the comparison must pin the rule revision to mean anything |
| Honest claims (U13, `release.py`) | A dependency finding must never be presented as proof the deployed app is exploitable or safe — the baseline says this explicitly | Same risk, plus a stronger temptation: "we scan your code" reads as broader assurance than a pinned rule set delivers |

## 9. Summary

| Dimension | Trivy (dependency-only) | Semgrep OSS |
|---|---|---|
| Coverage breadth | Broad across ecosystems; nothing in first-party code | Broad across languages; nothing about components |
| Honest coverage denominator | Countable artefacts | Weakness classes per language — expensive to state truthfully |
| Identity fit (measured) | 3/3 fields from tool output; 7/7 mutations retained | No field supplies `structural_context`; every substitute fails collision or stability |
| Licensing | Apache-2.0 engine expected; aggregated advisory content carries attribution terms | LGPL-2.1 engine expected; rule content terms vary; Pro must be excluded |
| Capacity risk | Low | Moderate — memory and runtime scale with code × rules |
| D10 freshness fit | Direct, dated | Indirect |
| W03 closure determinism | High | Moderate |
| Extra build cost created | None beyond the adapter itself | Per-language structural-context derivation inside the trust boundary |

## 10. Recommendation (a proposal, not a decision)

**Select Option A: Trivy, dependency-only, as the single L03 adapter**, and defer
source-code analysis to a separate, later decision that is scoped and budgeted on its
own merits.

The reasons, in order of weight:

1. **Identity fits the modelled contract without invention.** Measured today: every
   dependency identity field comes from the tool. Semgrep's does not exist in its
   output, and the obvious substitutes either merge distinct findings or lose identity
   on a blank line.
2. **Coverage can be stated honestly and cheaply.** `coverage.py` and U13 both demand
   that an unassessed thing is never reported as a clean thing. "These four manifests,
   these 312 packages, this one skipped" is a defensible manifest. "These rules, these
   languages, and here is what they do not cover" is a continuing research obligation.
3. **Closure is deterministic**, which is the baseline's own stated reason for
   proposing Trivy, and it is what makes W03's find–fix–prove loop demonstrable.
4. **Freshness is measurable** against D10, with a dated advisory database the spec
   already requires Seal to record.
5. **Capacity risk is the lower of the two** against ceilings that are already fixed.

### Residual risks this recommendation accepts

- **No code-level weakness detection at all**, for as long as this stands. Seal's
  coverage story becomes "runtime web surface (ZAP) + component inventory (Trivy)",
  and every external claim must say so. This is a real reduction in ambition and
  should be recorded as such, not smoothed over.
- **No lockfile means no assessment.** `NOT_ASSESSED` must surface in the UI and in
  exports, never as a clean result.
- **An advisory-database mirror becomes an operational obligation** with an owner, a
  refresh cadence and a recorded digest — a standing D10/F01 cost, not a one-off.
- **Attribution/licence conditions on aggregated advisory content** must be satisfied
  wherever findings are displayed or exported.
- **A dependency finding is not a statement about exploitability.** `release.py`
  already refuses to let a model-level check support a production-control claim; the
  same discipline must reach the dashboard copy and the management summary.

## 11. What must be verified before §13 is signed

None of these has been run. They are the pack's own outstanding work, and the first
three are the ones v1.6 explicitly assigns to D04/F01/L01.

1. **Licences, current.** Retrieve and read the engine licence, the rule or advisory
   content terms, and any registry terms of use for the exact pinned versions. Record
   per spec §8.
2. **Versions and digests, pinned.** Image digest, signature/provenance verification,
   advisory DB (or rule) digest and timestamp, adapter/schema/transformation versions.
   Confirm an unapproved combination is rejected.
3. **Offline operation, proven.** The selected tool completes with no network access
   and a pre-staged database or vendored rules.
4. **Disabled classes, evidenced.** Configuration, secret and licence scanners off
   (Option A); Pro engine, registry fetch and telemetry off (Option B) — each shown by
   output or configuration, not asserted.
5. **Capacity, measured.** One representative authorized artefact inside the 30-minute
   (or 45-minute) ceiling under bounded worker resources, with stop and termination
   targets met, hardware and workload described.
6. **Fixture suitability, on real output.** Repeat §5 against genuine tool JSON rather
   than simulated JSON, including the mutation set, before L04 claims its ≥95%.

Steps 3–6 involve running a scanner, which the current repository deliberately cannot
do (`docs/BOUNDARY.md`). They are permitted laboratory preparation once this decision
is recorded — not before.

## 12. If Semgrep is selected instead

The selection is the authority's, and Option B is defensible — particularly if the
pilot targets are first-party code with no meaningful dependency manifests, or if
code-level weaknesses are the point of the pilot. In that case the decision should be
recorded **with conditions**, because three things must come with it:

1. A specified, versioned derivation for `structural_context` that is stable across
   line shifts and distinct per finding, with its own benchmark against L04's ≥95%.
2. Added scope and effort for per-language symbol extraction inside the trust
   boundary, reflected in D03's schedule and D11's assurance funding.
3. A reformulated freshness measure for D10 that does not pretend a rule revision is a
   dated advisory feed.

## 13. Decision record — unsigned

Left deliberately empty. A decision is recorded by the accountable authority, not by
the preparer of the pack, and not by any agent.

| Field | Value |
|---|---|
| Selected adapter | *(not selected)* |
| Decision | *(Approve / Approve with conditions / Hold / Redirect — not recorded)* |
| Conditions | |
| Accountable authority (named) | |
| Date | |
| Reviewer consulted | |
| Evidence pack reference | This document, revision as merged |

Until this table is completed by a named authority, D04 is **Unconfirmed / Blocked**,
L03 remains Blocked, and `admission.py` continues to have no adapter capable of
producing real output.

## 14. Provenance and limits of this pack

- **Sources.** `Seal_Integrated_Baseline_v1_6.docx` (Appendix E.3 D04; E.6 L01–L05;
  the second-adapter proposal; [R7]), `Seal_Engineering_Specification_v1_6.docx`
  (§8 untrusted-output and recorded-fields requirements; the 60/45/30-minute maxima;
  the Phase 0 confirmation list), and this repository's `src/seal/core/` with
  `docs/BOUNDARY.md` and `docs/TRACEABILITY.md`.
- **Measured here.** §5 only, via a probe in a scratch directory against the real
  `admission.py` and `identity.py`, on **simulated** tool output. The probe is not
  part of the repository and is not a test; if these numbers are to be relied on, §11
  step 6 repeats them on genuine output under version control.
- **Not measured.** Every runtime, memory, detection-rate and false-positive
  statement in §4, §6 and §7. Each is labelled as expectation.
- **Tool facts carry a cutoff.** Licence, packaging and feature statements come from
  model knowledge, not from retrieved documents, which is precisely why v1.6 requires
  verification at pin time and why §11 exists.
- **This pack establishes no approval.** It is not a gate decision, not evidence of
  one, and not a substitute for the Product/security lead's recorded selection. It was
  drafted by an AI agent and requires competent human review before it informs any
  decision.
