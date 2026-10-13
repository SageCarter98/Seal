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
| Revision 2 | 2026-10-13. §11.1 discharged: licences retrieved and read, so §6 now carries verified citations instead of unverified notes. **The finding changed the picture** — see §6.1. §9, §10 and §12 adjusted accordingly |
| Status of this pack | Revision 1 reviewed and APPROVED by Russell Kenny (kenAddme) on PR #3, merged as `ca3e3da`. That approved the pack as an artefact; it recorded no selection. Revision 2 needs its own review |

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

One detail in the "Misses" row is now verified rather than assumed (2026-10-13):
Semgrep's Community Edition provides "Single file, cross function constant
propagation" and "Single function taint analysis", while cross-file and cross-function
taint analysis belong to the paid platform, as do Pro Rules
(docs.semgrep.dev/semgrep-pro-vs-oss). So Option B's false-negative profile on
multi-file data flows is a property of the free engine, not a tuning question — and it
has to be stated in L05's coverage manifest rather than discovered in a pilot.

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

**Discharged on 2026-10-13.** §11.1 required the licences to be retrieved and read
rather than recalled. They were, from primary sources, on 2026-10-13. Every statement
below is a quotation or a direct reading of a document fetched on that date; the
retrieval dates matter, because licence terms change and v1.6 requires them re-checked
at pin time.

### 6.1 The finding that changes the picture

**Semgrep's own rules are licensed for internal use only and may not be made
available to others as a service.** `semgrep-rules`, the open-source rule corpus
behind the registry's community rules, is not under the engine's LGPL. Its `LICENSE`
names the **Semgrep Rules License v1.0**, whose operative restriction reads:

> "You may use the rules only for your own internal business purposes. This license
> does not allow you to distribute the rules, or to make them available to others as
> a service."
>
> — https://semgrep.dev/legal/rules-license, retrieved 2026-10-13

Seal is a multi-tenant service that assesses other organisations' assets and shows
them the findings. On the face of the text, shipping Semgrep's community rules as
part of that service is the thing this licence excludes. That is a licensing question
with a plain reading, not a settled legal conclusion — **it belongs to the D09
regulatory/legal workstream to confirm**, and this pack does not decide it.

What it does mean for D04 is concrete: **Option B cannot assume the community rule
corpus.** Either a commercial agreement with Semgrep, Inc. covers service use, or
Seal writes and maintains its own rules in Semgrep's syntax — which is permitted (the
licence covers only rules provided by Semgrep, Inc.) but means authoring and
maintaining a rule corpus as ongoing project work, and losing the breadth that made
Option B attractive in the first place.

### 6.2 Verified licence positions

| | Trivy (dependency-only) | Semgrep OSS |
|---|---|---|
| Engine | **Apache-2.0** — `aquasecurity/trivy` `LICENSE`, "Apache License, Version 2.0, January 2004" (retrieved 2026-10-13) | **LGPL-2.1** — `semgrep/semgrep` `LICENSE`, "GNU LESSER GENERAL PUBLIC LICENSE, Version 2.1, February 1999" (retrieved 2026-10-13) |
| Database / rule tooling | **Apache-2.0** — `aquasecurity/trivy-db` `LICENSE` (retrieved 2026-10-13) | n/a |
| Content Seal would ship | Advisory data, predominantly **GitHub Advisory Database**, which Trivy names as the source for pip, npm, Java, Go, Rust, .NET, Dart, Elixir, Swift, PHP and Ruby ecosystems. GHSA is **CC-BY-4.0** (`github/advisory-database` `LICENSE.md`, retrieved 2026-10-13) | **Semgrep Rules License v1.0** — internal use only, no distribution, no service use (§6.1) |
| Obligation created | **Attribution.** CC-BY-4.0 requires, when sharing the material, retaining creator identification, a copyright notice and a notice referring to the licence, and indicating modifications | **A blocker to resolve**, not an obligation to discharge (§6.1) |
| Commercial boundary | Dependency-only use sits inside the open-source scope | Pro engine and Pro rules are paid-platform features and must be excluded and evidenced as excluded |
| Telemetry | No telemetry concern in the scan path; `check.trivy.dev` is an optional update check that can be disabled | **Better than this pack first claimed.** Semgrep "does **not** enable metrics when running with only local configuration files or command-line search patterns", and does enable them "if rules are loaded from the Semgrep Registry" (docs.semgrep.dev/metrics, retrieved 2026-10-13). Vendored local rules therefore send nothing; `--metrics off` makes that explicit rather than implicit |

### 6.3 Obligations either option still creates

- **Binary redistribution notices.** Both engines ship inside a worker image Seal
  distributes. Apache-2.0 requires the licence and notices to travel with it;
  LGPL-2.1 adds notice and source-availability obligations for the library it covers.
  Invoking a scanner as a separate process in a container is the lightest form of
  this, but it is not nothing, and the exact posture is a question for D09/counsel.
- **Attribution in the product surface.** If Trivy is selected, GHSA's CC-BY-4.0
  attribution has to appear wherever findings derived from that data are displayed or
  exported — the dashboard, the management summary and the CSV/JSON export (W04).
  That is a design requirement, not a footnote, and it should be written into W04
  rather than discovered at pilot.
- **Licence review as a recorded field.** Spec §8 requires a recorded licence review
  per approved scanner combination. §6.2 is the content of that record for the
  candidates; the pinning record (`D04_pinning_record.md`) is where it gets fixed to
  the exact selected versions.
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
| Licensing (verified 2026-10-13) | Apache-2.0 engine, Apache-2.0 DB tooling; advisory content predominantly GHSA under CC-BY-4.0 — an **attribution obligation** in the product surface | LGPL-2.1 engine, but Semgrep's own rules are **internal-use-only and may not be made available as a service** — a blocker to resolve, not an obligation to discharge (§6.1) |
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
6. **Licensing, now verified, points the same way.** Trivy's engine and DB tooling are
   Apache-2.0 and its advisory content carries an attribution obligation Seal can
   discharge in the UI and exports. Semgrep's engine is usable, but its rule corpus —
   the thing that makes it valuable — is licensed for internal business purposes only
   and explicitly not for making available to others as a service (§6.1). Option B
   therefore needs either a commercial agreement or a Seal-authored rule corpus before
   it can be a product capability at all.

Reason 6 did not exist in revision 1, which carried an unverified licence table
instead. It does not reverse the recommendation; it removes the main reason to doubt
it, and it changes Option B from "more expensive" to "blocked until a licence
question is answered".

### Residual risks this recommendation accepts

- **No code-level weakness detection at all**, for as long as this stands. Seal's
  coverage story becomes "runtime web surface (ZAP) + component inventory (Trivy)",
  and every external claim must say so. This is a real reduction in ambition and
  should be recorded as such, not smoothed over.
- **No lockfile means no assessment.** `NOT_ASSESSED` must surface in the UI and in
  exports, never as a clean result.
- **An advisory-database mirror becomes an operational obligation** with an owner, a
  refresh cadence and a recorded digest — a standing D10/F01 cost, not a one-off.
- **GHSA attribution becomes a W04 design requirement**, not a footnote: CC-BY-4.0
  requires creator identification, a copyright notice, a notice referring to the
  licence, and an indication of modifications, wherever findings derived from that
  data are displayed or exported.
- **Apache-2.0 notices must travel with the worker image** Seal distributes, and the
  exact redistribution posture is a D09/counsel question, not an engineering one.
- **A dependency finding is not a statement about exploitability.** `release.py`
  already refuses to let a model-level check support a production-control claim; the
  same discipline must reach the dashboard copy and the management summary.

## 11. What must be verified before §13 is signed

Step 1 is **done**. Steps 2–6 are not, and four of them cannot be until a scanner may
run. The scanner-free half of each has been prepared rather than left as a sentence.

1. ~~**Licences, current.**~~ **Done 2026-10-13.** Engine, database-tooling, advisory-
   content and rule licences retrieved from primary sources and read; see §6, which
   now quotes and cites them. Re-check at pin time, as v1.6 requires. The one finding
   that needs an answer from outside engineering is §6.1, which belongs to D09.
2. **Versions and digests, pinned.** *Groundwork prepared:*
   `D04_pinning_record.md` is the empty record, with spec §8's required fields, the
   exact command that populates each one, and the rejection rule for an unapproved
   combination. *Outstanding:* the values, which require pulling the selected
   artefacts.
3. **Offline operation, proven.** *Groundwork prepared:* `D04_pinning_record.md` §4
   names the pre-staged artefacts per option (for Trivy: `trivy-db` and, for Java
   artefacts, `trivy-java-db`, both OCI images), the download and air-gap flags, and
   the self-hosted-registry route. *Outstanding:* running it.
4. **Disabled classes, evidenced.** *Groundwork prepared:* `D04_pinning_record.md` §3
   states the exact invocation per option and the evidence form each disabled class
   must produce. *Outstanding:* the output.
5. **Capacity, measured.** *Groundwork prepared:* the pass condition and the ceilings
   are stated in §7 and restated as a measurement sheet in `D04_pinning_record.md` §5.
   *Outstanding:* the measurements.
6. **Fixture suitability, on real output.** *Groundwork prepared:*
   `tools/d04_identity_probe.py` is §5's probe under version control, with its
   simulated fixtures in `tools/fixtures/d04/` labelled as simulated and a
   `--fixtures` flag so real tool JSON drops in without touching the harness.
   *Outstanding:* real JSON, which requires a scanner run.

Steps 3–6 involve running a scanner, which this repository deliberately cannot do
(`docs/BOUNDARY.md`). They are permitted laboratory preparation once this decision is
recorded — not before.

## 12. If Semgrep is selected instead

The selection is the authority's, and Option B is defensible — particularly if the
pilot targets are first-party code with no meaningful dependency manifests, or if
code-level weaknesses are the point of the pilot. In that case the decision should be
recorded **with conditions**, because four things must come with it — and the first is
new in revision 2 and is a precondition rather than a condition:

1. **A resolved rule-provenance and licence position**, answered by D09/counsel, not
   by engineering: either a commercial agreement with Semgrep, Inc. that covers
   service use, or a decision to author and maintain Seal's own rule corpus in
   Semgrep's syntax, with the coverage consequences of starting from zero rules stated
   honestly in L05's manifest. Until one of those exists, Option B has no lawful rule
   content to ship (§6.1).
2. A specified, versioned derivation for `structural_context` that is stable across
   line shifts and distinct per finding, with its own benchmark against L04's ≥95%.
3. Added scope and effort for per-language symbol extraction inside the trust
   boundary — and, if condition 1 resolves to self-authored rules, for rule authoring
   and maintenance as a standing workstream — reflected in D03's schedule and D11's
   assurance funding.
4. A reformulated freshness measure for D10 that does not pretend a rule revision is a
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
- **Measured here.** §5 only, against the real `admission.py` and `identity.py`, on
  **simulated** tool output. As of revision 2 the probe is under version control at
  `tools/d04_identity_probe.py` with its fixtures in `tools/fixtures/d04/`; the
  fixtures are still simulated, and §11 step 6 remains outstanding until real tool
  JSON replaces them.
- **Retrieved and cited (revision 2).** The licence positions in §6, each from a
  primary source on 2026-10-13: `aquasecurity/trivy` `LICENSE`,
  `aquasecurity/trivy-db` `LICENSE`, `semgrep/semgrep` `LICENSE`,
  `semgrep/semgrep-rules` `LICENSE` and the Semgrep Rules License v1.0 text at
  semgrep.dev/legal/rules-license, `github/advisory-database` `LICENSE.md`,
  docs.semgrep.dev/metrics, docs.semgrep.dev/semgrep-pro-vs-oss, and Trivy's
  vulnerability-scanner, database-configuration and air-gap documentation.
- **Not measured.** Every runtime, memory, detection-rate and false-positive
  statement in §4 and §7. Each is labelled as expectation.
- **Legal reading is not legal advice.** §6.1 quotes a licence and states its plain
  reading against Seal's service model. Confirming it is D09's work with counsel, and
  this pack must not be cited as having settled it.
- **This pack establishes no approval.** It is not a gate decision, not evidence of
  one, and not a substitute for the Product/security lead's recorded selection. It was
  drafted by an AI agent and requires competent human review before it informs any
  decision.
