# D04 — scanner pinning and evidence record (empty)

**This is a form, not a finding.** Every value column below is blank because filling
it requires pulling and running the selected scanner, which D04 has not authorised.
What is prepared here is the *shape* of the record: the fields spec §8 makes
mandatory, the exact command that produces each value, and the rule that rejects an
unapproved combination.

| | |
|---|---|
| Purpose | Discharge steps 2–5 of `D04_scanner_adapter_selection.md` §11 once a scanner may run |
| Applies to | Whichever option D04 selects. §2 is per-option; §3–§5 are written for both |
| Authority to populate | Security lead (Appendix E.3 assigns D04–D06 preparation), under a recorded D04 selection |
| Status | **Empty. No value in this document has been obtained.** |
| Prepared | 2026-10-13, alongside revision 2 of the decision pack |

## 1. Why these fields and not others

Spec §8 is prescriptive, and the list is not negotiable down:

> "Record scanner image digest, signature/provenance verification, license review,
> rule digest, advisory database digest and timestamp, adapter version, schema version
> and transformation version. Reject an unapproved combination."

L03 adds: "Exact tool/rules/input revision recorded; unselected analysis classes
disabled; artifact treated as untrusted data, not executed application code."

Two consequences worth stating before anyone fills this in:

- **"Reject an unapproved combination" is a runtime control, not a filing habit.** The
  orchestrator must refuse to dispatch a job whose image/DB/rule/adapter tuple is not
  in the approved set. A populated form that nothing enforces satisfies the paperwork
  and none of the requirement.
- **The combination is the unit, not the tool.** A new advisory-database digest is a
  new combination. Whether that requires re-approval or only re-recording is a D10
  threat-data-freshness policy question, and it should be answered when D10 is
  prepared rather than improvised at the first DB refresh.

## 2. The record

### 2.1 Common fields

| Field | Value | How it is obtained |
|---|---|---|
| Selected option | | From the signed §13 of the decision pack — not from this form |
| Scanner image reference | | The pinned `registry/repo@sha256:…` reference, never a tag |
| Scanner image digest | | `docker buildx imagetools inspect <ref>` or the registry API; record the `sha256:` digest |
| Signature / provenance verified | | `cosign verify <ref>` (or the vendor's documented verification route), recording the verifying key or identity and the command output — not merely "verified" |
| Licence review | | §6 of the decision pack, re-checked against the pinned version at pin time. Record the licence names, the retrieval date and, for content licences, the obligation each creates |
| Adapter version | | Seal's own adapter module version |
| Schema version | | `adapter-result-1` is the only version `admission.py` accepts today (`SUPPORTED_SCHEMA_VERSIONS`) |
| Transformation version | | Seal's tool-output-to-`adapter-result-1` mapping version. Bump it whenever the mapping changes, independently of the adapter |
| Fingerprint version | | `identity.FINGERPRINT_VERSION` at the time of the run. A change here re-identifies findings and is an L04 event, not a detail |
| Approved by (named) | | Security lead. A combination is approved by a person, not by this file existing |
| Date approved | | |

### 2.2 If Option A (Trivy, dependency-only)

| Field | Value | How it is obtained |
|---|---|---|
| Trivy version | | `trivy --version` |
| Vulnerability DB digest | | The pinned digest of the `trivy-db` OCI artefact (default source `ghcr.io/aquasecurity/trivy-db`, with `mirror.gcr.io/aquasec` as the other documented default) |
| Vulnerability DB timestamp | | `trivy --version` reports the DB's `UpdatedAt`; record it, because spec §8 requires the timestamp and D10's freshness policy will be measured against it |
| Java DB digest and timestamp | | Required only if Java/Maven artefacts are in scope: `trivy-java-db`, pinned the same way |
| Enabled scanner set | | `--scanners vuln` only. Record the full invocation |
| Rule digest | | Not applicable in the Semgrep sense; the advisory DB digest is the content identity. Record "n/a — advisory DB digest serves this field" rather than leaving it blank |

### 2.3 If Option B (Semgrep OSS)

| Field | Value | How it is obtained |
|---|---|---|
| Semgrep version | | `semgrep --version` |
| Rule corpus origin | | **Answer §6.1 first.** Either the commercial agreement reference that permits service use, or the identifier of Seal's own rule corpus. A registry ruleset reference is not an acceptable answer on its own |
| Rule digest | | A digest over the exact vendored rule files, computed by Seal and recorded — not a registry ruleset name, which is mutable |
| Rule corpus revision | | The commit or version of the vendored rules |
| Engine edition | | Must be OSS/Community. Record the evidence that Pro is absent, not the intention |
| `structural_context` derivation version | | The derivation required by the pack's §12 condition 2, versioned separately, because changing it changes every source-family identity |

## 3. Disabled analysis classes — the evidence form (§11.4)

L03 requires "unselected analysis classes disabled". The evidence must be *output or
configuration*, never an assertion. For each row: the control, the mechanism, and what
counts as proof.

| Must be off | Option | Mechanism | Evidence that counts |
|---|---|---|---|
| Misconfiguration / IaC scanning | A | Enable only `--scanners vuln`; `--skip-check-update` for the checks bundle | The recorded invocation plus a result whose classes contain no misconfiguration entries. Note that Trivy embeds a checks bundle in the binary, so "no network" is not by itself proof this class is off |
| Secret scanning | A | Not in the enabled scanner set | As above |
| Licence scanning | A | Not in the enabled scanner set | As above |
| SBOM generation | A | Not requested | The invocation |
| Pro engine | B | Never installed in the image | Image contents, plus a run whose engine is reported as OSS |
| Pro rules | B | Not present in the vendored corpus | The rule digest and corpus listing |
| Registry rule fetch | B | `--config` points only at local paths | The invocation, plus no network egress from the worker |
| Telemetry | B | Off by default with local-only configuration — Semgrep "does not enable metrics when running with only local configuration files"; `--metrics off` makes it explicit | The invocation **and** the absence of outbound connections, since the worker denies egress anyway (D06) |

## 4. Offline operation (§11.3)

The worker denies egress (D06), so everything the scanner needs must be staged before
the run and recorded by digest.

**Option A.** Pre-stage the OCI database artefacts and disable update attempts:

- Download once, outside the worker: `trivy image --download-db-only` (and the Java DB
  equivalent if Java artefacts are in scope).
- Pin the source with `--db-repository` / `--java-db-repository`, which accept a
  self-hosted registry reference; hosting Seal's own mirror is the documented route
  and removes the dependency on a public registry's availability and terms.
- At scan time: `--skip-db-update`, `--skip-java-db-update`, and `--offline-scan` so
  no package repository is contacted.
- Disable the optional update check to `check.trivy.dev`; Trivy's documentation
  describes that connectivity as entirely optional.

**Option B.** Vendor the rule corpus into the image and point `--config` at local
paths only. No registry fetch means no telemetry by default (§3), but record
`--metrics off` anyway so the control is explicit rather than incidental.

**Evidence that counts for either:** a completed run inside a worker with no network
route, with the staged artefact digests recorded in §2 and matching the digests the
run reports.

## 5. Capacity measurement sheet (§11.5)

The ceilings are fixed by v1.3 and retained in v1.6: **30 minutes for dependency
assessment, 45 for source**, with bounded worker CPU, memory, disk, process count and
output size, a five-second outbound-stop target and a thirty-second worker-termination
target.

| Measurement | Value | Pass condition |
|---|---|---|
| Representative artefact described | | Named, with size: repository size, lines of code, or manifest and package counts |
| Worker resource bounds applied | | The actual CPU, memory, disk and process limits — the measurement is meaningless without them |
| Wall-clock duration | | Inside the ceiling for the family being assessed |
| Peak memory | | Inside the worker's bound, with no OOM kill |
| Output size | | Inside `admission.AdapterLimits.max_payload_bytes` (8 MiB) and `max_observations` (10,000) |
| Observation count | | As above; a truncated result must report `truncated: true`, and partial coverage must be `PARTIAL`, never `COMPLETE` |
| Outbound stop honoured | | Within five seconds |
| Worker termination honoured | | Within thirty seconds |
| Hardware and workload described | | Recorded alongside the numbers, per H02's requirement that raw measurements come with their environment |

A measurement that misses a ceiling is a finding to record and escalate, not a reason
to relax the ceiling. The ceilings are "reviewable ceilings" per the spec — reviewable
by D06 profile review, not by whoever is running the test.

## 6. What this document is not

- **Not a decision.** It does not select an adapter, and completing it does not. The
  selection lives in `D04_scanner_adapter_selection.md` §13 and is a named authority's
  signature.
- **Not evidence.** An empty form proves nothing, and a filled-in form proves only
  what its command outputs show. Attach or reference the outputs.
- **Not a licence to run a scanner.** Populating §2.2 or §2.3 requires an authorised
  laboratory and a recorded D04 selection. Until then this file documents what will be
  required, which is all it claims to do.
