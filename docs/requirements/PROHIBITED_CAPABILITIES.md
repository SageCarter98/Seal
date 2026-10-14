# Prohibited capabilities — draft specification for D05 ratification

**Draft. Not ratified.** D05's required evidence includes a prohibited-capability
specification; this is that draft. A prohibition nobody signed is a preference, and
the point of this list is that it binds work nobody has started yet — so §4's
ratification block matters as much as the list.

**This is not `docs/BOUNDARY.md`.** That document says *not built yet, and here is the
decision that blocks it*. This one says *must never exist*, or *must never exist
without one specific named authorisation*. A FastAPI service is absent and expected
later; Seal filing a regulatory report by itself is forbidden. Keeping those in one
list would let a prohibition quietly become a backlog item.

Every row cites the approved document it comes from. Where this draft proposes a
prohibition the documents imply but do not state in those words, the row says
**proposed** rather than citing something it cannot.

## 1. Tier A — never permitted

No work package delivers these. A design that needs one is a design to reject.

| # | Prohibited | Source |
|---|---|---|
| A1 | Making an external regulatory report, notification or filing autonomously | Spec §12.3: Seal "records the detection and notification clock but does not make an external report autonomously unless the authorization record expressly delegates that action"; U11–U12 amendment: "No automated notification or regulatory filing is authorized merely by this document" |
| A2 | Direct outbound network access from a scanner worker, and following automatic redirects | Integration amendment to U01–U03: "Deny direct worker egress and automatic redirects" |
| A3 | Accepting user-supplied shell commands, or unrestricted scanner flags, into an adapter invocation | L01 implementation boundary: "no user-supplied shell commands or unrestricted scanner flags" |
| A4 | Letting a content field from scanner output invoke a tool or alter policy | Spec §8: "A content field cannot invoke a tool or alter policy" |
| A5 | Running a worker as root, or with unnecessary capabilities, host mounts, or a container-engine socket | Spec §8: workers "run without root, unnecessary capabilities, host mounts or a container-engine socket" |
| A6 | Presenting an unanchored decision as externally verified | D07 audit implementation detail: "the implementation must not label unanchored decisions externally verified" |
| A7 | Treating an accepted risk, suppression or exception as verified closure | W02 acceptance evidence: "accepted risk is not verified closure" |
| A8 | Any code path, hook, agent or automation that records a gate decision | PM Framework §3.3 (no self-approval, one accountable person per gate); enforced today by `release.py` having no `approve` or `sign_off` and a test that parses the module to keep it that way |
| A9 | Extending an assessment to systems discovered during it, or connected to an authorised target | Spec §12: "Permission to assess one asset never extends automatically to connected or discovered systems"; §12.2 requires stopping interaction and routing through responsible disclosure |
| A10 | Admitting a new scanner or analysis class through a profile setting | Phase 2 exit text: "No new scanner class may enter via a profile setting alone" |
| A11 | Activating scan authority on a pending approval anchor | D07: "Pending approval anchors must not activate scan authority" |
| A12 | Treating a failed, partial or stopped scan as evidence that a finding is fixed | Adapter result contract: "A failed or partial scan never implies a finding is fixed"; `coverage.CoverageStatus.proves_coverage` permits only `COMPLETE` |
| A13 | Treating merged code as acceptance of the corresponding control | E.4: "No task is Verified merely because its code is merged"; spec §2: "Passing a model test is not acceptance of the corresponding production control" |
| A14 | **Proposed.** Running more than one software adapter, or both candidates, without a new decision superseding D04 | L03 restricts to "exactly one selected Semgrep or dependency-only Trivy integration"; the baseline adds "Semgrep remains the alternative, not an additional committed adapter". Stated here as a prohibition because nothing else enforces it |

## 2. Tier B — only under one specific recorded authorisation

These are not forbidden. They are forbidden *by default*, and the named authorisation
is the only thing that changes that. The authorisation is per-instance, not a standing
grant.

| # | Capability | Authorisation required before it may happen |
|---|---|---|
| B1 | Assessing any system not owned by the project | The recorded Ghana regulatory determination (or written CSA clarification) **and** target authorisation **and** a rules-of-engagement record. Spec §12.1: "No assessment may be conducted against a system not owned by the project until qualified Ghanaian legal counsel has issued a recorded opinion"; and "No external target can enter the registry until the Ghana regulatory determination and target authorization are recorded" |
| B2 | Safe-active web testing (anything beyond passive) | "Exact lab/profile approval" per L02; prohibited write, authentication and upload classes stay denied regardless |
| B3 | Running any scanner at all | A recorded D04 selection **and** laboratory authorisation. Nothing in this repository can run one today |
| B4 | Admitting real personal data, or real external evidence | D08: approved PIA, data inventory, processing roles, minimisation, access and retention/hold/disposal map — "required before real personal data or external evidence" |
| B5 | Writing to an external audit sink, or claiming external verification | D07: selected sink, independent administration, retention lock, signing and key rotation, with "no claim of external trust from a local mock" |
| B6 | Including Semgrep-authored rule content anywhere in this project | An answer to Q1 and Q2 of `docs/decisions/D09_counsel_instruction_tooling_licences.md`. Until then the position is Undetermined, which is deliberately not permission — see that document's §7 |
| B7 | Outbound requests of any kind from the platform | D06: approved egress design, fail-closed decisions, worker escape tests, request limits and profile approval |
| B8 | Exceeding the per-target ceilings, or relaxing them | D06 profile review. The spec calls the one request per second, one in-flight request, 1 MiB response and 10-second timeout figures "reviewable ceilings, not evidence of harmlessness" |

## 3. Tier C — deferred, and expected to exist later

Not prohibited, just absent. The authoritative list is
[`docs/BOUNDARY.md`](../BOUNDARY.md), which names each absent capability and the
decision that blocks it: the API, database and queue; outbound network capability; the
external signed sink and key custody; evidence storage and disposal; the dashboard and
HTTP export surface; the scanner adapters.

This tier is here only so that the three categories are visibly different things. It
is not duplicated, so that there is one place to update.

One deferral worth naming explicitly because D04 touches it: **configuration and
infrastructure-as-code scanning is deferred**, not prohibited — "Trivy excludes
configuration scanning" (D04) and "configuration coverage remains deferred" (spec §8).
If Trivy is selected, that class must be disabled and evidenced as disabled, which is
a Tier A-style constraint on the selected adapter even though the capability itself is
only deferred.

## 4. Ratification — unsigned

To be completed by the Product/security lead as part of D05. Review is not
ratification: the question is whether this list binds subsequent work.

| Field | Value |
|---|---|
| Tier A ratified as stated | |
| Tier B ratified as stated | |
| Items moved between tiers, with reasons | |
| Items added | |
| Items rejected, with reasons | |
| Proposed rows (A14) accepted or rejected | |
| Ratified by (named) | |
| Date | |
| Review period | |

Until this block is completed, every row above is a draft reading of approved
documents by an AI agent, and nothing in it has been accepted as binding.
