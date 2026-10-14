# D09 — draft written instruction to counsel: third-party tooling licences

**A draft instruction, unissued.** Nobody has engaged counsel, nobody has sent this,
and nothing in it is legal advice. It exists so that the person who *does* issue it
sends a complete question rather than a partial one, and so the project's reading of
the licences is on the record where counsel can correct it.

| | |
|---|---|
| Decision it belongs to | D09 — "Start regulatory workstream" (Integrated Baseline v1.6, Appendix E.3) |
| Accountable role | Legal/compliance adviser, with the project manager owning submission and lead time |
| What it unblocks | D04's Option B (Semgrep) and, either way, obligations that land on W04's display and export surfaces |
| Scope fit | Inside D09's existing instruction scope — see §1 |
| Drafted | 2026-10-14, by Claude Opus 5 at the owner's instruction |
| Status | **Unissued draft. No counsel engaged, no opinion received, no question answered.** |

## 1. Why this sits inside D09 rather than needing a new decision

D09's required evidence is "Counsel engagement, written instruction covering the four
v1.3 determinations, owner and evidence register in Phase 0". The four determinations
are the Act 1038 questions in spec §12.1, and tool licensing is not one of them.

But §12.1 does not stop at the four. Its own next sentence requires that the record
"also identify privacy, cybercrime, electronic-transactions, **contractual**, sector
and public-procurement obligations applicable to the proposed target." A third-party
scanner licence is a contractual obligation, and one that bears directly on whether
Seal may lawfully operate at all in a given configuration. So this instruction extends
the D09 record on a limb it already has, rather than opening a new workstream.

**One thing the issuer must decide, not assume.** The four Act 1038 determinations
need Ghanaian cybersecurity-regulatory competence. The questions below need commercial
and intellectual-property licensing competence, and §4's licences are governed by
their own terms rather than by Ghanaian statute. Those may not be the same lawyer.
The choice is:

- brief the same counsel and accept that they may sub-instruct or decline the IP
  limb; or
- issue this as a separate instruction to commercial/IP counsel, recorded in the same
  D09 evidence register so the workstream stays one owned thing rather than two.

Either is defensible. Picking one is the legal/compliance adviser's call with the
project manager, and it should be recorded in §8 before this is sent.

## 2. What is being asked, in one sentence

Whether Seal may lawfully use each candidate scanner and its content in the ways §3
describes, and what each licence obliges Seal to do if it may.

## 3. The material facts counsel must be able to rely on

A licence opinion is only as good as the description of use it rests on. These are
the facts as they stand on 2026-10-14. Where something is undecided, it is marked
undecided rather than guessed, because the answer may differ between the options and
may therefore constrain them.

**What Seal is.** A vulnerability-management system that assesses a target
organisation's assets, records findings, tracks remediation and verifies closure. It
is in controlled Phase 0 preparation: a pure decision core exists, with no scanner,
API, database, user login or network capability. See `docs/BOUNDARY.md`.

**The intended scanner use.** Exactly one software adapter will be selected under
D04 — either Trivy restricted to dependency vulnerability scanning, or Semgrep OSS
over source code. The selected tool would run inside a restricted container, be
invoked as a separate process, and have its output treated as untrusted data and
normalised into Seal's own finding records. Findings would then be displayed to the
target organisation's users in a dashboard, summarised for their management, and
exported as JSON and CSV.

**The deployment model is NOT yet decided**, and counsel should opine on both because
D05 has not baselined it:

- **(a) Operated service.** Seal is run by the project for another organisation,
  which is the model the Act 1038 question "whether operating Seal for another
  organization is a cybersecurity service for reward" already contemplates. In this
  model Seal's operator runs the scanner and shows the customer the results.
- **(b) Licensed deployment.** The customer organisation runs its own Seal instance
  and scans its own code.

**What would be distributed.** In model (a), nothing is distributed to the customer
except findings. In model (b), a worker container image containing the scanner binary
and, for Semgrep, a rule corpus, would be distributed to the customer.

**Who the users are.** Multiple distinct organisations (tenants), separated inside
Seal. A tenant sees only its own findings.

## 4. The licences, as read by engineering

Each retrieved from a primary source on 2026-10-13 and recorded in
`D04_scanner_adapter_selection.md` §6. These readings are offered so counsel can
correct them; they are not assertions of law.

| Component | Licence | Where read |
|---|---|---|
| Trivy engine | Apache-2.0 | `aquasecurity/trivy` `LICENSE` |
| Trivy database tooling | Apache-2.0 | `aquasecurity/trivy-db` `LICENSE` |
| Advisory content Trivy ships | Predominantly GitHub Advisory Database, **CC-BY-4.0** | `github/advisory-database` `LICENSE.md` |
| Semgrep engine | **LGPL-2.1** | `semgrep/semgrep` `LICENSE` |
| Semgrep community rules | **Semgrep Rules License v1.0** | `semgrep/semgrep-rules` `LICENSE`, full text at https://semgrep.dev/legal/rules-license |

The clause that prompted this instruction, quoted in full from the Semgrep Rules
License v1.0 as retrieved on 2026-10-13:

> "You may use the rules only for your own internal business purposes. This license
> does not allow you to distribute the rules, or to make them available to others as
> a service."

Engineering's plain reading is that this excludes using Semgrep's own rules inside
Seal, because Seal exists to assess other organisations' assets and show them the
results. That reading is why Option B is currently treated as blocked. **Confirming,
qualifying or correcting it is the first question below.**

## 5. The questions

Numbered so the opinion can answer them by reference, and ordered so that Q1 is the
one that blocks a decision now.

**Q1 — The Semgrep rules restriction.** On the clause quoted in §4, does Seal's
intended use fall outside the licence?
- (a) In deployment model (a), where Seal's operator runs Semgrep and shows another
  organisation the findings — is that "making the rules available to others as a
  service"?
- (b) In deployment model (b), where the customer runs its own instance — does
  distributing a worker image containing the rule corpus breach the distribution
  restriction, and does the customer's own use then qualify as its "own internal
  business purposes"?
- (c) Does Seal using Semgrep on **its own** source code, in its own CI, with no
  customer involved, sit within "internal business purposes"? This is a narrower and
  possibly permitted use, and worth confirming separately because it would be useful
  to the project even if (a) and (b) are excluded.
- (d) If the use is excluded, is a commercial agreement with Semgrep, Inc. the route,
  and is there anything in the licence or Semgrep's published terms that would prevent
  one being sought?

**Q2 — Self-authored rules.** The licence text appears to cover only rules provided by
Semgrep, Inc. If Seal authored its own detection rules in Semgrep's rule syntax and
shipped only those:
- (a) Are those rules outside the Semgrep Rules License entirely?
- (b) Does the engine's LGPL-2.1 licence reach rule content, scan configuration, or
  the findings the engine produces, or is its reach limited to the engine code?
- (c) Does writing rules in Semgrep's syntax, or relying on its rule schema, create
  any derivative-work exposure in respect of Semgrep's own rule corpus?

**Q3 — LGPL-2.1 and the worker image.** In deployment model (b), Seal would ship a
container image containing the Semgrep binary, invoked as a separate process rather
than linked into Seal's code.
- (a) What notice and source-availability obligations does LGPL-2.1 impose on that
  distribution?
- (b) Does separate-process invocation keep Seal's own code outside the licence's
  reach, as engineering assumes, or does the image's composition change that?

**Q4 — Apache-2.0 and the worker image.** Same distribution scenario, for Trivy.
What notice, licence-copy and attribution obligations attach, and is anything owed
in model (a), where the image is never handed to the customer?

**Q5 — CC-BY-4.0 attribution for advisory content.** If Trivy is selected, Seal's
findings would derive from GitHub Advisory Database content under CC-BY-4.0.
- (a) Does showing a tenant a finding derived from that data constitute "sharing" the
  licensed material, triggering the attribution conditions?
- (b) If so, what must appear, and where — the dashboard finding view, the management
  summary, the CSV export, the JSON export, or all of them?
- (c) Seal normalises advisory data into its own finding records with its own
  severity, confidence and identity fields. Does that make the output "adapted
  material" requiring an indication that modifications were made?
- (d) Does the answer differ between deployment models (a) and (b)?

**Q6 — Interaction with the Act 1038 limb.** Does the characterisation of Seal as a
"cybersecurity service for reward" under the four determinations affect any answer
above — in particular whether operating Seal for another organisation is "internal
business purposes" under Q1(a)?

**Q7 — Evidence we should retain.** Spec §8 requires a recorded licence review per
approved scanner version combination, and D09 requires an evidence register. What form
of record of this advice should the project retain, and should the review be repeated
when a pinned tool or database version changes?

## 6. What counsel is NOT being asked to decide

- **Which scanner Seal should use.** That is D04, a Product/security lead decision on
  coverage, identity fit, capacity and licensing together. Counsel's answers are an
  input to it.
- **Whether the technical coverage of either tool is adequate.** Engineering's
  assessment is in `D04_scanner_adapter_selection.md` §§4–9.
- **Whether the project's plain reading in §4 is clever.** If it is wrong, saying so
  plainly is the most useful possible answer.

## 7. How the project will behave until this is answered

The spec's rule for pending legal guidance is that it "must be visibly owned and
escalated, never silently treated as approval." The decision core already models this:
`incident.DutyStatus.UNDETERMINED` is deliberately distinct from `NO_DUTY`, so silence
cannot read as clearance. The same discipline applies here:

- **The Semgrep licence position is UNDETERMINED, not permissive and not prohibited.**
  Option B stays blocked in `D04_scanner_adapter_selection.md` §12 condition 1.
- **No Semgrep rule content enters this repository** — not as a fixture, not as an
  example, not as a test input — until Q1 and Q2 are answered.
- **A D04 selection of Option A does not depend on this instruction.** Trivy's
  position raises obligations (Q4, Q5), not a blocker. If the authority selects
  Option A, Q5's answer shapes W04's display and export design, so it is still worth
  asking before that UI is built rather than after.
- **Nothing here authorises a scanner run.** That remains gated on D04 and on the
  laboratory authorisation in the baseline.

## 8. Issue record — unsigned

To be completed by the person issuing the instruction. Drafting it is not issuing it.

| Field | Value |
|---|---|
| Counsel instructed (name, firm) | |
| Competence confirmed for the IP/commercial limb | |
| Same counsel as the Act 1038 limb, or separate (§1) | |
| Instruction issued by (named) | |
| Date issued | |
| Lead-time assumption | |
| Submission owner | |
| Target decision date | |
| D09 evidence register reference | |
| Opinion received (date, reference) | |

## 9. Materials to attach when issuing

1. This instruction.
2. `docs/decisions/D04_scanner_adapter_selection.md` — the licence readings in §6, the
   use description, and the recommendation the answer feeds.
3. `docs/BOUNDARY.md` — what Seal is and is not today, so the use description is not
   mistaken for a deployed system.
4. The licence texts themselves, retrieved and dated, rather than links alone: the
   Semgrep Rules License v1.0, LGPL-2.1, Apache-2.0 and CC-BY-4.0.
5. Spec §12.1 and Appendix E.3 D09, so counsel can see the record this opinion joins.

## 10. Limits of this draft

- **Not legal advice, and not a legal determination.** §4 states a plain reading of
  licence text for counsel to correct. The project has made no determination.
- **No counsel is engaged.** D09's status is Unconfirmed / Blocked, and this draft
  does not change it.
- **The deployment model is genuinely undecided**, so §3 asks for an opinion on two
  scenarios. If D05 later baselines one, the instruction should be narrowed before
  issue rather than sent as-is.
- **Drafted by an AI agent.** It requires review by the legal/compliance adviser
  before issue, and the issuer owns every word of what actually goes out.
