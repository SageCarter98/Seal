# D01 — appointments and separation of duties: decision pack

**Decision pack. Nothing here is a decision, and nothing here appoints anyone.** D01
belongs to the Project Authority. This pack prepares its four required evidence
elements, reports what separation of duties the repository can actually evidence after
fifteen pull requests, and reports what became of the one measured constraint that
changed what the project could promise: while the repository was private, the review
every merged change carries could not be *required* by any setting in it. The owner
removed that obstacle on 2026-10-18 by making the repository public (§4), so protection
is now available and unconfigured. Every measurement below comes from
`tools/d01_review_separation_probe.py` reading live GitHub state.

| | |
|---|---|
| Decision | Appoint sponsor, project manager, acceptance authority and independent reviewer (Integrated Baseline v1.6, Appendix E.3, D01) |
| Accountable role | Project Authority |
| Required evidence | "Names, separation checks, appointment scope and review period required before Phase 0 exit" |
| Blocks | Phase 0 exit, and through it every other decision — D02–D11 each name an accountable role that D01 is the decision appointing; every pack in this folder ends in an unsigned decision record for want of a named authority |
| Depends on | D02 for the class that sets how strict separation must be; D11 for whether independent assurance — including a deputy reviewer — is funded as a distinct line item |
| Drafted | 2026-10-18, by Claude Opus 5 at the owner's instruction |
| Status | **Unconfirmed / Blocked. §12's decision record is unsigned.** |

## 1. The decision as the documents state it

Appendix E.3's D01 row reads: *"Appoint sponsor, project manager, acceptance authority
and independent reviewer"*, accountable role *Project Authority*, status *"Unconfirmed /
Blocked. Names, separation checks, appointment scope and review period required before
Phase 0 exit"*.

Baseline §15.3 makes the sequencing explicit: *"Phase 0 completes D01–D11 at their stated
gates"*, and Phase 0 exit *"requires the named review and Project Authority decision"*.
So D01 is not one of eleven parallel decisions. It is the one that creates the authority
the other ten are waiting for, and the one that makes "the named review" nameable.

Four appointments are required. A fifth role — the Project Authority itself — is the
accountable role for D01 and is therefore assumed rather than appointed by it. The
framework quoted below constitutes it and names its chair, so what is open is not who
holds it but whether it acts here as the standing body or through a recorded delegate
(§11 Q1).

The institutional framework this project is governed under states the separation rules
D01 has to satisfy. KenAddme IT Links Project Management Framework v1.3 §3.3 reads:

> "No project manager may approve their own charter, baseline, material change, release,
> acceptance or closure. For Class A and Class B projects, the sponsor and final
> acceptance authority must be different people, and no individual may be the sole
> author, reviewer, tester and approver of the same material deliverable."

and, for the case where the team is too small to deliver that:

> "Where staffing prevents the required separation, the Project Authority must approve a
> named reviewer who is independent of delivery, the evidence to be checked and the time
> limit. Class A compensating arrangements require Executive Authority approval and may
> not waive legal, security, privacy or financial controls."

§3.4 settles who the appointing authority is: the Project Authority is *"the standing
governance body for portfolio priority, Class A oversight, major commitments and
exceptions"*, chaired by Freston Kenny Adedeme as Document Owner / Executive Authority,
*"or by a formally recorded delegate"*.

That framework is a different document family from Seal's baseline — it governs the
project, it is not part of the product specification — but it binds the same decision,
and where the two differ the stronger control and the more senior approver govern.

## 2. What the repository evidences today

Fifteen pull requests, fourteen merged. Probe section 1:

```
  PR  author         approved by    merged by      open>appr appr>merge  size
   1  SageCarter98   kenAddme       kenAddme             26m        28s  +8000/-0
   2  SageCarter98   kenAddme       SageCarter98       12.9h         1m  +4475/-19
   3  SageCarter98   kenAddme       kenAddme             15m        21s  +347/-0
   ...
  14  SageCarter98   kenAddme       kenAddme             30m        50s  +763/-1
  15  SageCarter98   (none)         (unmerged)            --         --  +407/-113

Of 14 merged pull requests:
  author was not among the approvers   -> 14/14
  merger was not among the approvers   -> 1/14
  merged with no approving review      -> 0/14
```

Three facts worth stating separately, because they are usually run together:

**Nobody has approved their own change.** 14 of 14. Every merged change was written
under the `SageCarter98` account and approved under the `kenAddme` account. That is the
separation control that matters, and it holds without exception.

**An account is not a person, and this project's two accounts are two people.** The
owner confirmed on 2026-10-13 that `SageCarter98` is Freston Kenny Adedeme's personal
account and `kenAddme` is the KenAddme IT Links company account, entrusted to Russell
Kenny, who is a different person. Without that statement the account split would prove
nothing — the same person can hold two accounts, and an earlier session recorded exactly
that wrong inference before the owner corrected it. **The separation evidence in this
repository therefore rests on a verbal attribution, not on anything GitHub can show.**
D01 is where that attribution becomes a recorded appointment or stops being relied on.

**Collaborator permissions are at their floor.** `SageCarter98` holds admin as the owner;
`kenAddme` holds write (pull, push, triage). Write is enough to review, approve and
merge and cannot change settings, secrets or collaborators, so the reviewer holds exactly
the permissions the review requires and none beyond it. This is a personal repository,
so write is also the collaborator ceiling — admin would require an organisation-owned
repository.

**A third account was invited on 2026-10-18**: `MiltonBello15`, at write, at the owner's
direction, named by him as Milton. The invitation is **pending acceptance** at the time
of writing, so the account can do nothing yet. Three things about it belong in this pack
rather than in a commit message:

- **It is not an appointment.** Write access is the permission to open, review, approve
  and merge. Which role Milton holds — if any — is §12's to record, and §12 is unsigned.
  He is a collaborator who has been given one named obligation to own (see
  `../TRACEABILITY.md`, "Obligations with named owners"), which is a different thing from
  a D01 role with a scope and a review period.
- **The attribution carries the same caveat as `kenAddme`'s.** That this account is
  operated by a person called Milton is the owner's statement. Nothing in GitHub
  corroborates it, and this pack does not infer a surname from a username.
- **It changes the separation arithmetic, but only once he accepts and only if D01 says
  so.** §5 was written about two people. A third person with write on a public repository
  and no recorded scope is not yet an improvement to separation; it is one more account
  that can approve a pull request. What makes it an improvement is §12 naming what he
  may approve.

## 3. A practice is not an appointment

D01 asks for four things. The repository supplies part of one of them.

| D01 requires | State | Evidence |
|---|---|---|
| **Names** | **Absent as a record.** Two people are known and neither is appointed to a named role. No document in this repository states who the sponsor, project manager, acceptance authority or independent reviewer is | — |
| **Separation checks** | **Evidenced in practice, for one control.** Author never approved; reviewer never authored | Probe §1; 14/14 |
| **Appointment scope** | **Absent.** Nothing states what the reviewer is reviewing for — correctness, security, licence exposure, governance — or what they may refuse | — |
| **Review period** | **Absent.** Nothing states for how long the appointment runs or when it is revisited | — |

The tracker records the same shape from the PM side: item **#19** (*"Sponsor, project
manager and key decision makers nominated"*) and item **#21** (*"Governance and
tolerances recorded: decision rights, reporting, escalation, role separation, financial
band, change authority"*) are both **Not started**, while SDLC items **#116**
(*"commits and pull/merge requests linked with reviewer evidence"*), **#118** (*"Peer
review completed"*) and **#124** (*"AI- or tool-generated code reviewed, tested and
accepted by a competent human"*) are **Complete**. That combination is exactly the
finding: the reviewing is done and recorded; the appointing is not.

What the practice cannot carry on its own: a reviewer with no stated scope cannot be
said to have failed to review something, and a reviewer with no stated period cannot be
said to have stopped. Fourteen approvals are evidence of a habit. Appendix E.3 asks for
an appointment, which is a commitment with edges.

## 4. Enforcement was unavailable; the owner removed the obstacle by publishing

Probe section 2 asked GitHub what the repository *requires*, as opposed to what it has
done. On the morning of 2026-10-18, while the repository was private, it answered:

```
main carries no readable branch protection. gh reported:
  gh: Upgrade to GitHub Pro or make this repository public to enable this feature. (HTTP 403)
```

Tracker item **#117** (*"Protected release branches enforced; merges require successful
checks and review"*) had been carried as **Not started**, which reads like a setting
nobody had got round to. It was not: branch protection could not be enabled for a
private repository on that plan at all. The three routes to enforcement were a paid
plan, a public repository, or an organisation-owned one — a cost decision, a disclosure
decision and an ownership decision.

**The owner took the disclosure route the same day.** Acting as Project Authority (§11
Q1), and after being shown what publication would expose, he directed the repository be
made public; it was, on 2026-10-18. The same request now answers:

```
{"message":"Branch not protected","status":"404"}
```

404 rather than 403 was the whole point: protection became *available and
unconfigured* instead of unavailable. **It was then configured, the same day, at the
owner's direction**:

```
approving reviews         -> 1        force pushes allowed      -> False
stale reviews dismissed   -> True     branch deletion allowed   -> False
conversations resolved    -> True     rules bind administrators -> True
branch up to date         -> True
required checks           -> test (py3.10), test (py3.13), purity boundary,
                             no committed credentials
```

`main` no longer accepts a direct push or an unreviewed merge, and tracker item **#117**
is recorded Complete against this configuration.

**The line that decides whether the rest means anything is the last one.** Every change
in §2 was authored by the account that owns the repository; an owner exempt from the
rules can merge past all of them, so `enforce_admins` is what separates enforcement from
decoration here. It is set, which has a consequence the owner accepted knowingly: **he
can no longer merge his own pull requests**, including the two open as this was written.
Protection remains reversible — an administrator can lift it — but lifting it is a
recorded settings change rather than a quiet unreviewed merge, and that difference is
the control. §5's missing deputy is what makes the distinction load-bearing rather than
theoretical: with one reviewer and no deputy, the pressure to lift protection arrives
the first time he is unavailable.

**What the disclosure cost, recorded here because a decision's price belongs in the
record.** Publication is permanent in effect: clones, caches, forks and scraped copies
survive any later reversal. It exposed the whole repository and its history, including
the controlled `.docx` document set and `Seal_All_Documents_2026_09_10.zip` — which
carries KenAddme IT Links' own institutional governance frameworks (PM v1.0, SDLC v1.1)
rather than Seal product material — the unissued draft counsel instruction in
`D09_counsel_instruction_tooling_licences.md`, the threat model, and the commit-author
email addresses of both accounts. The owner was shown each of these before directing
publication and accepted them; this paragraph records the trade, not a reservation
about it.

One consequence falls on §2 and should not be lost. The separation claim rests on the
owner's statement that `SageCarter98` and `kenAddme` are two people. That statement is
now the only thing standing between a public reader and the opposite conclusion, since
the `kenAddme` commit-author address is a personal one of similar form. §10.3 asked for
the attribution in writing when the repository was private; with it public, that step is
no longer only an internal tidiness.

## 5. Five roles, two people

The roles D01 touches are sponsor, project manager, acceptance authority and independent
reviewer, plus the Project Authority that appoints them. Two people are known to the
project. Tested against §3.3's actual provisions rather than against a general sense
that two people cannot separate duties, the result is not what it looks like:

| §3.3 provision | A two-person set: owner as sponsor + project manager, Russell Kenny as independent reviewer + acceptance authority |
|---|---|
| PM must not approve their own charter, baseline, material change, release, acceptance or closure | **Satisfied.** The owner approves none of these; the reviewer does |
| Class A: sponsor and final acceptance authority must be different people | **Satisfied.** Owner sponsors, Russell accepts |
| No individual may be sole author, reviewer, tester and approver of one deliverable | **Satisfied.** The owner authors and tests; Russell reviews and approves. Nobody holds all four |

**So a two-person appointment set can satisfy §3.3 for a Class A project, and it does
not need the compensating-assurance route at all.** That matters because the
compensating-assurance clause is expensive to use: for Class A it requires **Executive
Authority** approval, a level above the Project Authority, and §3.4 puts the same person
in both chairs — so an exception would be escalated to the person who authored every
change in the repository. Recommending an exception the project does not need would walk
into that for nothing.

**What the arrangement does not fix, and D01 should not imply it does.**

1. **There is no deputy.** One person is the only reviewer and the only acceptance
   authority. When he is unavailable, either work stops or something merges unreviewed,
   and the second is what actually happens under deadline. §3.3 is satisfied by the
   arrangement; it says nothing about its availability.
2. **Reviewer and acceptance authority are the same person.** §3.3 permits it — it
   separates sponsor from acceptance authority, not reviewer from acceptance authority —
   but it means the change-level check and the deliverable-level acceptance are one
   person's judgement, reviewed by nobody. For the second-highest software class that is
   a concentration worth recording rather than discovering at Gate 4.
3. **The independent reviewer reviews under the company's own account.** `kenAddme` is
   the KenAddme IT Links company account and Seal is a KenAddme IT Links asset.
   Independence *from delivery* is clear; independence from the owning organisation is
   not, and Appendix E.3 does not say which it means.
4. **Everything rests on the attribution in §2.** If `SageCarter98` and `kenAddme` were
   one person, every row of the table above inverts and the project has had no separation
   at all. The attribution is the owner's recorded statement, and §10.3 is where it gets
   re-confirmed in writing.

The honest summary: D01 is appointable today without exceptions, and the work is naming
the people, scoping the review, setting the period, and deciding what happens when the
single reviewer is away. The difficulty is not the arithmetic of five roles across two
people — it is that the arrangement has no slack, and slack is what D11 would fund.

**The third collaborator invited on 2026-10-18 (§2) is the first slack this project has
had, and it is not slack until D01 uses it.** An accepted invitation gives Milton the
mechanical ability to approve a pull request. It does not make him a deputy reviewer,
because a deputy who may approve anything is not a control, and it does not make him an
acceptance authority, because §3.3 would then need the sponsor to be someone else again.
The two appointments it could support are a **deputy independent reviewer** — which would
answer §11 Q10 and remove the pressure to lift branch protection when one reviewer is
away — or the **acceptance authority**, which would let the current reviewer stop holding
both the change-level and the deliverable-level judgement. **Those are different
decisions with different consequences, and picking one is the Project Authority's act,
not an inference from a collaborator invitation.**

## 6. What the evidence cannot show

Three limits, recorded so a signature does not inherit them silently.

**Review depth is not measured anywhere.** PR #1 was +8000/−0 and was approved 26 minutes
after it opened. That is around 300 lines a minute if the review began when the pull
request opened. The number is not proof of a shallow review — the branch may have been
read before it was opened, and much of that 8000 was generated test and specification
text rather than novel logic — but nothing in this repository can distinguish a thorough
review from a fast one, and D01's "appointment scope" is the place that could say what a
review is expected to cover.

**The approve-to-merge gap measures clicks, not reading.** Thirteen of fourteen merges
followed their approval by 15 to 50 seconds, which is what it looks like when the
reviewer approves and merges in one sitting. It neither proves nor disproves anything
about the review itself, and it is listed here only because it is the kind of number
that looks like a finding when it is not.

**One merge was performed by the author.** PR #2, merged by `SageCarter98` 1 minute after
`kenAddme` approved it. Approver and merger differ there, which is the stricter
arrangement, not the weaker one; it is recorded for completeness.

## 7. What D01 can decide now, and what it cannot

**Decidable now, with no external dependency:** all four appointments, including the
acceptance authority, since §5 shows a two-person set satisfying §3.3 for Class A
without an exception; the scope of the review (what the reviewer reviews for and may
refuse); and the review period and its revisit date. The branch-protection question
that sat here is closed: §4 records what was configured, including that the rules bind
the owner's admin account.

**Not decidable now:**

- **A deputy for the independent reviewer and acceptance authority**, because no third
  person is engaged and D11 has not funded the effort. This is the one genuine staffing
  gap, and it is an availability gap rather than a separation breach.
- **Whether a company-account reviewer is "independent" in the sense Appendix E.3
  means**, which is a judgement for the Project Authority. This pack does not assume it
  either way.
- **Whether the class justifies funding that deputy**, which belongs to D02 and D11
  rather than to D01.

So D01 does not need to be partial. It can be signed in full, with the deputy recorded
as a named, time-bound gap carrying a stated consequence — which is a stronger record
than deferring an appointment that §3.3 already permits.

## 8. The D02 and D11 dependencies, stated plainly

**D02** confirms *"Project Class A / Software Class 3"* and documents Class 4 escalation
triggers. The class is what makes separation strict: Class A is the highest PM band and
Class 3 the second-highest SDLC band, and both frameworks tighten role separation as the
class rises. D01 inherits whatever D02 confirms, so an appointment set built for Class A
and then reclassified downward is over-built, and one built for a hoped-for lower class
and then confirmed at A is non-compliant. **The tracker already carries Class A / Class 3
as the project's classification** while D02 is unsigned, so the live tracking assumes the
stricter answer. D01 should assume the same.

**D11** funds assurance separately — *"QA, security, privacy, accessibility, recovery,
legal and independent-review effort, cost, owner and dates as a distinct G2 line item"*.
The Software Development and Engineering Framework v1.4 carries the same requirement and
adds that Class 3 and Class 4 client proposals must disclose the assurance effort during
commercial scoping. That is the money behind §5's missing deputy and behind the paid
plan §4 says enforcement would need. D01 can name a role; it cannot fund one. If the
recommendation in §9 is taken, D11 inherits two concrete line items from it.

## 9. Recommendation (a proposal, not a decision)

1. **Record** the Project Authority first and separately. Every other appointment in this
   pack is made by that role, so an appointment set signed without it has no author.
2. **Appoint** all four roles to the two people already doing the work — the owner as
   sponsor and project manager, Russell Kenny as independent reviewer and acceptance
   authority — which §5 shows satisfies §3.3 for Class A without a compensating
   arrangement. Converting practice into appointment introduces nobody new.
3. **State the review scope explicitly**: what the independent reviewer reviews for, what
   they may refuse, and what must not be merged without them. Fourteen approvals with no
   stated scope are the gap §3 names, and this is the cheapest part of D01 to close.
4. **State the review period and a revisit date**, so the appointment can lapse rather
   than fade.
5. **Record the absence of a deputy as a named, time-bound gap** with its consequence
   stated: with one reviewer and no deputy, work either waits or merges unreviewed when
   he is unavailable, and the second is what happens under deadline. Name who decides
   which, and the date the gap is revisited. Do **not** route this through §3.3's
   compensating-assurance clause — the arrangement needs no exception, and for Class A
   that clause would escalate to an Executive Authority chaired by the same person who
   authored every change.
6. ~~Configure branch protection on `main`.~~ **Done, 2026-10-18** — the
   shortest-lived recommendation in the pack, superseded within hours of being written.
   §4 records the configuration: one approving review, the four existing status checks,
   stale reviews dismissed, no force-push or deletion, and the rules binding the owner's
   admin account. What remains for D01 is the decision this created rather than solved:
   **who merges when the single reviewer is unavailable**, given that the honest options
   are waiting or lifting protection, and §9.5 is where that gap is recorded.
7. **Hand D11 one line item**: deputy-reviewer effort. The platform cost the first
   draft listed beside it was paid in disclosure instead of money (§4).

This is a recommendation from a decision pack. It is not a decision, and the Project
Authority may reject any part of it.

## 10. What must be verified before §12 is signed

1. Re-run `python tools/d01_review_separation_probe.py` and confirm the separation counts
   still read 14/14 or better, that no merge has landed without an approving review, and
   what section 2 now says about protection. The probe reads live GitHub state, so both
   a lapse in practice and a change in enforcement show up as changed lines.
2. Confirm directly with Russell Kenny that he accepts both the independent reviewer
   and the acceptance authority appointment, their scope and their period. §3's evidence is fourteen approvals, which is
   consent to review changes, not consent to hold an appointment. Appendix E.3's
   first-five-days list is a *proposed* assignment, and an unaccepted assignment leaves
   the task Blocked however complete this pack is.
3. Confirm the account-to-person attribution in §2 is still accurate, in writing, since
   the whole separation claim rests on it, nothing in GitHub can corroborate it, and the
   repository is now public (§4's closing paragraph).
4. Check the D01 row and §15.3 against the approved `.docx` directly. The quotations here
   come from a stdlib text extraction of `Seal_Integrated_Baseline_v1_6.docx`; headings
   and paragraph text extract reliably, but a table-formatting difference would not be
   visible in it.
5. Confirm with D02's owner that Class A / Class 3 is still the operating assumption,
   since §5's whole difficulty follows from it.

## 11. Open questions for the Project Authority

1. Does the Project Authority act here as the standing body §3.4 constitutes, or
   through *"a formally recorded delegate"* — and if a delegate, who, recorded where?
   §3.4 names the chair; it does not say who signs for this project. **Partly answered
   2026-10-18: the owner confirmed he is "the one" when directing publication, which
   §4 records as a Project Authority act. Whether that is the standing body, the
   Executive Authority chair acting alone, or a delegate is still unrecorded — and it
   matters, because §3.3's compensating-assurance route needs those to be distinguishable
   people.**
2. Is the independent reviewer independent enough for Appendix E.3's purpose when the
   account they review under is the company's own?
3. Is the reviewer and the acceptance authority being the same person accepted for a
   Class A / Class 3 project, given §3.3 permits it and §5's second point records
   what it concentrates?
4. What exactly does the independent reviewer review for, and what may they refuse?
5. For how long does each appointment run, and what triggers a revisit?
6. Is the sponsor a distinct appointment here, or does the Project Authority hold it?
7. ~~Is unenforceable branch protection accepted as a time-bound exception, or funded as
   a platform change?~~ **Resolved 2026-10-18: neither. The repository was published and
   protection configured to bind the owner's admin account too (§4). The question that
   replaces it is §11 Q10's, now sharper — with protection binding everyone and no
   deputy, an unavailable reviewer stops merges until someone lifts protection.**
8. Does review depth get a stated expectation (a size limit per pull request, a required
   checklist), or does it stay the reviewer's judgement?
9. What happens to work already merged under a practice that predates the appointments —
   is it re-reviewed, accepted as-is, or accepted with a recorded limitation?
10. Who deputises when the single independent reviewer is unavailable — and until
    someone does, who holds the authority to lift branch protection, on what record, and
    for how long? §4's configuration turned this from a staffing preference into the
    project's only route to merging in that situation. **A candidate now exists:
    `MiltonBello15` was invited at write on 2026-10-18 (§2). What is open is whether he
    is appointed deputy reviewer, acceptance authority, or neither, and what he may
    approve — not whether he can click approve, which write access already settles.**

## 12. Decision record — unsigned

| Field | Value |
|---|---|
| Decision | Appoint sponsor, project manager, acceptance authority and independent reviewer (D01) |
| Project Authority | *(unsigned)* |
| Sponsor | *(unset)* |
| Project manager | *(unset)* |
| Acceptance authority | *(unset)* |
| Independent reviewer | *(unset)* |
| Review scope | *(unset)* |
| Review period and revisit date | *(unset)* |
| Separation exceptions recorded | *(unset)* |
| Date | *(unset)* |

**This table is deliberately empty.** D01 is recorded as "Unconfirmed / Blocked" in
Appendix E.3 and nothing in this repository can change that. An appointment is a named
human authority's act; no document, probe or tooling in this project may record one on
anyone's behalf, and that applies with particular force to a decision whose entire
subject is who is allowed to decide.

## 13. Provenance and limits

Drafted 2026-10-18 by Claude Opus 5 at the owner's instruction. Quotations come from
`Seal_Integrated_Baseline_v1_6.docx` (Appendix E.3 rows D01, D02 and D11, and §15.3) read
through a stdlib text extraction; the `.docx` file remains authoritative.

The separation provisions quoted in §1 come from the KenAddme IT Links Project Management
Framework v1.3 §3.3 and §3.4, and the assurance-funding line in §8 from the Software
Development and Engineering Framework v1.4, both read from the Markdown working
references at `~/.claude/frameworks/`; the approved `.docx` originals in that folder
remain the controlled versions. These frameworks govern the project and are not part of
its product specification. **They were read before §5 was written and they changed it**:
a first draft of this pack asserted that no two-person arrangement could satisfy §3.3
and recommended deferring the acceptance authority. §3.3's actual text separates sponsor
from acceptance authority and bars one person holding all four of author, reviewer,
tester and approver — neither of which a two-person set breaches — so the recommendation
changed from deferral to appointment, and the real gap turned out to be the missing
deputy.

Every measurement in §2, §4 and §6 comes from `tools/d01_review_separation_probe.py`
reading live GitHub state on 2026-10-18 — §4 quotes it twice, before and after the
repository was made public that day, and the probe asserts nothing — it prints what
the repository evidences so a person can judge it. Tracker item numbers and statuses come
from the `pm-sdlc-tracker` database for this project, read the same day.

**What this pack is not.** It is not an appointment, not a separation-of-duties
attestation, and not evidence that the review practice it measures is adequate. It
measures one control (author never approves) and reports that the other three elements
D01 requires — names, scope, period — do not exist in any form. The attribution of
accounts to people in §2 is the owner's statement, recorded as such; it is the single
load-bearing fact in the pack that no tool here can verify, and §10.3 exists because of
it.
