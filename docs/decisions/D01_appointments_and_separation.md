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
under the `SageCarter98` account and approved under the `kenAddme` account. That is a
**role** separation and it holds without exception. It is not independence, and the
relationships disclosed below are why the distinction has to be made every time this
number is quoted: author ≠ approver is a fact about accounts, while §14.1's "independent
enough to challenge the delivery team" is a question about people that 14 of 14 cannot
answer.

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
direction, named by him as **Milton Kenny Adedeme**. The invitation is **pending
acceptance** at the time of writing, so the account can do nothing yet. Three things about it belong in this pack
rather than in a commit message:

- **It is not an appointment.** Write access is the permission to open, review, approve
  and merge. Which role Milton holds — if any — is §12's to record, and §12 is unsigned.
  He is a collaborator who has been given one named obligation to own (see
  `../TRACEABILITY.md`, "Obligations with named owners"), which is a different thing from
  a D01 role with a scope and a review period.
- **The attribution carries the same caveat as `kenAddme`'s.** That this account is
  operated by Milton Kenny Adedeme is the owner's statement, given on 2026-10-18.
  Nothing in GitHub corroborates it.
- **It changes the separation arithmetic, but only once he accepts and only if D01 says
  so.** §5 was written about two people. A third person with write on a public repository
  and no recorded scope is not yet an improvement to separation; it is one more account
  that can approve a pull request. What makes it an improvement is §12 naming what he
  may approve.

**The three named individuals' names share components, and a Class A separation record
has to address that rather than pass over it.** The people named in this pack are Freston
Kenny Adedeme (owner, Project Authority, author of every change), Russell Kenny
(independent reviewer, acceptance authority until Gate 4) and Milton Kenny Adedeme
(deputy reviewer, acceptance authority from Gate 4). "Kenny" appears in all three and
"Kenny Adedeme" in two.

> **Disclosed 2026-10-18 by the owner, in full:**
>
> | Person | Roles | Relationship |
> |---|---|---|
> | Freston Kenny Adedeme (`SageCarter98`) | Project Authority, Executive Authority chair, sponsor, project manager, author of every change | — |
> | Russell Kenny Adedeme (`kenAddme`) | Independent reviewer; acceptance authority until Gate 4 | **Relative, through the extended family — not a sibling** |
> | Milton Kenny Adedeme (`MiltonBello15`) | Deputy independent reviewer; acceptance authority from Gate 4 | **Brother** |
>
> Recorded as given rather than inferred. The pack asked this question in the morning
> precisely so the answer would come from the Project Authority rather than from a
> reader's guess, and §10.4 required it before signing. Both answers came the same day.
>
> **Correction, same day.** This pack first recorded Russell as a brother. That was the
> drafter's error, not the owner's statement, and the owner corrected it: the relation is
> through the extended family. The degree matters to §14.1's test and the two are
> therefore kept distinct everywhere below rather than collapsed into "related".

**Every assurance role in this project is held by a relative of its sole author, and one
of the two is his brother.** That is the finding, stated plainly because the alternative
is a record that implies otherwise by omission. It is a statement about structure, not
about anyone's conduct: the fourteen approvals happened, the review findings were real,
and nothing here suggests a review was waved through.

The degree is the part that does the work, and §14.1's test is why. "Independent enough
to challenge the delivery team" asks whether a refusal is realistic, which is a question
about pressure rather than about genealogy — and the pressure on an extended-family
reviewer and on a sibling are not the same thing. So the two roles are weighed separately
below, and the answer is not the same for both.

The disclosure is what the framework asks for first, and it settles nothing on its own,
for three reasons:

1. **The framework's independence test is functional, not formal.** §14.1: "High-risk
   deliverables require reviewers independent enough to challenge the delivery team."
   §19.1: assurance must be "sufficiently independent for the reviewer to challenge
   assumptions and report concerns without pressure." Neither bars a relative. Both ask a
   question about pressure that a role title cannot answer and a surname cannot settle
   either way.
2. **A material conflict of interest is a mandatory escalation, not a private
   judgement.** §12.2 lists "material conflict of interest, falsified evidence or
   deliberate concealment of project status" among the immediate escalation triggers. The
   way to comply is to record the relationships and the reasoning, so that if one is
   material it escalates, and if none is, the record shows that was examined rather than
   assumed.
3. **The repository is public (§4).** Any reader can see the three names, the single
   authoring account, and the fourteen approvals. A reader who forms their own view from
   that is working from exactly the material this pack publishes; the only way the record
   answers them is by stating the position.

> **Judged 2026-10-18 by the owner as Project Authority: Russell Kenny Adedeme's
> relation is through the extended family and is not material to his independence as
> reviewer. He continues as independent reviewer, and no unrelated person is to be
> engaged in addition.** Recorded as the Project Authority's judgement under §12.2, which
> is where the judgement belongs; this pack's §9.8 had recommended otherwise and that
> recommendation is declined on the record rather than quietly dropped.

**Weighed against those three, the disclosure lands differently on the different
controls — which is why the pack does not reduce it to one verdict.**

*The deputy reviewer half is defensible on its face.* A deputy who reviews code when the
primary reviewer is unavailable, under a recorded trigger, with the primary's scope and
the primary still accountable, is a brother checking work — and the alternative on offer
was lifting branch protection and merging unreviewed. Between a related reviewer and no
reviewer, the related reviewer is the stronger control, and §3.3's compensating-assurance
clause exists for exactly that trade.

*The primary reviewer is settled, by the judgement recorded above.* An extended-family
reviewer, reviewing under a company account, with every approval and finding on a public
record, is the arrangement the Project Authority has judged non-material under §12.2 —
and the judgement is his to make, not this pack's. What the pack adds is the reason the
judgement is tenable rather than merely asserted: the reviewer's work is visible. Every
approval, every COMMENTED-versus-APPROVED state and every merge is in the public history,
so a reviewer who stopped challenging would leave a trace that an auditor could find.
That is a weaker control than independence and it is not nothing.

*Acceptance is where the degree stops helping.* Acceptance is the single control in this
project with no second pair of eyes behind it, and under the appointment stated earlier
today it passes at Gate 4 to the author's **brother**, where the author is also the
sponsor, the project manager and the Project Authority who made the appointment. The
extended-family reasoning above does not reach that: it is the sibling relation, on the
one control whose output is a signature rather than a reviewable diff. Nothing here says
a refusal would not happen. It says the record cannot demonstrate that it could, and a
reader of a public Class A record will ask about that specific row.

**And the escalation route has a loop the record should name.** §12.2 makes a *material*
conflict of interest an immediate escalation, and §3.3 requires Executive Authority
approval for Class A compensating arrangements. §3.4 puts the Executive Authority chair
and the Project Authority chair in the same person — who is also the author, the sponsor,
the project manager, and the brother in question. **Every route this framework offers for
testing or compensating this conflict terminates in the person the conflict is about.**
That is not a reason to stop; it is the reason the disclosure and the reasoning have to
be written down here, where they can be read by someone outside the loop, since no
approval step inside the loop adds anything the disclosure does not.

> **Decided 2026-10-18 by the owner as Project Authority: Milton takes acceptance
> authority at Gate 4 as stated, under a recorded compensating arrangement.** That is
> option 2 below. It does not make the sibling relation immaterial and this pack does not
> record it as immaterial — it records that the Project Authority accepted a known,
> disclosed conflict with compensating measures, which is the one §12.2-compliant way to
> keep it. **The terms were adopted the same day and are in force at §12.1.**

**With the reviewer question judged, one question remained and it is now decided: who
holds acceptance.** The three closings, with the one taken marked:

1. ~~Russell keeps acceptance past Gate 4, Milton deputy only.~~ Not taken. It was this
   pack's recommendation, it needed nobody new, and the Project Authority chose otherwise.
2. **Milton takes acceptance at Gate 4 as stated, under a recorded compensating
   arrangement. ← taken.** §3.3 is the clause that permits this and it is not permissive
   about the terms: a compensating arrangement must name the reviewer, the evidence to be
   checked and the time limit, and for Class A it "require[s] Executive Authority
   approval" and "may not waive legal, security, privacy or financial controls". §9.8
   proposes the terms; the Executive Authority step is a self-approval and §12 must say so
   in those words.
3. ~~An unrelated acceptance authority.~~ Not taken. It remains the only closing that
   produces independence on this control rather than compensating for its absence, and it
   stays on D11's list as the option purchasable later.

**What option 2 costs, said once and plainly.** The project's final acceptance will be
signed by the author's brother, under terms set by the author, approved by the author
wearing the Executive Authority hat. No step in that chain is independent. The
compensating measures below do not fix that; they make the acceptance *checkable by
someone else afterwards*, which is a different and weaker property — and it is the
property the pack can actually deliver. A reader who disagrees with the Project
Authority's judgement will be able to see exactly what was decided, by whom, on what
terms, and what evidence the acceptance rested on. That is the whole of what disclosure
buys, and it is why the terms have to be specific rather than reassuring.

Whichever is chosen, a weak arrangement that is disclosed is auditable, while the same
arrangement implied by omission is the finding. This pack's job was to make sure the first
sentence of that comparison is the true one, and as of today it is.

## 3. A practice is not an appointment

D01 asks for four things. The repository supplies part of one of them.

| D01 requires | State | Evidence |
|---|---|---|
| **Names** | **Absent as a record.** Two people are known and neither is appointed to a named role. No document in this repository states who the sponsor, project manager, acceptance authority or independent reviewer is | — |
| **Separation checks** | **Evidenced in practice, for role separation only.** Author never approved; reviewer never authored. Independence in §14.1/§19.1's sense is not evidenced by those numbers: the reviewer is an extended-family relative, judged non-material by the Project Authority, and the acceptance authority named for Gate 4 is the author's brother (§2) | Probe §1; 14/14, read with §2 |
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
mechanical ability to approve a pull request; it is the appointment that says what he may
approve, and when.

> **Stated 2026-10-18 by the owner as Project Authority (§11 Q10, Q3): Milton is deputy
> independent reviewer now, and acceptance authority from Gate 4.** Recorded here as the
> Project Authority's position; §12 is unsigned and this is not a substitute for signing
> it.

Tested against §3.3 the way the two-person set was tested above, the staged arrangement
is compliant in both of its stages and strictly better in the second:

| §3.3 provision | Now (owner sponsors + manages, Russell reviews + accepts, Milton deputises) | From Gate 4 (Milton accepts) |
|---|---|---|
| PM must not approve their own work | Satisfied | Satisfied |
| Class A: sponsor ≠ final acceptance authority | Satisfied | Satisfied |
| Nobody sole author, reviewer, tester *and* approver | Satisfied | Satisfied |
| §5's own second point: reviewer and acceptance authority are one person | **Still true** | **Resolved** — the change-level check and the deliverable-level acceptance become two people |

**What the tables above do not test.** Every provision in them is about *roles* — who
approves, who accepts, who authored. §3.3 is silent on relatedness, so an arrangement can
satisfy every row and still fail §14.1's "independent enough to challenge" test. The
owner disclosed on 2026-10-18 that **Russell is a relative through the extended family
and Milton is his brother** (§2), so every row of every table above stays satisfied while
the functional test is a separate question they cannot reach. The Project Authority has
judged the reviewer relation non-material and has accepted the Gate 4 acceptance relation
under a compensating arrangement (§2). Both decisions are his; both are recorded with
their reasoning and with this pack's declined recommendations beside them. The tables are
not wrong — they measure role separation, which holds. §2 is where the rest is weighed,
and §9.8 is where the compensating terms are proposed.

**What the appointment fixes immediately:** §11 Q10's gap. An unavailable reviewer no
longer leaves lifting branch protection as the only route to a merge, which was the
pressure §4 created the moment the rules were set to bind everyone.

**What it does not fix, and must be written down before it is useful.** A deputy who may
approve anything, at any time, is not a control — it is a second unconditional approver,
and the project would then have two people who can each wave anything through rather than
one reviewer with a scope. The appointment needs a stated **trigger** (what counts as the
primary being unavailable, and who records it), a stated **scope** (whether the deputy
may approve everything the primary may, or a narrower set that excludes, say, changes to
`src/seal/core` or to the decision packs), and for the Gate 4 half, a stated **start
condition** — Gate 4 is an event the tracker records, so "from Gate 4" is checkable, but
only if someone says whether it means the gate decision or the readiness review that
precedes it. §9 carries those as recommendations; §11 Q4 and Q5 stay open until they are
stated.

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

**No evidence here speaks to independence.** Everything the probe measures — who
authored, who approved, who merged, how long a review had — is about roles and timing.
None of it can distinguish a review that could have refused from one that could not, and
with the relationships in §2 disclosed, that is the question a Class A reader asks first.
D01 cannot close that gap with evidence; only an appointment, or a judgement recorded with
its reasoning, can — §2 now carries one of each.

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
   arrangement. Converting practice into appointment introduces nobody new. Record both
   disclosed relationships in the same act (§10.4): Russell is a relative through the
   extended family, Milton is the owner's brother, both disclosed 2026-10-18. An
   appointment table that names all three without the relationships would be the one
   document in this repository that misleads by omission.
3. **State the review scope explicitly**: what the independent reviewer reviews for, what
   they may refuse, and what must not be merged without them. Fourteen approvals with no
   stated scope are the gap §3 names, and this is the cheapest part of D01 to close.
4. **State the review period and a revisit date**, so the appointment can lapse rather
   than fade.
5. ~~Record the absence of a deputy as a named, time-bound gap.~~ **Superseded
   2026-10-18**: the Project Authority stated the staged appointment in §5 — Milton as
   deputy independent reviewer now, acceptance authority from Gate 4 — so there is a
   deputy to appoint rather than a gap to record. Three things still have to be stated
   for it to function, and this pack proposes them rather than assuming them:
   **(a)** the deputy's trigger — suggested: the primary reviewer unavailable for two
   consecutive business days, recorded in the pull request by whoever invokes it, so an
   invocation leaves a trace instead of being inferred from who clicked approve;
   **(b)** the deputy's scope — suggested: the same scope as the primary, since a
   narrower one means the urgent change that needed a deputy is the one he may not
   approve; **(c)** what "from Gate 4" means for the acceptance half — the gate decision
   itself, or the readiness review preceding it. Still do **not** route any of this
   through §3.3's compensating-assurance clause: the arrangement needs no exception, and
   for Class A that clause escalates to an Executive Authority chaired by the same person
   who authored every change here.
6. ~~Configure branch protection on `main`.~~ **Done, 2026-10-18** — the
   shortest-lived recommendation in the pack, superseded within hours of being written.
   §4 records the configuration: one approving review, the four existing status checks,
   stale reviews dismissed, no force-push or deletion, and the rules binding the owner's
   admin account. What remains for D01 is the decision this created rather than solved:
   **who merges when the single reviewer is unavailable**, given that the honest options
   are waiting or lifting protection, and §9.5 is where that gap is recorded.
7. **Hand D11 one line item**: deputy-reviewer effort. The platform cost the first
   draft listed beside it was paid in disclosure instead of money (§4).
8. ~~Adopt a compensating arrangement for the Gate 4 acceptance authority.~~ **Adopted
   2026-10-18 — the terms are in force at §12.1 and reproduced there.** They are kept
   below as the recommendation they were, so the pack still shows what was proposed
   against what was adopted. §3.3 requires a named reviewer, the evidence to be checked
   and a time limit; the rest of these terms exist because the signature will be a
   related party's and the only available substitute for independence is after-the-fact
   checkability.

   | Term | Proposed |
   |---|---|
   | **Named acceptance authority** | Milton Kenny Adedeme (`MiltonBello15`), brother of the author, from Gate 4 |
   | **Evidence he must check before accepting** | the T01–T14 acceptance mapping; that every claim in the release pack is locatable, digest-bound, verified and same-revision (what `release.py` already refuses without); that no tracker item supporting the release reads Complete without a specific locatable reference; that CI was green on the exact accepted revision; and that an approving review from the independent reviewer exists for every change in the release |
   | **What he may refuse** | acceptance, on any unmet acceptance criterion, with the refusal recorded in the decision record and the tracker before any further work on that release |
   | **If the Project Authority disagrees with a refusal** | the override is recorded as an override, in the decision record, naming the criterion overridden and the reason. It does not escalate to anyone, because §3.4 puts the Executive Authority chair in the same person — so the compensating measure is publication of the disagreement, not its resolution |
   | **What must escalate past him** | anything with a legal or regulatory consequence (D09/H03: no autonomous regulatory filing, the duty determination is counsel's); any conflict beyond the disclosed family relation; and any matter §3.3 forbids a compensating arrangement from waiving — legal, security, privacy or financial controls |
   | **Time limit** | expires at the Gate 5 continuation decision or twelve months from adoption, whichever is earlier, and must be re-approved rather than rolled over |
   | **§3.3 Executive Authority approval** | recorded as a **self-approval**: the Executive Authority chair, the Project Authority, the sponsor, the project manager and the author are one person, and §12 must say so in those words rather than presenting the step as independent sign-off |
   | **Standing statement in the record** | independent assurance in §19.1's sense is absent for the acceptance control, and present for no control other than through the public visibility of the reviewer's work (§2) |

   Adopted unamended by the Project Authority on 2026-10-18 (§12.1). What the pack
   cannot do is let the arrangement exist as an intention: §3.3's clause is satisfied by
   recorded terms, and an unrecorded compensating arrangement is the same thing as none.

This is a recommendation from a decision pack. It is not a decision, and the Project
Authority may reject any part of it.

## 10. What must be verified before §12 is signed

1. Re-run `python tools/d01_review_separation_probe.py` and confirm the separation counts
   still read 14/14 or better, that no merge has landed without an approving review, and
   what section 2 now says about protection. The probe reads live GitHub state, so both
   a lapse in practice and a change in enforcement show up as changed lines.
2. Confirm directly with Russell Kenny that he accepts the independent reviewer
   appointment and, until Gate 4, the acceptance authority role, with their scope and
   period. Confirm separately with Milton that he accepts the deputy reviewer appointment
   now and the acceptance authority appointment from Gate 4 — he has been *invited to the
   repository*, which is consent to nothing, and at the time of writing the invitation
   itself is still unaccepted. §3's evidence is fourteen approvals, which is
   consent to review changes, not consent to hold an appointment. Appendix E.3's
   first-five-days list is a *proposed* assignment, and an unaccepted assignment leaves
   the task Blocked however complete this pack is.
3. Confirm the account-to-person attribution in §2 is still accurate, in writing, since
   the whole separation claim rests on it, nothing in GitHub can corroborate it, and the
   repository is now public (§4's closing paragraph).
4. **Record each named individual's relationship to the others, or state explicitly that
   there is none**, with the Project Authority's reasoning on whether any of them impairs
   the independence §14.1 and §19.1 require. **Done for the reviewer, 2026-10-18:**
   Russell Kenny Adedeme is a relative through the extended family and the Project
   Authority has judged that non-material, with his reasoning and this pack's declined
   recommendation both recorded (§2). **Decided for acceptance, the same day:** Milton
   Kenny Adedeme is the owner's brother, holds acceptance from Gate 4, and the Project
   Authority accepted that relation under a compensating arrangement rather than judging
   it immaterial (§2). **Terms adopted the same day** and in force at
   §12.1, including the Executive Authority step recorded as a self-approval.
   **Outstanding:** the appointees' own acceptance of their roles (§10.2), and the
   reviewer's scope and period, which the arrangement does not cover.
5. Check the D01 row and §15.3 against the approved `.docx` directly. The quotations here
   come from a stdlib text extraction of `Seal_Integrated_Baseline_v1_6.docx`; headings
   and paragraph text extract reliably, but a table-formatting difference would not be
   visible in it.
6. Confirm with D02's owner that Class A / Class 3 is still the operating assumption,
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
   account they review under is the company's own — and **what is each named
   individual's relationship to the others?** §14.1 and §19.1 set a functional test
   ("independent enough to challenge", "without pressure") that a role title does not
   answer; §2's closing block explains why the question is now unavoidable and §10.4
   requires the answer before signing. An explicit "no relationship" is a complete
   answer; silence is not. **Answered 2026-10-18: Russell is a relative through the
   extended family, judged non-material by the Project Authority and continuing as
   reviewer; Milton is the owner's brother. The acceptance row is decided the same
   day: Milton holds it from Gate 4 under a compensating arrangement, accepted rather
   than judged immaterial, with terms adopted unamended and in force at §12.1. **This
   question is closed.** What it leaves behind is not a question but a dependency: the
   arrangement expires, and §12.1's expiry date is the next time this reasoning has to
   be done again.**
3. Is the reviewer and the acceptance authority being the same person accepted for a
   Class A / Class 3 project, given §3.3 permits it and §5's second point records
   what it concentrates? **Answered 2026-10-18: accepted until Gate 4, then separated —
   Milton takes acceptance from Gate 4 and Russell keeps change-level review (§5).**
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
    project's only route to merging in that situation. **Answered 2026-10-18: Milton
    (`MiltonBello15`) is deputy independent reviewer, effective now, and acceptance
    authority from Gate 4 (§5).** What remains open is not who, but on what terms — the
    deputy's trigger, his scope, and what "from Gate 4" means — which §9.5 proposes and
    §11 Q4/Q5 still need stated. Until the trigger is recorded, an invocation of the
    deputy is indistinguishable from a second unconditional approver.

## 12. Decision record — unsigned

### 12.1 Compensating arrangement for the Gate 4 acceptance authority — adopted

**Adopted 2026-10-18 by Freston Kenny Adedeme as Project Authority, on his instruction
recorded in that day's working session, under PM Framework v1.3 §3.3's
compensating-assurance clause.** The terms are reproduced here in force rather than
referenced, so the arrangement can be read without reconstructing it from a
recommendation.

| Term | Adopted |
|---|---|
| **Named acceptance authority** | Milton Kenny Adedeme (`MiltonBello15`), brother of the author, from Gate 4 |
| **Evidence he must check before accepting** | the T01–T14 acceptance mapping; that every claim in the release pack is locatable, digest-bound, verified and same-revision; that no tracker item supporting the release reads Complete without a specific locatable reference; that CI was green on the exact accepted revision; and that an approving review from the independent reviewer exists for every change in the release |
| **What he may refuse** | acceptance, on any unmet acceptance criterion, with the refusal recorded in the decision record and the tracker before any further work on that release |
| **If the Project Authority disagrees with a refusal** | the override is recorded as an override, naming the criterion overridden and the reason. It escalates to nobody, because §3.4 puts the Executive Authority chair in the same person; the compensating measure is publication of the disagreement, not its resolution |
| **What must escalate past him** | anything with a legal or regulatory consequence (D09/H03 — no autonomous regulatory filing; the duty determination is counsel's); any conflict beyond the disclosed family relation; and anything §3.3 forbids a compensating arrangement from waiving — legal, security, privacy or financial controls |
| **Expiry** | **2027-10-18**, or the Gate 5 continuation decision, whichever is earlier. Re-approval required; it does not roll over |
| **§3.3 Executive Authority approval** | **Recorded as a self-approval.** The Executive Authority chair, Project Authority, sponsor, project manager and author of every change are one person (§3.4). This step adds no independent scrutiny and is recorded so that nobody reads it as though it did |
| **Standing statement** | Independent assurance in §19.1's sense is absent for the acceptance control. It is absent for every other control too, except insofar as the independent reviewer's work is publicly visible and therefore auditable after the fact (§2) |

**What adopting this does and does not settle.** It satisfies §3.3's requirement that a
compensating arrangement exist in recorded terms with a named reviewer, stated evidence
and a time limit — the thing that, left as an intention, would have been worth nothing.
It does not complete D01: the table below still has no names against its rows, no review
scope, no review period and no deputy trigger, and neither appointee has accepted their
appointment (§10.2). And it does not convert a self-approval into an approval.

**On how this adoption is recorded.** The text above was written by the drafter from the
Project Authority's instruction, in the same session and on the same day. It becomes part
of the project record the way every other change here does — reviewed by the independent
reviewer and merged under branch protection that binds administrators (§4). That merge is
the signature ceremony available to this project, and it is the first use of the control
this pack describes. No agent, document or tool in this repository can sign on anyone's
behalf, and this section is a transcription of a decision, not a substitute for the
person making it.

### 12.2 The appointment record

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

**Positions the Project Authority has stated but not signed**, as of 2026-10-18, each
recorded where the question it answers lives:

| Position | Stated | Where |
|---|---|---|
| The owner holds the Project Authority for this project | "Sure I'm the one", directing publication | §4, §11 Q1 |
| The repository is public, and protection binds administrators | Directed and configured the same day | §4 |
| Milton (`MiltonBello15`) is deputy independent reviewer, effective now | Stated | §5, §11 Q10 |
| Milton is acceptance authority from Gate 4 | Stated | §5, §11 Q3 |
| Milton Kenny Adedeme is the owner's brother; Russell Kenny Adedeme is a relative through the extended family | Disclosed in full, on request, the same day the pack asked | §2, §10.4, §11 Q2 |
| Russell's relation is not material to his independence as reviewer, and no unrelated person is to be engaged in addition | Judged as Project Authority, this pack's §9.8 recommendation declined on the record | §2, §9.8 |
| Milton takes acceptance authority at Gate 4 as stated, under a compensating arrangement — the relation accepted, not judged immaterial | Decided as Project Authority; §2's option 1 (this pack's recommendation) and option 3 both declined | §2, §9.8 |

Those are positions on record, which the project may act on and which this pack has
acted on in §5, §9 and §11. **They are not the table above.** The table needs names
against every row, a scope, a period, and a signature, and the three of those four that
are still missing are missing because nobody has stated them, not because nobody has
written them down.

**The table itself is deliberately empty.** D01 is recorded as "Unconfirmed / Blocked" in
Appendix E.3 and nothing in this repository can change that. An appointment is a named
human authority's act; no document, probe or tooling in this project may record one on
anyone's behalf, and that applies with particular force to a decision whose entire
subject is who is allowed to decide.

## 13. Provenance and limits

Drafted 2026-10-18 by Claude Opus 5 at the owner's instruction. Quotations come from
`Seal_Integrated_Baseline_v1_6.docx` (Appendix E.3 rows D01, D02 and D11, and §15.3) read
through a stdlib text extraction; the `.docx` file remains authoritative.

The separation provisions quoted in §1 come from the KenAddme IT Links Project Management
Framework v1.3 §3.3 and §3.4, the independence tests in §2 and §5 from its §14.1 and
§19.1, the escalation trigger in §2 from its §12.2, and the assurance-funding line in §8 from the Software
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

**One correction on the record.** This pack first recorded Russell Kenny Adedeme as the
owner's brother. That was the drafter's error — the owner had stated the relation existed,
not its degree — and he corrected it the same day: extended family, not a sibling. The
correction is kept visible rather than silently applied, because the pack's own argument
turns on the degree: §14.1's test is about pressure, the pressure on a sibling and on an
extended-family relative are not the same, and a record that had quietly swapped one for
the other would have been making the drafter's mistake look like the Project Authority's
statement.

**What this pack is not.** It is not an appointment, not a separation-of-duties
attestation, and not evidence that the review practice it measures is adequate. It
measures one control (author never approves) and reports that the other three elements
D01 requires — names, scope, period — do not exist in any form. The attribution of
accounts to people in §2 is the owner's statement, recorded as such; it is the single
load-bearing fact in the pack that no tool here can verify, and §10.3 exists because of
it.
