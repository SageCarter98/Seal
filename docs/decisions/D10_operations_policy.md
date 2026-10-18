# D10 — operations policy: decision pack

**Decision pack. Nothing here is a decision, and nothing here approves a priority
policy.** D10 belongs to the security lead and the service owner. This pack prepares
its six required elements, reports what the decision core already runs as a *candidate*
policy, and reports four numbers and three override gaps where the built behaviour and
the documented proposal are not the same thing. Every measurement below comes from
`tools/d10_priority_probe.py` running the real `priority.py`.

| | |
|---|---|
| Decision | Set operations policy (Integrated Baseline v1.6, Appendix E.3, D10) |
| Accountable role | Security lead and service owner |
| Required evidence | "Approved priority decision tree, validation/remediation deadlines, threat-data freshness, incident contacts, maintenance window and escalation paths" |
| Blocks | W01 directly (its stated dependencies are "L04, D10"), and through W01 the whole W02–W05 chain; H03 jointly with D09 |
| Depends on | D04 for the threat-data freshness half that is not EPSS — §4; D09 for the contacts and clocks that carry a legal consequence — §8 |
| Drafted | 2026-10-18, by Claude Opus 5 at the owner's instruction |
| Status | **Unconfirmed / Blocked. §12's decision record is unsigned.** |

## 1. The decision as the documents state it

**The policy is already written down, and that is exactly the risk.** Baseline U06 is
unusually direct about it:

> "the candidate ordered tree, EPSS 0.10 threshold, 48-hour freshness and
> acknowledgment targets remain pending D10 approval, **not silent operating
> defaults**."

So D10 is not a blank page. Appendix D.6 states a complete candidate policy, the
decision core implements it, and 46 tests exercise it. What D10 decides is whether that
candidate becomes the policy — and the failure mode the baseline names is that nobody
ever decides, the numbers keep working, and six months later the thresholds are policy
because they ran rather than because anyone approved them.

**Five of the six required elements are not the tree.** The evidence line reads
"Approved priority decision tree, validation/remediation deadlines, threat-data
freshness, incident contacts, maintenance window and escalation paths". The tree is the
part with code behind it. The other five are mostly not code at all, and §4 reports
where each one actually stands.

**Two named roles, jointly.** Appendix E.3 names "Security lead and service owner", and
its first-five-days list assigns preparation to the service owner. That list ends with
its own caveat — "These assignments are proposed and remain unconfirmed until accepted
by named individuals" — so the preparer is not yet established either, and neither role
may sign for the other.

## 2. What is already built, and what it settles

`src/seal/core/priority.py` implements the Appendix D.6 candidate in full. Probe
section 1 runs every branch in the documented order and prints the outcome:

| Condition | Outcome | Appendix D.6 row |
|---|---|---|
| Known exploitation + exposure or serious impact | Act | row 1 |
| Known exploitation, serious impact, severity ≥9, or exposed severity ≥7 | Attend | row 2 |
| Exposed and fresh EPSS ≥0.10 | Attend | row 3 |
| Severity ≥4 or exposed | Track* | row 4 |
| Otherwise, on complete context | Track | row 5 |
| Any dimension unknown | Triage | the "requires triage" rule |

Three things that settles, and they are worth stating because they are the parts D10
does **not** need to re-litigate:

- **Unknown is not zero.** Each of the four dimensions is tri-state. Probe section 2
  takes a finding that would otherwise land on Track — the least urgent branch — and
  blanks one dimension at a time: every row routes to Triage and names which dimension
  was missing. Stale EPSS and future-dated EPSS both read `unknown_or_stale`, never
  `0.0`.
- **The source severity is never overwritten.** Source and environmental readings are
  two instances of a frozen `Severity`, so W01's first acceptance line is structurally
  true rather than conventionally true. Probe section 1 shows a source 4.0 still
  reading 4.0 after an environmental 9.5 drove the outcome to Attend.
- **Every outcome is version-stamped.** `POLICY_VERSION = "seal-priority-proposal-v1"`
  rides on every `Priority`. The string says "proposal" in it, which is the honest
  state, and when D10 approves something the string changes and every finding
  prioritised under the candidate stays identifiable for recalculation. This is the
  single most useful property the core has for D10's purposes.

One interface obligation falls out of the same probe section. `Priority` carries **one**
severity field, holding the effective reading. The source reading survives in the input
object, but a display cannot recover it from the outcome alone — so W01's "separate
source and environment-adjusted CVSS fields" and U13's "show severity … together" are
obligations on the W01/W04 surface, not something `priority.py` discharges by itself.
Worth recording in W01's design rather than discovering in W04.

## 3. Four numbers that are the code's and not the baseline's

All four are defensible. None of them is approved, and three of them are not in
Appendix D.6 at all.

**`URGENT_VALIDATION_SEVERITY = 7.0`.** Appendix D.6 says "Low-confidence High/Critical
findings enter urgent validation immediately" — a severity *band*, not a number. 7.0 is
the CVSS v4 floor of High, so the translation is the obvious one; but it is a
translation, and it silently assumes the band comes from CVSS v4 rather than from
whichever version a given adapter reports. D04 has not selected the adapter.

**Calendar days, not business days.** Appendix D.6 proposes "one business day" for
Attend and "five business days" for Track*. `ACKNOWLEDGEMENT_TARGETS` holds
`timedelta(days=1)` and `timedelta(days=5)`. A Track* finding raised on a Friday comes
due the following Wednesday rather than the Friday after — five calendar days where the
proposal gives seven. An Attend finding raised on a Friday comes due Saturday rather
than Monday. The difference is not a rounding error, and it cannot be fixed inside
`priority.py`, because "business day" needs a calendar, a timezone and a holiday set
that the pure core has no way to hold. Either D10 approves calendar days as the policy,
or W01 owns a working-time calculation and the targets table moves behind it.

**Triage's four hours.** Appendix D.6 proposes targets for Act, Attend, Track* and
Track only. The code gives Triage the same four hours as Act. Defensible — an
unclassifiable finding should not wait longer than an urgent one — but it is an
addition, and the whole point of U06's "not silent operating defaults" sentence is that
additions get ratified rather than inherited.

**Urgent validation is a flag, not a branch.** Probe section 2's last block shows a
severity 8.0 Low-confidence finding landing on **Track\*** with `urgent_validation=True`
beside it. Appendix D.6 says such findings "enter urgent validation immediately". Whether
a Track\* outcome carrying a flag *is* entering urgent validation immediately depends
entirely on what W02's queue does with the flag — the core cannot answer it. D10 should
state the intent so W01 and W02 implement the same reading.

## 4. The six required elements, one at a time

Probe section 4 prints this list from the live module rather than from this document.

**1. Approved priority decision tree — EXPRESSED, unapproved.** §2 above. The code is
ahead of the decision, which is the normal and intended state for Phase 0 design work,
and becomes a governance problem only if it stays that way past W01.

**2. Validation/remediation deadlines — PARTIAL, and the two halves are in very
different states.** Validation exists: urgent validation raises immediately, and every
action carries an acknowledgement target and a derived `acknowledgement_due`.
Remediation deadlines do not exist anywhere in the core. Appendix D.6 is explicit that
they are a separate thing and that they are a prerequisite: the plan "must select
remediation deadlines appropriate to asset impact and the approved frameworks **before
enabling automatic overdue escalation**." Nothing can escalate on overdue today, so
nothing is being violated — but this is the element with the most work left in it, and
"appropriate to asset impact" means it cannot be answered without an asset-impact
classification that no document in this repository holds.

**3. Threat-data freshness — PARTIAL, bounded on one input of two.**
`EPSS_FRESHNESS = 48h` bounds the EPSS reading, and the future-dated case is handled.
A scanner advisory database's age has no equivalent limit. That is not an oversight
here: D04 has not selected a scanner, and `D04_pinning_record.md` already names the
vulnerability-DB timestamp as the thing D10's freshness policy will be measured
against. So this element is *half* decidable now — the EPSS half — and the other half
is downstream of D04. D04's pack also flags that a Semgrep-style rule revision is not a
dated advisory feed, so a freshness measure written for one option may not transfer to
the other.

**4. Incident contacts — PARTIAL, a container with nothing in it.**
`authorization.emergency_contacts` and `incident.target_owner_contacts` exist, are
typed, and are routed from: `notification_plan` builds the internal list as the named
coordinator followed by the target-owner contacts on the authorization and infers
nobody, while `may_contact_external` denies every external party without a named
delegated authority — and Seal prepares external notifications rather than sending
them. The
fields are empty, because there is no authorization and no target. A field is not a
policy. What D10 owes here is the *rule* — who must be named before an authorization is
valid, who is reachable out of hours, and what happens when a named contact does not
answer — not a list of names, which belongs to each authorization.

**5. Maintenance window — ABSENT, and `priority.py` is the wrong home for it.** The
baseline's only mention outside D10's own evidence line is in the §18 risk table, among
the controls for "Service disruption — target slowdown or outage", beside passive
defaults, rate limits, health checks and emergency stop. It is a constraint on *when Seal may touch a target*, not on how a
finding is ranked. The nearest existing structure is `authorization.starts/expires`,
which is a single validity window for one authorization and raises `OUTSIDE_WINDOW` —
not a recurring window, and not a per-target blackout. So this element should be
designed with the authorization profile and the D06 egress boundary, and D10 should
record that placement rather than leaving it to land wherever W01 happens to put it.

**6. Escalation paths — PARTIAL, flags without routes.** Three real escalation signals
exist: `OVERRIDE_EXPIRED` comes back with the recalculated outcome so an expired
override escalates visibly rather than silently (Appendix D.6: "Expired overrides
trigger recalculation and visible escalation"); `lifecycle.expire_disposition` returns
`requires_reassessment=True`; `incident.ReportingClock.requires_escalation` is True
whenever a legal duty is undetermined. Every one of them is a flag. None has a
recipient, a route or a clock — and the clock is the part that cannot be written here,
because an escalation path with no time limit escalates nothing.

## 5. Three gaps between what an override records and what is checked

Appendix D.6 requires every override to retain "old/new outcome, policy version, named
reviewer, reason, evidence, creation time and expiry". `Override` retains every field in
that list. Two of them — the old outcome and the policy version — are never read by
`apply_override`; and the field that *is* read against the Attend floor is ranked so
that one downgrade passes. Probe section 5 demonstrates all three.

**(a) The floor stops at Track, not at Triage.** `_RANK` gives Triage and Attend the
same rank, so `apply_override` does not treat Triage as below the Attend floor:

```
Act -> Triage, no exception   -> Triage   PERMIT
Act -> Track,  no exception   -> Act      DENY ('PRIORITY_FLOOR_EXCEPTION_REQUIRED',)
```

A known-exploitation finding can be moved to "we do not know" with no approved
exception, and Triage's four-hour target then applies — so it is not a parking space,
and the equal rank is arguably correct. But it is reachable, undocumented, and the one
route that gets a finding off Act without the exception the baseline requires. D10
should say whether Triage sits below the floor or beside it. `tests/test_priority.py`
covers the Track and Track\* downgrades and not this one.

**(b) An override's `policy_version` is recorded and not compared.** An override
authored under a retired policy still applies, and the resulting outcome is stamped
with the *current* version:

```
override.policy_version -> 'seal-priority-retired-v0'
outcome.policy_version  -> 'seal-priority-proposal-v1'   PERMIT
```

This is the one that matters most for D10 specifically, because version-stamping is the
mechanism D10's own approval depends on. The day the candidate becomes
`seal-priority-approved-v1`, every override reasoned under the proposal keeps applying
and keeps looking current. Expiry limits the damage — an override must expire — but
expiry is time-based and a policy change is not.

**(c) An override's `computed` field — the "old outcome" — is recorded and not compared
either.** An override claiming the computed action was Track still applies to a finding
computed as Act. The recorded old outcome is therefore an assertion by whoever built
the override, not evidence about what the policy actually produced.

**None of the three is a defect to fix before D10 decides.** No code here contradicts
its own stated intent: the floor is implemented, the fields are retained, and nothing
claims the two unread fields are checked. What each one exposes is an unanswered policy
question, and each question belongs to the security lead rather than to whoever next
edits `apply_override` — whether Triage is below the floor, what happens to an override
when its policy version is retired, and whether a recorded old outcome must be verified
rather than trusted. Once D10 answers them the code changes are small, and the
assertions belong in W01's required test set, which U06 says Appendix D records.

## 6. What D10's approval would let W01 test

W01's stated dependencies are "L04, D10", and its acceptance evidence is four lines.
Three are already demonstrable against the candidate; the fourth has the §5(a) caveat.

| W01 acceptance line | Where it stands | Evidence |
|---|---|---|
| "Source scores/evidence never overwritten" | Demonstrable | Probe §1; `test_priority.py::TestSeparateDimensions` |
| "Missing signals are unknown, not zero" | Demonstrable | Probe §2; `TestIncompleteContext`, `TestEpss` |
| "Severe low-confidence findings enter urgent validation" | Demonstrable as a flag; the *entering* is W02's | Probe §2; §3 above |
| "Priority floor exception is explicit" | Demonstrable for Track and Track\*; **not** for Triage | Probe §3, §5(a) |

So D10's approval does not unblock W01 by supplying something W01 is missing. It
unblocks W01 by converting numbers that currently run as a proposal into numbers W01
may write tests against — which is the difference between a test that asserts a policy
and a test that freezes an accident.

## 7. What D10 can decide now, and what it cannot

**Decidable now, with no external dependency:** the tree's shape and order, the 0.10
EPSS threshold, the 48-hour EPSS freshness limit, the four acknowledgement targets,
calendar-versus-business days, Triage's target, whether Triage sits below the floor, the
two unchecked override fields, and where the maintenance window is designed. That is
most of the policy, and all of it is reviewable from this repository plus Appendix D.6.

**Not decidable now:**

- **Remediation deadlines**, which Appendix D.6 ties to "asset impact and the approved
  frameworks". No asset-impact classification exists for any target, because no target
  exists.
- **The non-EPSS half of threat-data freshness**, which waits on D04 — §5 of
  `D04_scanner_adapter_selection.md` and the vulnerability-DB timestamp row in
  `D04_pinning_record.md`.
- **Named incident contacts**, which belong to an authorization that does not exist.
  The *rule* about naming them is decidable; the names are not.

A partial D10 that approves the first list and records the second as explicitly
deferred would unblock W01 and H03's priority dependency. A D10 that waits for all six
elements waits on D04, which waits on D09, which waits on counsel nobody has engaged.

## 8. The D09 and H03 dependency, stated plainly

H03's dependencies are "F06–F08, D09–D10", and its acceptance evidence requires a
"legal/CERT decision clock recorded; no autonomous regulatory filing assumed". Two of
D10's elements touch that clock: incident contacts and escalation paths.

`incident.py` already refuses to resolve it the wrong way. `ReportingClock` carries the
v1.3 twenty-four-hour consideration period forward as a *legal-review requirement*,
marks `deadline_established_by_seal: False` and `breach_asserted: False`, and sets
`requires_escalation` whenever the duty is undetermined. That is the correct posture and
D10 should not disturb it: D10 may set Seal's internal escalation clock, and it may not
convert that into a regulatory deadline, because the determination is counsel's under
D09 and no counsel has been engaged.

## 9. Recommendation (a proposal, not a decision)

Approve the candidate policy as written, with four amendments and two deferrals,
recorded as `seal-priority-approved-v1`:

1. **Approve** the tree, the 0.10 threshold and the 48-hour EPSS freshness limit as
   stated in Appendix D.6. They are implemented, tested, and the probe shows every
   branch firing in the documented order.
2. **Amend** the acknowledgement targets to say explicitly whether they are calendar or
   business days. If business, W01 owns the working-time calculation and the core's
   table becomes the input to it rather than the answer.
3. **Amend** the policy to state Triage's target and Triage's position relative to the
   Attend floor, rather than inheriting both from the code.
4. **Amend** the override rules to require that `policy_version` match the active policy
   and that `computed` match the recomputed outcome, with the reason codes split so a
   missing evidence reference does not report as a missing reviewer.
5. **Defer, with a recorded reason and a review date**: remediation deadlines (pending
   an asset-impact classification) and the non-EPSS freshness limit (pending D04).
6. **Record** that the maintenance window is designed with the authorization profile and
   the D06 egress boundary, not with the priority tree.

This is a recommendation from a decision pack. It is not a decision, and the security
lead and service owner may reject any part of it.

## 10. What must be verified before §12 is signed

1. Re-run `python tools/d10_priority_probe.py` against the then-current `priority.py`
   and confirm every printed outcome still matches Appendix D.6. The probe reads the
   live module, so a drifted threshold shows up as a changed line rather than a passing
   test.
2. Check the four numbers in §3 against the approved `.docx` Appendix D.6 directly. The
   quotations here come from a stdlib text extraction of
   `Seal_Integrated_Baseline_v1_6.docx`; headings and paragraph text extract reliably,
   but a table-formatting difference would not be visible in it.
3. Confirm that the three §5 controls are still unenforced at signing time, and that
   nothing has been changed to enforce them without a recorded decision.
4. Confirm with D04's owner whether a scanner has been selected, since the freshness
   deferral in §9.5 lapses the moment one is.
5. Confirm the two accountable roles have accepted the assignment. Appendix E.3's
   first-five-days list is a *proposed* assignment, and an unaccepted assignment leaves
   the task Blocked regardless of how complete this pack is.

## 11. Open questions for the security lead and service owner

1. Calendar or business days for Attend and Track\*?
2. Is Triage below the Attend floor, or beside it?
3. Does Triage keep four hours, or get its own target?
4. Must an override's `policy_version` match the active policy — and if it does not,
   does the override lapse, or does it survive with an escalation?
5. Must an override's recorded old outcome be verified against a recomputation?
6. Does a Track\* outcome carrying `urgent_validation=True` satisfy "enter urgent
   validation immediately", or must the tree itself route such findings differently?
7. Which asset-impact classification will remediation deadlines be written against, and
   who owns producing it?
8. Does the EPSS 48-hour limit also govern the scanner advisory DB once D04 selects one,
   or does that input get its own limit?
9. Who must be named as an incident contact before an authorization is valid, and what
   happens when a named contact does not answer?
10. Where does the maintenance window live — authorization profile, egress boundary, or
    both — and who owns it?

## 12. Decision record — unsigned

| Field | Value |
|---|---|
| Decision | Set operations policy (D10) |
| Policy version approved | *(unset — the running code is `seal-priority-proposal-v1`)* |
| Security lead | *(unsigned)* |
| Service owner | *(unsigned)* |
| Date | *(unset)* |
| Elements approved | *(unset)* |
| Elements deferred, with review date | *(unset)* |
| Amendments adopted | *(unset)* |

**This table is deliberately empty.** D10 is recorded as "Unconfirmed / Blocked" in
Appendix E.3 and nothing in this repository can change that. A gate decision is a named
human authority's act; no document, probe or tooling in this project may record one on
anyone's behalf.

## 13. Provenance and limits

Drafted 2026-10-18 by Claude Opus 5 at the owner's instruction. Quotations come from
`Seal_Integrated_Baseline_v1_6.docx` (Appendix D.6, Appendix E.3, Appendix E.7 row W01,
Appendix E.8 row H03, and the risk table at §18) and
`Seal_Engineering_Specification_v1_6.docx` §6 — whose prioritization text is identical
to Appendix D.6 — read through a stdlib text extraction; the `.docx` files remain
authoritative.

Every measurement in §2 to §6 comes from `tools/d10_priority_probe.py` run against
`src/seal/core/priority.py` at commit time, and the probe asserts nothing — it prints
what the policy does so a person can judge it.

**What this pack is not.** It is not an approved priority policy, not an operations
policy, and not evidence that the candidate thresholds are correct. The thresholds are a
security judgement about a target estate that does not exist yet: no scanner has been
selected, no authorization has been issued, no finding has ever been prioritised from
real scanner output, and the repository has no network capability to produce one (see
`docs/BOUNDARY.md`). The probe can show what the code decides. It cannot show that
deciding so is right, and §12 stays unsigned until the two named roles say it is.
