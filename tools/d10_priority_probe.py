"""D10 probe -- is the candidate priority policy operating as a proposal or as a default?

`docs/decisions/D10_operations_policy.md` sections 3 to 6 turn on four things that are
checkable today. The ordered tree in baseline Appendix D.6 is implemented and every
branch fires. Unknown, stale and future-dated signals route to Triage rather than to
the least urgent branch, which is what that section requires of them. The Attend floor
holds along every downgrade path, the move to Triage included, and the two override
fields that were once retained-but-unread are now compared; section 5 prints all three.
And of D10's six required elements, one is expressed, four are partial and one is
absent; section 4 prints which is which rather than asserting it.

This runs the real `priority.py` decisions and prints what happens. Like its D04, D06,
D07 and D08 counterparts it asserts nothing and emits no pass/fail: it establishes what
the policy currently does, not that the policy is right, which is the security lead's
and service owner's judgement.

    python tools/d10_priority_probe.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from seal.core.priority import (
    ACKNOWLEDGEMENT_TARGETS,
    EPSS_ACT_THRESHOLD,
    EPSS_FRESHNESS,
    POLICY_VERSION,
    PRIORITY_FLOOR,
    URGENT_VALIDATION_SEVERITY,
    Action,
    Confidence,
    Context,
    Epss,
    Override,
    Severity,
    apply_override,
    prioritize,
)

T0 = datetime(2026, 10, 15, 9, 0, tzinfo=timezone.utc)
CVSS_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def run(sev, *, exposed, serious, exploited, conf=Confidence.HIGH, epss=None):
    return prioritize(
        source_severity=Severity(vector=CVSS_VECTOR, score=sev) if sev is not None else None,
        context=Context(exposed=exposed, serious_impact=serious, known_exploitation=exploited),
        confidence=conf,
        now=T0,
        epss=epss,
    )


print("=" * 78)
print("1. Every branch of the candidate tree, in the order Appendix D.6 states it")
print("=" * 78)
print(f"   POLICY_VERSION = {POLICY_VERSION!r}")
print()

BRANCHES = [
    ("known exploitation + exposure", 5.0, dict(exposed=True, serious=False, exploited=True)),
    ("known exploitation + serious impact", 5.0,
     dict(exposed=False, serious=True, exploited=True)),
    ("known exploitation alone", 2.0, dict(exposed=False, serious=False, exploited=True)),
    ("serious impact alone", 2.0, dict(exposed=False, serious=True, exploited=False)),
    ("severity 9.1, not exposed", 9.1, dict(exposed=False, serious=False, exploited=False)),
    ("severity 7.2, exposed", 7.2, dict(exposed=True, serious=False, exploited=False)),
    ("severity 7.2, not exposed", 7.2, dict(exposed=False, serious=False, exploited=False)),
    ("severity 4.0, not exposed", 4.0, dict(exposed=False, serious=False, exploited=False)),
    ("severity 1.0, exposed", 1.0, dict(exposed=True, serious=False, exploited=False)),
    ("severity 1.0, nothing else", 1.0, dict(exposed=False, serious=False, exploited=False)),
]
for label, sev, ctx in BRANCHES:
    p = run(sev, **ctx)
    print(f"  {label:44} -> {p.action.value:7}  {p.reason}")

print()
print(f"  The EPSS branch, threshold {EPSS_ACT_THRESHOLD}, freshness {EPSS_FRESHNESS}:")
for label, prob, age_hours, exposed in [
    ("exposed, EPSS 0.11 observed 1h ago", 0.11, 1, True),
    ("exposed, EPSS 0.09 observed 1h ago", 0.09, 1, True),
    ("exposed, EPSS 0.11 observed 49h ago", 0.11, 49, True),
    ("not exposed, EPSS 0.99 observed 1h ago", 0.99, 1, False),
]:
    e = Epss(probability=prob, percentile=prob, observed_at=T0 - timedelta(hours=age_hours))
    p = run(3.0, exposed=exposed, serious=False, exploited=False, epss=e)
    print(f"  {label:44} -> {p.action.value:7}  epss={p.epss_status}")

print()
print("  The environmental reading decides; the source reading is untouched.")
print("  W01's first acceptance line is \"source scores/evidence never")
print("  overwritten\":")
source = Severity(vector=CVSS_VECTOR, score=4.0)
adjusted = prioritize(
    source_severity=source,
    environmental_severity=Severity(vector=CVSS_VECTOR, score=9.5),
    context=Context(exposed=False, serious_impact=False, known_exploitation=False),
    confidence=Confidence.HIGH,
    now=T0,
)
print(f"    source.score after the call    -> {source.score}")
print(f"    outcome.action                 -> {adjusted.action.value}")
print(f"    outcome.severity_score         -> {adjusted.severity_score}")
print("    Priority carries one severity field, holding the effective reading.")
print("    The source reading survives because Severity is frozen and the two")
print("    are separate instances -- but a display cannot recover it from the")
print("    outcome alone, so W01's \"separate source and environment-adjusted")
print("    fields\" is an interface obligation on W01/W04, not something")
print("    priority.py can discharge by itself.")

print()
print("=" * 78)
print("2. Weak signals must not reach the least urgent branch")
print("=" * 78)
print("   Appendix D.6: \"Unknown exposure, impact or severity requires triage; it")
print("   must not default to the least urgent branch.\" Each row below is a")
print("   low-severity finding that would otherwise land on Track.")
print()

for label, sev, ctx in [
    ("everything known, genuinely low", 1.0,
     dict(exposed=False, serious=False, exploited=False)),
    ("exposure unknown", 1.0, dict(exposed=None, serious=False, exploited=False)),
    ("impact unknown", 1.0, dict(exposed=False, serious=None, exploited=False)),
    ("exploitation unknown", 1.0, dict(exposed=False, serious=False, exploited=None)),
    ("severity unknown", None, dict(exposed=False, serious=False, exploited=False)),
    ("nothing known at all", None, dict(exposed=None, serious=None, exploited=None)),
]:
    p = run(sev, **ctx)
    detail = f"unknown={p.unknown_dimensions}" if p.unknown_dimensions else ""
    print(f"  {label:44} -> {p.action.value:7}  {detail}")

print()
print("  A future-dated EPSS reading, which baseline U06 names as an adversarial")
print("  case alongside the missing and stale ones:")
future = Epss(probability=0.99, percentile=0.99, observed_at=T0 + timedelta(hours=6))
p = run(3.0, exposed=True, serious=False, exploited=False, epss=future)
print(f"  {'EPSS 0.99 dated six hours in the future':44} -> {p.action.value:7}  "
      f"epss={p.epss_status}")

print()
print(f"  Low confidence at or above severity {URGENT_VALIDATION_SEVERITY} raises urgent")
print("  validation. Note it is a flag beside the outcome, not a branch within it:")
for label, sev, conf in [
    ("severity 8.0, Low confidence", 8.0, Confidence.LOW),
    ("severity 8.0, High confidence", 8.0, Confidence.HIGH),
    ("severity 6.9, Low confidence", 6.9, Confidence.LOW),
    ("severity 3.0, Low confidence", 3.0, Confidence.LOW),
]:
    p = run(sev, exposed=False, serious=False, exploited=False, conf=conf)
    print(f"  {label:44} -> {p.action.value:7}  urgent_validation={p.urgent_validation}")

print()
print("=" * 78)
print("3. The Attend floor under override")
print("=" * 78)
print(f"   PRIORITY_FLOOR = {PRIORITY_FLOOR.value}. Appendix D.6: known exploitation")
print("   or serious impact \"cannot fall below Attend without an approved")
print("   exception\".")
print()

CTX = Context(exposed=True, serious_impact=False, known_exploitation=True)
computed = prioritize(
    source_severity=Severity(vector=CVSS_VECTOR, score=8.0),
    context=CTX,
    confidence=Confidence.HIGH,
    now=T0,
)


def override(to, **extra):
    base = dict(
        override_id="O-1",
        finding_id="F-1",
        computed=computed.action,
        override_to=to,
        policy_version=POLICY_VERSION,
        reviewer="sec.lead",
        reason="business context",
        evidence_reference="ticket-1",
        created_at=T0,
        expires_at=T0 + timedelta(days=30),
    )
    base.update(extra)
    return Override(**base)


def show(label, ov, *, now=T0):
    result, decision = apply_override(computed, ov, CTX, now=now)
    tag = "PERMIT" if decision.allowed else "DENY  " + str(decision.reasons)
    print(f"  {label:44} -> {result.action.value:7}  {tag}")


for label, ov in [
    ("downgrade Act -> Track, no exception", override(Action.TRACK)),
    ("downgrade Act -> Track, exception approved",
     override(Action.TRACK, exception_approved_by="ciso")),
    ("downgrade Act -> Attend (at the floor)", override(Action.ATTEND)),
    ("override with no reviewer", override(Action.ATTEND, reviewer="")),
    ("override with no reason", override(Action.ATTEND, reason="")),
    ("override with no evidence", override(Action.ATTEND, evidence_reference="")),
    ("override that expired yesterday",
     override(Action.ATTEND, expires_at=T0 - timedelta(days=1))),
]:
    show(label, ov)

print()
print("  Each missing field now names itself -- DISPOSITION_REVIEWER_REQUIRED,")
print("  OVERRIDE_REASON_REQUIRED, OVERRIDE_EVIDENCE_REQUIRED -- so the denial")
print("  tells the reviewer which of the three to supply.")

print()
print("=" * 78)
print("4. Which of D10's six required elements the core can already express")
print("=" * 78)
print("   Appendix E.3 requires: \"Approved priority decision tree,")
print("   validation/remediation deadlines, threat-data freshness, incident")
print("   contacts, maintenance window and escalation paths\".")
print()

print("  Acknowledgement targets ARE modelled, as a per-action table and a")
print("  derived due time on every Priority:")
for action in Action:
    target = ACKNOWLEDGEMENT_TARGETS[action]
    shown = "next planned review" if target is None else str(target)
    print(f"    {action.value:10} -> {shown}")
print()
sample = prioritize(
    source_severity=Severity(vector=CVSS_VECTOR, score=9.5),
    context=Context(exposed=True, serious_impact=True, known_exploitation=True),
    confidence=Confidence.HIGH,
    now=T0,
)
print(f"    an Act finding evaluated at {T0.isoformat()}")
print(f"    acknowledgement_due            -> {sample.acknowledgement_due}")
print()
print("  Two differences from the proposal those four numbers came from.")
print("  Appendix D.6 proposes \"one business day\" for Attend and \"five business")
print("  days\" for Track*; the table above holds calendar days, so a Track*")
print("  finding raised on a Friday comes due the following Wednesday rather")
print("  than the Friday after. And Appendix D.6 proposes targets for Act,")
print("  Attend, Track* and Track only -- Triage's four hours is an addition the")
print("  code made. Both are defensible. Both are D10's to ratify or change")
print("  rather than to inherit.")
print()

import seal.core.priority as priority_module  # noqa: E402

names = {n.upper() for n in dir(priority_module)}
fields = set(sample.__dataclass_fields__) | {
    n for n in dir(sample) if not n.startswith("_")
}
def present(*keys):
    hit = sorted(n for n in names | {f.upper() for f in fields}
                 if any(k in n for k in keys))
    return hit or "none"

print("  Searching priority.py for the rest of what D10 names:")
print(f"    remediation deadlines          -> {present('REMEDIAT', 'DUE_')}")
print(f"    automatic overdue escalation   -> {present('OVERDUE', 'ESCALAT')}")
print(f"    maintenance window             -> {present('MAINTENANCE', 'WINDOW')}")
print(f"    threat-data freshness          -> {present('FRESH')}")
print()
print("  The six elements of Appendix E.3, one row each:")
print()
print("  1 priority decision tree       EXPRESSED as a candidate, every branch")
print("                                   firing, every outcome version-stamped")
print()
print("  2 validation/remediation       PARTIAL -- validation is there (urgent")
print("    deadlines                      validation raises immediately,")
print("                                   acknowledgement targets carry a due")
print("                                   time per action); remediation")
print("                                   deadlines do not exist at all, and")
print("                                   Appendix D.6 requires them \"before")
print("                                   enabling automatic overdue")
print("                                   escalation\"")
print()
print("  3 threat-data freshness        PARTIAL -- 48h bounds the EPSS reading")
print("                                   only; a scanner advisory DB's age has")
print("                                   no equivalent limit, which is the gap")
print("                                   D04's pinning record names")
print()
print("  4 incident contacts            PARTIAL -- the fields exist and are")
print("                                   empty (authorization.emergency_contacts,")
print("                                   incident.target_owner_contacts); a")
print("                                   container is not a policy")
print()
print("  5 maintenance window           ABSENT -- no model anywhere in core")
print()
print("  6 escalation paths             PARTIAL -- expired overrides and")
print("                                   undetermined reporting duties raise")
print("                                   flags (OVERRIDE_EXPIRED,")
print("                                   requires_reassessment,")
print("                                   requires_escalation); no route, no")
print("                                   recipient, no clock")
print()

print("=" * 78)
print("5. The three override controls Appendix D.6 requires, now checked")
print("=" * 78)
print("   Appendix D.6 requires every override to retain \"old/new outcome, policy")
print("   version, named reviewer, reason, evidence, creation time and expiry\".")
print("   Every field in that list is retained, and every field in that list is")
print("   now read. These three rows were permits when the D10 pack measured")
print("   them; each is a control the documents describe and apply_override")
print("   previously recorded without comparing:")
print()

print("  (a) The floor reaches Triage. Triage ranks below Attend, so moving a")
print("      known-exploitation Act finding to \"we do not know\" needs the same")
print("      approved exception as moving it to Track:")
show("Act -> Triage, no exception", override(Action.TRIAGE))
show("Act -> Triage, exception approved",
     override(Action.TRIAGE, exception_approved_by="ciso"))
show("Act -> Track, no exception", override(Action.TRACK))
print()
print("  (b) An override's policy_version is compared with the active policy. One")
print("      authored under a retired policy lapses rather than carrying forward,")
print("      and the computed outcome comes back in its place:")
stale = override(Action.TRACK, policy_version="seal-priority-retired-v0",
                 exception_approved_by="ciso")
result, decision = apply_override(computed, stale, CTX, now=T0)
print(f"      override.policy_version        -> {stale.policy_version!r}")
print(f"      active policy version          -> {POLICY_VERSION!r}")
print(f"      decision                       -> "
      f"{'PERMIT' if decision.allowed else 'DENY ' + str(decision.reasons)}")
print(f"      effective action               -> {result.action.value}")
print("      The version checked against is a parameter, so once D10 approves a")
print("      policy an override authored under that one is read against it:")
fresh = override(Action.TRACK, policy_version="seal-priority-approved-v1",
                 exception_approved_by="ciso")
_, decision = apply_override(computed, fresh, CTX, now=T0,
                             active_policy_version="seal-priority-approved-v1")
print(f"      decision                       -> "
      f"{'PERMIT' if decision.allowed else 'DENY ' + str(decision.reasons)}")
print()
print("  (c) An override's computed field -- the \"old outcome\" -- is compared with")
print("      the outcome actually being overridden, which makes it evidence rather")
print(f"      than an assertion. The real computed action is {computed.action.value}:")
mismatched = override(Action.ATTEND, computed=Action.TRACK)
result, decision = apply_override(computed, mismatched, CTX, now=T0)
print(f"      override.computed              -> {mismatched.computed.value}")
print(f"      decision                       -> "
      f"{'PERMIT' if decision.allowed else 'DENY ' + str(decision.reasons)}, result "
      f"{result.action.value}")
print()
print("  Each of the three answers a policy question D10 owns, and each answer is")
print("  visible in one place: Triage's rank in _RANK, the policy-version")
print("  comparison and the old-outcome comparison in apply_override. A denial")
print("  returns the computed outcome with its reason code rather than silently")
print("  dropping the override, so the review is escalated rather than lost.")
print()

print("=" * 78)
print(f"  Every outcome above is stamped {POLICY_VERSION!r}. That is the useful part:")
print("  when D10 approves a policy, the version string changes, and every finding")
print("  prioritised under the proposal stays identifiable for recalculation.")
print("=" * 78)
