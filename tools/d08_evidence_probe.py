"""D08 probe -- what does the core already decide about personal data, and where
does it have no opinion at all?

`docs/decisions/D08_privacy_evidence_handling.md` sections 3 and 4 turn on two things
that are checkable today. ``EvidenceRecord.may_dispose`` enforces holds and
sanitization but has no concept of elapsed time, so the retention floors in baseline
section 11.1 have no enforcement point in the decision core -- and early disposal is
permitted, not just late disposal unprevented. ``may_export`` gates person fields by
role, which is the one access rule the core does implement.

This runs the real decisions and prints what happens. Like its D04, D06 and D07
counterparts it asserts nothing and emits no pass/fail: it establishes what the core
decides, not that any handling arrangement is adequate, which is the privacy
reviewer's judgement and needs a PIA nobody has approved.

    python tools/d08_evidence_probe.py
"""

import sys
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from seal.core.audit import EvidenceRecord
from seal.core.export import (
    EXPORT_ROLES,
    PERSON_FIELD_ROLES,
    ExportRequest,
    may_export,
)

T0 = datetime(2026, 10, 15, 9, 0, tzinfo=timezone.utc)
ORG = "org-1"
DIGEST = "a" * 64


def verdict(decision) -> str:
    tag = "PERMIT" if decision.allowed else "DENY  "
    return f"{tag}{decision.reasons}" if decision.reasons else tag


def record(**changes) -> EvidenceRecord:
    base = EvidenceRecord(
        evidence_id="E-1",
        organization=ORG,
        revision=1,
        content_digest=DIGEST,
        collected_at=T0,
        sanitized=True,
    )
    return replace(base, **changes)


print("=" * 78)
print("1. What may_dispose actually enforces")
print("=" * 78)
print("   Baseline section 11.1 sets retention floors in years. The disposal")
print("   decision is asked here at a range of ages, with everything else valid.")
print()

NOW = T0 + timedelta(days=365 * 8)
for label, rec, now in [
    ("legal hold set", record(legal_hold=True), NOW),
    ("incident hold set", record(incident_hold=True), NOW),
    ("not marked sanitized", record(sanitized=False), NOW),
    ("no content digest", record(content_digest=""), NOW),
    ("already disposed", record(disposed_at=T0), NOW),
    ("sanitized, no hold, eight years old", record(), NOW),
    ("sanitized, no hold, one day old", record(), T0 + timedelta(days=1)),
    ("sanitized, no hold, one second old", record(), T0 + timedelta(seconds=1)),
]:
    print(f"  {label:50} -> {verdict(rec.may_dispose(now=now))}")

print()
print("  The last three rows are the finding. The decision has no retention")
print("  concept: `now` is used only to reject a naive datetime. Evidence")
print("  containing personal data may be disposed one second after collection,")
print("  and a record that should be held for seven years after PM Gate 6 is")
print("  not distinguishable here from one that should not.")

print()
print("=" * 78)
print("2. The one access rule the core does implement")
print("=" * 78)
print("   may_export gates person fields by role. Baseline section 5 names eight")
print("   roles; EXPORT_ROLES names five. Both lists are run below.")
print()

BASELINE_ROLES = [
    "platform_owner",
    "security_administrator",
    "authorized_assessor",
    "system_or_code_owner",
    "reviewer_or_auditor",
    "legal_compliance_adviser",
    "incident_coordinator",
    "executive_viewer",
]

print("  Asking for person fields, as each baseline section 5 role identifier:")
for role in BASELINE_ROLES:
    request = ExportRequest(
        organization=ORG,
        actor="a-1",
        role=role,
        format="csv",
        requested_at=T0,
        member_organizations=frozenset({ORG}),
        include_person_fields=True,
    )
    print(f"  {role:50} -> {verdict(may_export(request))}")

print()
print("  The same request, as each identifier EXPORT_ROLES actually knows:")
for role in sorted(EXPORT_ROLES):
    request = ExportRequest(
        organization=ORG,
        actor="a-1",
        role=role,
        format="csv",
        requested_at=T0,
        member_organizations=frozenset({ORG}),
        include_person_fields=True,
    )
    mark = "  (person-cleared)" if role in PERSON_FIELD_ROLES else ""
    print(f"  {role:50} -> {verdict(may_export(request))}{mark}")

print()
print("  Not one baseline section 5 identifier is recognised. That is the same")
print("  unreconciled gap the frontend spec raised as its Q1, reached from the")
print("  other side: the core's five identifiers and the baseline's eight roles")
print("  are different vocabularies, and nothing maps between them.")

print()
print("=" * 78)
print("3. What is recorded but never decided")
print("=" * 78)
print("  Fields an EvidenceRecord carries today:")
print(f"    {', '.join(f.name for f in fields(EvidenceRecord))}")
print()
print("  `access_log` is read in exactly one place -- export.py renders its")
print("  length as `access_count`. Nothing appends to it and no decision")
print("  consults it, so 'access' as D08 requires it -- who may read evidence")
print("  containing personal data, under what purpose -- has no decision in the")
print("  core at all. `sanitized` is likewise a recorded flag: the core refuses")
print("  to dispose of evidence not marked sanitized, but cannot establish that")
print("  sanitization happened. The standard is D08's; the mechanism is F08's.")
