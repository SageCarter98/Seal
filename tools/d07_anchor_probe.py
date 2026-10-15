"""D07 probe -- what must an external audit sink be able to return?

`docs/decisions/D07_audit_sink_key_custody.md` section 3 turns on a constraint that
is measurable today. ``AuditLedger.record_receipt`` and ``closure.finalize`` both
reconcile a receipt against the exact ``(sequence, head)`` the ledger produced, and
both refuse a receipt whose ``verified`` flag is false. So a sink that acknowledges a
write without returning something that identifies *which chain head* it now holds --
and without a basis for verifying that independently -- cannot operate this decision.
It does not anchor less well; High and Critical findings simply never close.

This runs the real decisions with the information each candidate sink can actually
return, and prints what happens. Like its D04 and D06 counterparts it asserts nothing
and emits no pass/fail: it establishes what the decision needs, not that any sink
works, which needs a running platform and a real external service nobody has
authorised or selected.

    python tools/d07_anchor_probe.py
"""

import sys
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from seal.core.audit import (
    ANCHOR_INTERVAL,
    AnchorReceipt,
    AuditLedger,
    Checkpoint,
    EventKind,
    requires_immediate_anchor,
)
from seal.core.closure import ClosureIntent, LedgerView, finalize
from seal.core.coverage import CoverageStatus
from seal.core.integrity import (
    Admission,
    IntegrityState,
    Trigger,
    admit_request,
    detect,
)
from seal.core.lifecycle import Finding, State

T0 = datetime(2026, 10, 15, 9, 0, tzinfo=timezone.utc)
ORG = "org-1"


def verdict(decision) -> str:
    tag = "PERMIT" if decision.allowed else "DENY  "
    return f"{tag}{decision.reasons}" if decision.reasons else tag


def fresh_ledger() -> tuple[AuditLedger, object]:
    """A ledger holding one closure-intent event -- the high-risk anchor case."""
    ledger = AuditLedger(ORG)
    _, item = ledger.append(
        EventKind.CLOSURE_INTENT,
        {"finding": "F-1", "intent": "I-1"},
        organization=ORG,
        recorded_at=T0,
    )
    return ledger, item


print("=" * 78)
print("1. What must a sink return for the ledger to reconcile its receipt?")
print("=" * 78)
print("   One CLOSURE_INTENT event is appended; each row is the receipt a candidate")
print("   sink could actually produce for it.")
print()

_, reference = fresh_ledger()
TRUE_HEAD = reference.head

RECEIPTS = [
    (
        "signed inclusion proof naming the head, verified",
        dict(sequence=1, head=TRUE_HEAD, verified=True),
    ),
    (
        "write acknowledged (HTTP 200), nothing to verify against",
        dict(sequence=1, head=TRUE_HEAD, verified=False),
    ),
    (
        "sink returns its own object id, not the chain head",
        dict(sequence=1, head="obj-9f2c1b" + "0" * 52, verified=True),
    ),
    (
        "sink returns a head the ledger never produced (replay)",
        dict(sequence=1, head="f" * 64, verified=True),
    ),
    (
        "right head, wrong sequence (reordering)",
        dict(sequence=2, head=TRUE_HEAD, verified=True),
    ),
    (
        "receipt issued for another tenant's chain",
        dict(sequence=1, head=TRUE_HEAD, verified=True, organization="org-2"),
    ),
]

for label, spec in RECEIPTS:
    kwargs = dict(spec)
    ledger, _ = fresh_ledger()
    receipt = AnchorReceipt(
        organization=kwargs.pop("organization", ORG),
        sink_id="sink-a",
        received_at=T0 + timedelta(minutes=1),
        **kwargs,
    )
    print(f"  {label:56} -> {verdict(ledger.record_receipt(receipt))}")

print()
print("  Duplicate delivery of a receipt already reconciled:")
ledger, _ = fresh_ledger()
good = AnchorReceipt(
    organization=ORG,
    sequence=1,
    head=TRUE_HEAD,
    sink_id="sink-a",
    received_at=T0 + timedelta(minutes=1),
    verified=True,
)
first = ledger.record_receipt(good)
second = ledger.record_receipt(good)
print(f"  {'first delivery':56} -> {verdict(first)}")
print(f"  {'same receipt delivered again':56} -> {verdict(second)}")

print()
print("=" * 78)
print("2. Anchor timeliness is an availability requirement on the sink")
print("=" * 78)
print(f"   ANCHOR_INTERVAL = {ANCHOR_INTERVAL}. The clock runs from the first event")
print("   when nothing has been anchored yet, so a sink outage is what this measures.")
print()

for label, minutes, anchored in [
    ("sink responded 1 minute ago", 2, True),
    ("sink unreachable for 14 minutes", 14, False),
    ("sink unreachable for 16 minutes", 16, False),
    ("sink unreachable for 2 hours", 120, False),
]:
    ledger, _ = fresh_ledger()
    if anchored:
        ledger.record_receipt(
            AnchorReceipt(
                organization=ORG,
                sequence=1,
                head=TRUE_HEAD,
                sink_id="sink-a",
                received_at=T0 + timedelta(minutes=1),
                verified=True,
            )
        )
    print(f"  {label:56} -> {verdict(ledger.anchor_status(T0 + timedelta(minutes=minutes)))}")

print()
print("  What an overdue anchor does to the egress boundary:")
overdue_at = T0 + timedelta(minutes=16)
state = IntegrityState(admission=Admission.TRUSTED, generation=1, observed_at=T0)
after = detect(state, trigger=Trigger.ANCHOR_OVERDUE, now=overdue_at)
print(f"  {'integrity admission after ANCHOR_OVERDUE':56} -> {after.admission.value}")
print(f"  {'grant generation, before -> after':56} -> {state.generation} -> {after.generation}")
print(
    f"  {'a scanner request under that state':56} -> "
    f"{verdict(admit_request(after, now=overdue_at))}"
)

print()
print("=" * 78)
print("3. Which events cannot wait for the 15-minute interval")
print("=" * 78)
print("   Spec Section 7 names the event-triggered set; the sink must accept an")
print("   out-of-band write for each, so submission rate is not a batch property.")
print("   Everything else rides the base schedule -- every 15 minutes AND at scan")
print("   completion -- which is still the sink's availability problem, not a")
print("   licence to defer.")
print()
for kind in EventKind:
    mark = "immediate (event-triggered)" if requires_immediate_anchor(kind) else "base schedule"
    print(f"  {kind.value:56} -> {mark}")

print()
print("=" * 78)
print("4. The consequence: a High finding waiting on each kind of receipt")
print("=" * 78)
print("   Same receipts as section 1, but run through closure.finalize -- the")
print("   decision that actually holds a finding in `Closure awaiting anchor`.")
print()

FINDING = Finding(
    finding_id="F-1",
    organization=ORG,
    target_id="tgt-1",
    fingerprint="fp-1",
    rule="rule-1",
    profile_digest="pd-1",
    state=State.CLOSURE_AWAITING_ANCHOR,
    version=3,
    severity_score=8.1,
    fixed_revision="rev-9",
    observation_watermark="obs-7",
)

INTENT = ClosureIntent(
    intent_id="I-1",
    organization=ORG,
    target_id="tgt-1",
    control="c-1",
    finding_id="F-1",
    expected_finding_version=3,
    evidence_set_revision=2,
    evidence_digest="ed-1",
    repaired_artifact_revision="rev-9",
    observation_watermark="obs-7",
    verification_job_id="job-1",
    coverage_status=CoverageStatus.COMPLETE,
    profile_digest="pd-1",
    rule_version="rv-1",
    reviewer_decision_id="rd-1",
    audit_sequence=1,
    audit_head=TRUE_HEAD,
    created_at=T0,
)

VIEW = LedgerView(
    active_intent_id="I-1",
    finding_version=3,
    evidence_set_revision=2,
    evidence_digest="ed-1",
    observation_watermark="obs-7",
)

for label, kwargs in RECEIPTS:
    kwargs = dict(kwargs)
    receipt = AnchorReceipt(
        organization=kwargs.pop("organization", ORG),
        sink_id="sink-a",
        received_at=T0 + timedelta(minutes=1),
        **kwargs,
    )
    result = finalize(INTENT, FINDING, receipt, VIEW, now=T0 + timedelta(minutes=2))
    print(f"  {label:56} -> {result.finding.state.value}")

print()
print("  Only the first row leaves `Closure awaiting anchor`. A sink that cannot")
print("  name the head it holds does not weaken closure evidence -- it withholds")
print("  closure entirely, for every High and Critical finding, indefinitely.")

print()
print("=" * 78)
print("5. What the chain itself can and cannot prove")
print("=" * 78)
ledger, _ = fresh_ledger()
ledger.append(
    EventKind.CLOSURE_FINALIZED, {"finding": "F-1"}, organization=ORG, recorded_at=T0
)
print(f"  {'chain verified against the sink-held checkpoint':56} -> "
      f"{verdict(ledger.verify(Checkpoint(2, ledger.head)))}")
print(f"  {'same chain, checkpoint from a stale sink copy':56} -> "
      f"{verdict(ledger.verify(Checkpoint(1, TRUE_HEAD)))}")

tampered = AuditLedger(ORG)
tampered.append(EventKind.DISPOSITION, {"d": 1}, organization=ORG, recorded_at=T0)
tampered._events[0] = replace(tampered._events[0], payload={"d": 2})
print(f"  {'a payload altered after the fact':56} -> "
      f"{verdict(tampered.verify(Checkpoint(1, tampered.head)))}")

print()
print("  Fields an AnchorReceipt carries today:")
print(f"    {', '.join(f.name for f in fields(AnchorReceipt))}")
print()
print("  There is no key identity and no signature among them. The model takes")
print("  `verified` as a trusted input and says so. So the chain proves internal")
print("  consistency and that *a* sink acknowledged a head -- it does not express")
print("  which key signed it, and cannot answer what happens to a head signed")
print("  before a key rotation. That is section 7's question, and it is open.")
