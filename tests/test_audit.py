"""U07 + U08 -- audit chain, anchor outbox and evidence custody.

Acceptance evidence: "Sink outage and tamper exercises" (U07) and
"Sanitization and deletion tests" (U08). Spec Section 7 names the specific
exercises: "Test receipt loss, sink failure, replay, reordering and rewrite
before claiming integrity."
"""

from __future__ import annotations

import itertools
from dataclasses import replace
from datetime import timedelta

import pytest
from conftest import ORG, OTHER_ORG

from seal.core import reasons as R
from seal.core._canonical import digest
from seal.core.audit import (
    ANCHOR_INTERVAL,
    AUDIT_OWNER_ROLE,
    AnchorReceipt,
    AuditLedger,
    Checkpoint,
    EventKind,
    EvidenceRecord,
    requires_immediate_anchor,
)

RUNTIME_ROLES = ("seal_api", "seal_worker", "seal_migrator", "seal_readonly")


@pytest.fixture
def ledger(now) -> AuditLedger:
    chain = AuditLedger(ORG)
    for index in range(3):
        chain.append(
            EventKind.AUTHORIZATION,
            {"authorization_id": f"auth-{index}"},
            organization=ORG,
            recorded_at=now - timedelta(minutes=10 - index),
        )
    return chain


class TestChainIntegrity:
    def test_a_well_formed_chain_verifies_against_its_checkpoint(self, ledger):
        decision = ledger.verify(ledger.checkpoint)
        assert decision.allowed, decision.reasons
        assert decision.detail["count"] == 3

    def test_each_event_links_to_its_predecessor(self, ledger):
        events = ledger.events
        assert events[0].previous == "0" * 64
        for earlier, later in itertools.pairwise(events):
            assert later.previous == earlier.hash
            assert later.sequence == earlier.sequence + 1

    def test_a_rewritten_payload_is_detected(self, ledger, now):
        """The rewrite exercise."""
        events = list(ledger.events)
        tampered = replace(events[1], payload={"authorization_id": "auth-forged"})
        ledger._events[1] = tampered
        decision = ledger.verify(ledger.checkpoint)
        assert not decision.allowed
        assert R.CHAIN_EVENT_TAMPERED in decision.reasons
        assert decision.detail["sequence"] == 2

    def test_a_reordered_chain_is_detected(self, ledger):
        """The reordering exercise."""
        ledger._events[0], ledger._events[1] = ledger._events[1], ledger._events[0]
        decision = ledger.verify(ledger.checkpoint)
        assert not decision.allowed
        assert decision.reasons[0] in (
            R.CHAIN_SEQUENCE_MISMATCH,
            R.CHAIN_LINK_MISMATCH,
        )

    def test_a_removed_event_breaks_the_checkpoint(self, ledger):
        expected = ledger.checkpoint
        ledger._events.pop()
        decision = ledger.verify(expected)
        assert R.CHECKPOINT_MISMATCH in decision.reasons

    def test_a_checkpoint_from_elsewhere_cannot_be_satisfied_by_the_list_itself(self, ledger):
        """The checkpoint is held outside the list it checks, so a forged tail
        cannot make itself valid."""
        forged = Checkpoint(count=3, head=digest({"head": "forged"}))
        assert not ledger.verify(forged).allowed

    def test_a_cross_tenant_event_cannot_be_appended(self, ledger, now):
        with pytest.raises(ValueError, match=R.CHAIN_TENANT_MISMATCH):
            ledger.append(EventKind.INCIDENT, {}, organization=OTHER_ORG, recorded_at=now)

    def test_an_undurable_append_is_not_acknowledged(self, ledger, now):
        """A successful acknowledgment must mean the event is durably committed."""
        before = len(ledger.events)
        with pytest.raises(RuntimeError, match=R.AUDIT_APPEND_NOT_DURABLE):
            ledger.append(EventKind.INCIDENT, {}, organization=ORG, recorded_at=now, durable=False)
        assert len(ledger.events) == before

    def test_a_naive_timestamp_is_refused(self, ledger):
        from datetime import datetime

        with pytest.raises(ValueError, match=R.UTC_AWARE_TIME_REQUIRED):
            ledger.append(
                EventKind.INCIDENT, {}, organization=ORG, recorded_at=datetime(2026, 1, 1)
            )

    def test_an_empty_chain_has_the_genesis_head(self):
        assert AuditLedger(ORG).head == "0" * 64
        assert AuditLedger(ORG).verify(Checkpoint(0, "0" * 64)).allowed

    def test_a_ledger_requires_an_organization(self):
        with pytest.raises(ValueError, match="exactly one organization"):
            AuditLedger("")


class TestOutboxAndReceipts:
    def test_every_append_yields_an_outbox_item(self, now):
        chain = AuditLedger(ORG)
        event, item = chain.append(
            EventKind.CLOSURE_INTENT, {"intent": "i-1"}, organization=ORG, recorded_at=now
        )
        assert item.sequence == event.sequence
        assert item.head == event.hash
        assert chain.pending_outbox == (item,)

    def test_the_idempotency_key_is_the_sequence_and_head(self, now):
        chain = AuditLedger(ORG)
        _, first = chain.append(EventKind.INCIDENT, {"a": 1}, organization=ORG, recorded_at=now)
        _, second = chain.append(EventKind.INCIDENT, {"a": 2}, organization=ORG, recorded_at=now)
        assert first.idempotency_key != second.idempotency_key

    def test_a_verified_receipt_clears_its_outbox_item(self, ledger, now):
        item = ledger.pending_outbox[-1]
        decision = ledger.record_receipt(
            AnchorReceipt(ORG, item.sequence, item.head, "sink-1", now, verified=True)
        )
        assert decision.allowed
        assert item not in ledger.pending_outbox

    def test_an_unverified_receipt_is_refused(self, ledger, now):
        """Seal must never fabricate or assume a receipt."""
        item = ledger.pending_outbox[-1]
        decision = ledger.record_receipt(
            AnchorReceipt(ORG, item.sequence, item.head, "sink-1", now, verified=False)
        )
        assert R.RECEIPT_UNVERIFIED in decision.reasons
        assert item in ledger.pending_outbox

    def test_a_replayed_receipt_for_a_head_never_produced_is_refused(self, ledger, now):
        """The replay exercise."""
        decision = ledger.record_receipt(
            AnchorReceipt(ORG, 99, digest({"head": "never"}), "sink-1", now, verified=True)
        )
        assert R.RECEIPT_AUDIT_MISMATCH in decision.reasons

    def test_a_duplicate_receipt_is_an_idempotent_no_op(self, ledger, now):
        item = ledger.pending_outbox[-1]
        receipt = AnchorReceipt(ORG, item.sequence, item.head, "sink-1", now, verified=True)
        assert ledger.record_receipt(receipt).allowed

        again = ledger.record_receipt(receipt)
        assert again.allowed
        assert R.ALREADY_FINALIZED in again.reasons

    def test_a_cross_tenant_receipt_is_refused(self, ledger, now):
        item = ledger.pending_outbox[-1]
        decision = ledger.record_receipt(
            AnchorReceipt(OTHER_ORG, item.sequence, item.head, "sink-1", now, verified=True)
        )
        assert R.CHAIN_TENANT_MISMATCH in decision.reasons


class TestAnchorTimeliness:
    def test_a_recently_anchored_chain_is_current(self, ledger, now):
        item = ledger.pending_outbox[-1]
        ledger.record_receipt(
            AnchorReceipt(ORG, item.sequence, item.head, "sink-1", now, verified=True)
        )
        assert ledger.anchor_status(now).allowed

    def test_an_overdue_anchor_is_detected(self, ledger, now):
        """The sink outage exercise: nothing anchored past the interval."""
        decision = ledger.anchor_status(now + ANCHOR_INTERVAL + timedelta(minutes=1))
        assert not decision.allowed
        assert R.ANCHOR_OVERDUE in decision.reasons
        assert decision.detail["pending_count"] == 3

    def test_the_clock_runs_from_the_first_event_when_nothing_is_anchored(self, ledger, now):
        """A chain that has never anchored is overdue, not exempt."""
        assert ledger.anchor_status(now).allowed
        assert not ledger.anchor_status(now + timedelta(minutes=30)).allowed

    def test_an_empty_chain_has_nothing_to_anchor(self, now):
        decision = AuditLedger(ORG).anchor_status(now + timedelta(days=1))
        assert decision.allowed
        assert decision.detail["anchored"] is True

    def test_the_interval_is_fifteen_minutes(self):
        assert ANCHOR_INTERVAL == timedelta(minutes=15)

    def test_a_naive_now_is_refused(self, ledger):
        from datetime import datetime

        decision = ledger.anchor_status(datetime(2026, 1, 1))
        assert R.UTC_AWARE_TIME_REQUIRED in decision.reasons


class TestImmediateAnchorKinds:
    @pytest.mark.parametrize(
        "kind",
        [
            EventKind.AUTHORIZATION,
            EventKind.PRIORITY_OVERRIDE,
            EventKind.CLOSURE_INTENT,
            EventKind.CLOSURE_FINALIZED,
            EventKind.INCIDENT,
            EventKind.AUDIT_CONTROL,
            EventKind.INTEGRITY_STATE,
        ],
    )
    def test_the_kinds_spec_section_7_names_anchor_immediately(self, kind):
        assert requires_immediate_anchor(kind)

    @pytest.mark.parametrize("kind", [EventKind.SCOPE_DENIAL, EventKind.COVERAGE_MANIFEST])
    def test_other_kinds_follow_the_interval(self, kind):
        assert not requires_immediate_anchor(kind)


class TestAuditOwner:
    def test_no_runtime_role_is_the_audit_owner(self):
        """Spec Section 7: the NOLOGIN owner has no issued credentials and no
        routine assumption. F07's test asserts no runtime role equals it."""
        assert AUDIT_OWNER_ROLE == "seal_audit_owner"
        for role in RUNTIME_ROLES:
            assert role != AUDIT_OWNER_ROLE


class TestEvidenceCustody:
    def record(self, now, **changes) -> EvidenceRecord:
        base = {
            "evidence_id": "ev-1",
            "organization": ORG,
            "revision": 3,
            "content_digest": digest({"evidence": "sanitized"}),
            "collected_at": now - timedelta(hours=1),
            "sanitized": True,
        }
        base.update(changes)
        return EvidenceRecord(**base)

    def test_sanitized_unheld_evidence_may_be_disposed(self, now):
        assert self.record(now).may_dispose(now=now).allowed

    def test_a_legal_hold_prevents_disposal(self, now):
        """Honor incident/legal holds before deletion (spec Section 7)."""
        decision = self.record(now, legal_hold=True).may_dispose(now=now)
        assert R.HOLD_PREVENTS_DISPOSAL in decision.reasons

    def test_an_incident_hold_prevents_disposal(self, now):
        decision = self.record(now, incident_hold=True).may_dispose(now=now)
        assert R.HOLD_PREVENTS_DISPOSAL in decision.reasons

    def test_unsanitized_evidence_cannot_be_disposed_as_ordinary_retention(self, now):
        """Disposal has to state whether the content was sanitized."""
        decision = self.record(now, sanitized=False).may_dispose(now=now)
        assert R.EVIDENCE_NOT_SANITIZED in decision.reasons

    def test_evidence_already_disposed_is_not_disposed_again(self, now):
        decision = self.record(now, disposed_at=now - timedelta(days=1)).may_dispose(now=now)
        assert R.ALREADY_FINALIZED in decision.reasons

    def test_a_missing_content_digest_is_refused(self, now):
        decision = self.record(now, content_digest="").may_dispose(now=now)
        assert R.EVIDENCE_REQUIRED in decision.reasons

    def test_held_is_true_for_either_hold(self, now):
        assert self.record(now, legal_hold=True).held
        assert self.record(now, incident_hold=True).held
        assert not self.record(now).held

    def test_quarantined_secrets_are_recorded_not_inferred(self, now):
        quarantined = self.record(now, secret_quarantined=True)
        assert quarantined.secret_quarantined


def test_the_canonical_digest_is_order_independent_for_dict_keys():
    """Digests are only comparable if every component computes them alike."""
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


def test_the_canonical_digest_refuses_non_finite_floats():
    with pytest.raises(ValueError):
        digest({"score": float("nan")})
