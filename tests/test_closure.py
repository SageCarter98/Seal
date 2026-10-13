"""U04 proof review and C01 stale-intent rejection.

C01's four named acceptance scenarios are implemented as the ``TestC01*``
classes below:

* **C01-A** delay a valid receipt, admit recurrence or replacement evidence,
  then deliver it: no closure.
* **C01-B** race two intents and reordered/duplicate receipts: only the current
  eligible intent may finalize, once.
* **C01-C** force both serial orders of recurrence and finalization:
  contradiction either prevents closure or reopens it; no silent loss.
* **C01-D** crash between receipt verification and commit: recovery repeats the
  eligibility checks and cannot apply a stale decision.

Spec Section 13 is explicit that "acceptance awaits real integration tests" --
these are model checks against the pure contract, not acceptance evidence for
the production control.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from conftest import ORG, OTHER_ORG, PROFILE, TARGET

from seal.core import reasons as R
from seal.core._canonical import digest
from seal.core.audit import AnchorReceipt, EventKind
from seal.core.closure import (
    IntentStore,
    LedgerView,
    VerificationResult,
    build_intent,
    finalize,
    invalidate,
    reopen_after_closure,
    review_closure,
)
from seal.core.coverage import CoverageStatus
from seal.core.lifecycle import State, observe

EVIDENCE_DIGEST = digest({"evidence": "sanitized-set-3"})
AUDIT_HEAD = digest({"head": "chain-head-41"})


@pytest.fixture
def verification(pending_finding, now) -> VerificationResult:
    """A clean verification that matches the pending finding in every binding."""
    return VerificationResult(
        job_id="job-verify-1",
        organization=pending_finding.organization,
        target_id=pending_finding.target_id,
        fingerprint=pending_finding.fingerprint,
        rule=pending_finding.rule,
        profile_digest=pending_finding.profile_digest,
        tested_revision=pending_finding.fixed_revision,
        started=now - timedelta(minutes=30),
        finished=now - timedelta(minutes=10),
        reviewer="reviewer.esi",
        reviewer_decision_id="rd-9",
        evidence_set_revision=3,
        evidence_digest=EVIDENCE_DIGEST,
        coverage_status=CoverageStatus.COMPLETE,
        detected=False,
    )


@pytest.fixture
def intent(pending_finding, verification, now):
    return build_intent(
        pending_finding,
        verification,
        intent_id="intent-1",
        control="zap.40012",
        rule_version="rules-v1",
        audit_sequence=41,
        audit_head=AUDIT_HEAD,
        created_at=now - timedelta(minutes=5),
    )


@pytest.fixture
def receipt(intent, now):
    return AnchorReceipt(
        organization=intent.organization,
        sequence=intent.audit_sequence,
        head=intent.audit_head,
        sink_id="sink-assurance-1",
        received_at=now,
        verified=True,
    )


@pytest.fixture
def ledger(pending_finding, intent):
    """Committed state that agrees with the intent in every respect."""
    return LedgerView(
        active_intent_id=intent.intent_id,
        finding_version=pending_finding.version,
        evidence_set_revision=intent.evidence_set_revision,
        evidence_digest=intent.evidence_digest,
        observation_watermark=intent.observation_watermark,
    )


# ---------------------------------------------------------------------------
# U04 -- stage 1, the proof review
# ---------------------------------------------------------------------------


class TestProofReview:
    def test_a_complete_matching_verification_awaits_the_anchor(
        self, pending_finding, verification, now
    ):
        """Severity 8.0 means Closed is not reachable without a receipt."""
        decision = review_closure(pending_finding, verification, now=now)
        assert decision.allowed, decision.reasons
        assert decision.detail["next_state"] == State.CLOSURE_AWAITING_ANCHOR.value
        assert decision.detail["anchor_required"] is True

    def test_a_low_severity_finding_closes_without_an_anchor(
        self, pending_finding, verification, now
    ):
        low = replace(pending_finding, severity_score=4.0)
        decision = review_closure(low, verification, now=now)
        assert decision.detail["next_state"] == State.CLOSED.value
        assert decision.detail["anchor_required"] is False

    def test_a_persisting_finding_reopens(self, pending_finding, verification, now):
        decision = review_closure(pending_finding, replace(verification, detected=True), now=now)
        assert decision.allowed
        assert R.FINDING_PERSISTS in decision.reasons
        assert decision.detail["next_state"] == State.REOPENED.value

    def test_wrong_build_is_refused(self, pending_finding, verification, now):
        """U04: closure binds to the repaired revision."""
        decision = review_closure(
            pending_finding, replace(verification, tested_revision="rev-fixed-1"), now=now
        )
        assert R.WRONG_BUILD in decision.reasons

    def test_incomplete_coverage_is_inconclusive_not_closure(
        self, pending_finding, verification, now
    ):
        """An empty alert list over partial coverage proves nothing."""
        for status in (
            CoverageStatus.PARTIAL,
            CoverageStatus.FAILED,
            CoverageStatus.STOPPED,
            CoverageStatus.NOT_ASSESSED,
        ):
            decision = review_closure(
                pending_finding, replace(verification, coverage_status=status), now=now
            )
            assert not decision.allowed
            assert R.INCOMPLETE_COVERAGE in decision.reasons

    def test_the_fixer_cannot_review_their_own_closure(self, pending_finding, verification, now):
        decision = review_closure(
            pending_finding,
            replace(verification, reviewer=pending_finding.remediation_owner),
            now=now,
        )
        assert R.INDEPENDENT_REVIEW_REQUIRED in decision.reasons

    def test_the_assessor_cannot_review_their_own_closure(self, pending_finding, verification, now):
        decision = review_closure(
            pending_finding,
            replace(verification, reviewer=pending_finding.assessor),
            now=now,
        )
        assert R.INDEPENDENT_REVIEW_REQUIRED in decision.reasons

    def test_a_cross_tenant_verification_is_refused(self, pending_finding, verification, now):
        decision = review_closure(
            pending_finding, replace(verification, organization=OTHER_ORG), now=now
        )
        assert R.VERIFICATION_BOUNDARY_MISMATCH in decision.reasons

    def test_a_different_fingerprint_cannot_close_this_finding(
        self, pending_finding, verification, now
    ):
        decision = review_closure(
            pending_finding, replace(verification, fingerprint=digest({"fp": "other"})), now=now
        )
        assert R.VERIFICATION_BOUNDARY_MISMATCH in decision.reasons

    def test_a_scan_before_the_fix_cannot_prove_it(self, pending_finding, verification, now):
        early = replace(
            verification,
            started=pending_finding.fixed_at - timedelta(hours=1),
            finished=pending_finding.fixed_at - timedelta(minutes=30),
        )
        decision = review_closure(pending_finding, early, now=now)
        assert R.STALE_OR_FUTURE_VERIFICATION in decision.reasons

    def test_an_unauthorized_rescan_is_refused(self, pending_finding, verification, now):
        decision = review_closure(pending_finding, replace(verification, authorized=False), now=now)
        assert R.UNAUTHORIZED_RESCAN in decision.reasons

    def test_invalid_integrity_blocks_the_review(self, pending_finding, verification, now):
        decision = review_closure(
            pending_finding, replace(verification, integrity_valid=False), now=now
        )
        assert R.INVALID_INTEGRITY in decision.reasons

    def test_missing_evidence_digest_is_refused(self, pending_finding, verification, now):
        decision = review_closure(
            pending_finding, replace(verification, evidence_digest=""), now=now
        )
        assert R.EVIDENCE_REQUIRED in decision.reasons

    def test_a_changed_rule_needs_a_reviewed_equivalence_record(
        self, pending_finding, verification, now
    ):
        """Spec Section 5: no silent comparison across a rule change."""
        changed = replace(verification, rule_changed=True)
        assert (
            R.RULE_EQUIVALENCE_UNREVIEWED
            in review_closure(pending_finding, changed, now=now).reasons
        )

        reviewed = replace(changed, rule_equivalence_reviewed_by="reviewer.esi")
        assert review_closure(pending_finding, reviewed, now=now).allowed

    def test_a_finding_not_in_verification_pending_cannot_be_reviewed(
        self, pending_finding, verification, now
    ):
        decision = review_closure(
            replace(pending_finding, state=State.ASSIGNED), verification, now=now
        )
        assert R.NOT_PENDING in decision.reasons


# ---------------------------------------------------------------------------
# C01 -- stage 2, finalization
# ---------------------------------------------------------------------------


class TestFinalization:
    def test_a_verified_receipt_on_an_unchanged_intent_closes_the_finding(
        self, intent, pending_finding, receipt, ledger, now
    ):
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        view = replace(ledger, finding_version=awaiting.version)
        pinned = replace(intent, expected_finding_version=awaiting.version)

        result = finalize(pinned, awaiting, receipt, view, now=now)
        assert result.decision.allowed, result.decision.reasons
        assert result.finding.state is State.CLOSED
        assert result.finding.version == awaiting.version + 1

    def test_closure_and_its_audit_event_come_back_together(
        self, intent, pending_finding, receipt, ledger, now
    ):
        """C01: commit Closed and its audit/outbox event together."""
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        result = finalize(
            replace(intent, expected_finding_version=awaiting.version),
            awaiting,
            receipt,
            replace(ledger, finding_version=awaiting.version),
            now=now,
        )
        assert len(result.audit_events) == 1
        kind, payload = result.audit_events[0]
        assert kind is EventKind.CLOSURE_FINALIZED
        assert payload["intent_id"] == intent.intent_id
        assert payload["receipt_head"] == receipt.head
        assert payload["intent_binding"]

    def test_an_unverified_receipt_cannot_close(
        self, intent, pending_finding, receipt, ledger, now
    ):
        """Seal must never fabricate or assume a receipt."""
        result = finalize(
            intent, pending_finding, replace(receipt, verified=False), ledger, now=now
        )
        assert R.RECEIPT_UNVERIFIED in result.decision.reasons
        assert result.finding.state is not State.CLOSED

    def test_a_receipt_for_a_different_audit_event_cannot_close(
        self, intent, pending_finding, receipt, ledger, now
    ):
        result = finalize(intent, pending_finding, replace(receipt, sequence=99), ledger, now=now)
        assert R.RECEIPT_AUDIT_MISMATCH in result.decision.reasons

    def test_an_untrusted_integrity_state_blocks_finalization(
        self, intent, pending_finding, receipt, ledger, now
    ):
        """C01: stop or integrity restrictions still block finalization."""
        result = finalize(
            intent,
            pending_finding,
            receipt,
            replace(ledger, integrity_trusted=False),
            now=now,
        )
        assert R.INTEGRITY_UNTRUSTED in result.decision.reasons

    def test_an_active_stop_blocks_finalization(
        self, intent, pending_finding, receipt, ledger, now
    ):
        result = finalize(
            intent, pending_finding, receipt, replace(ledger, stop_active=True), now=now
        )
        assert R.STOP_ACTIVE in result.decision.reasons

    def test_a_withdrawn_reviewer_decision_blocks_finalization(
        self, intent, pending_finding, receipt, ledger, now
    ):
        result = finalize(
            intent,
            pending_finding,
            receipt,
            replace(ledger, reviewer_decision_withdrawn=True),
            now=now,
        )
        assert R.REVIEWER_DECISION_WITHDRAWN in result.decision.reasons


class TestC01A:
    """Delay a valid receipt, admit new evidence, then deliver it: no closure."""

    def test_recurrence_before_the_receipt_prevents_closure(
        self, intent, pending_finding, receipt, ledger, now
    ):
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        # A contradictory observation is admitted while the receipt is in flight.
        recurred, event = observe(awaiting, "obs-8")
        assert event == "repeated"

        view = replace(
            ledger,
            finding_version=recurred.version,
            observation_watermark="obs-8",
            contradictory_observation_after_watermark=True,
        )
        result = finalize(intent, recurred, receipt, view, now=now)

        assert not result.decision.allowed
        assert R.CONTRADICTORY_OBSERVATION_ADMITTED in result.decision.reasons
        assert result.finding.state is not State.CLOSED

    def test_the_late_receipt_is_preserved_without_closing(
        self, intent, pending_finding, receipt, ledger, now
    ):
        """C01: reject a late receipt as stale; preserve it without closing."""
        view = replace(ledger, contradictory_observation_after_watermark=True)
        result = finalize(intent, pending_finding, receipt, view, now=now)
        assert result.preserved_receipt is receipt
        assert result.audit_events == ()

    def test_replacement_evidence_prevents_closure(
        self, intent, pending_finding, receipt, ledger, now
    ):
        view = replace(
            ledger,
            evidence_set_revision=intent.evidence_set_revision + 1,
            evidence_digest=digest({"evidence": "replacement-set-4"}),
        )
        result = finalize(intent, pending_finding, receipt, view, now=now)
        assert R.EVIDENCE_REVISION_CHANGED in result.decision.reasons

    def test_a_changed_repaired_revision_prevents_closure(
        self, intent, pending_finding, receipt, ledger, now
    ):
        rebuilt = replace(pending_finding, fixed_revision="rev-fixed-3")
        result = finalize(intent, rebuilt, receipt, ledger, now=now)
        assert R.WRONG_BUILD in result.decision.reasons

    def test_an_invalidated_intent_cannot_finalize(
        self, intent, pending_finding, receipt, ledger, now
    ):
        dead = invalidate(intent, "replacement evidence admitted", at=now)
        result = finalize(dead, pending_finding, receipt, ledger, now=now)
        assert R.INTENT_INVALIDATED in result.decision.reasons
        assert dead.invalidated_reason


class TestC01B:
    """Race two intents and reordered/duplicate receipts."""

    def test_only_the_current_active_intent_may_finalize(
        self, pending_finding, verification, receipt, ledger, now
    ):
        store = IntentStore()
        first = build_intent(
            pending_finding,
            verification,
            intent_id="intent-1",
            control="zap.40012",
            rule_version="rules-v1",
            audit_sequence=41,
            audit_head=AUDIT_HEAD,
            created_at=now - timedelta(minutes=5),
        )
        second = build_intent(
            pending_finding,
            verification,
            intent_id="intent-2",
            control="zap.40012",
            rule_version="rules-v1",
            audit_sequence=42,
            audit_head=digest({"head": "chain-head-42"}),
            created_at=now - timedelta(minutes=1),
        )
        store.record(first, at=now - timedelta(minutes=5))
        store.record(second, at=now - timedelta(minutes=1))

        assert store.active(pending_finding.finding_id).intent_id == "intent-2"
        # The superseded intent is retained as history, not deleted.
        assert len(store.history(pending_finding.finding_id)) == 2
        assert store.history(pending_finding.finding_id)[0].superseded_at is not None

        view = replace(ledger, active_intent_id="intent-2")
        stale = finalize(first, pending_finding, receipt, view, now=now)
        assert R.INTENT_SUPERSEDED in stale.decision.reasons

    def test_a_duplicate_receipt_for_a_finalized_intent_is_an_idempotent_no_op(
        self, intent, pending_finding, receipt, ledger, now
    ):
        view = replace(ledger, already_finalized_intent_ids=frozenset({intent.intent_id}))
        result = finalize(intent, pending_finding, receipt, view, now=now)
        assert result.decision.allowed
        assert R.ALREADY_FINALIZED in result.decision.reasons
        # No second closure event, and the finding is untouched.
        assert result.audit_events == ()
        assert result.finding is pending_finding

    def test_a_reordered_receipt_for_the_superseded_intent_is_refused(
        self, intent, pending_finding, ledger, now
    ):
        old_receipt = AnchorReceipt(
            organization=ORG,
            sequence=intent.audit_sequence,
            head=intent.audit_head,
            sink_id="sink-assurance-1",
            received_at=now,
            verified=True,
        )
        view = replace(ledger, active_intent_id="intent-2")
        result = finalize(intent, pending_finding, old_receipt, view, now=now)
        assert not result.decision.allowed

    def test_finalizing_twice_requires_a_version_that_no_longer_matches(
        self, intent, pending_finding, receipt, ledger, now
    ):
        """Compare-and-swap: the first close bumps the version, so a replay fails."""
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        pinned = replace(intent, expected_finding_version=awaiting.version)
        view = replace(ledger, finding_version=awaiting.version)

        first = finalize(pinned, awaiting, receipt, view, now=now)
        assert first.decision.allowed

        # Replaying the same intent against the now-closed finding.
        replayed = finalize(
            pinned,
            first.finding,
            receipt,
            replace(view, finding_version=first.finding.version),
            now=now,
        )
        assert R.FINDING_VERSION_CONFLICT in replayed.decision.reasons


class TestC01C:
    """Both serial orders of recurrence and finalization. No silent loss."""

    def test_recurrence_then_finalization_prevents_closure(
        self, intent, pending_finding, receipt, ledger, now
    ):
        recurred, _ = observe(
            replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR), "obs-9"
        )
        view = replace(
            ledger,
            finding_version=recurred.version,
            observation_watermark="obs-9",
            contradictory_observation_after_watermark=True,
        )
        result = finalize(intent, recurred, receipt, view, now=now)
        assert not result.decision.allowed
        assert result.finding.state is State.CLOSURE_AWAITING_ANCHOR

    def test_finalization_then_recurrence_reopens_in_a_second_transaction(
        self, intent, pending_finding, receipt, ledger, now
    ):
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        closed = finalize(
            replace(intent, expected_finding_version=awaiting.version),
            awaiting,
            receipt,
            replace(ledger, finding_version=awaiting.version),
            now=now,
        )
        assert closed.finding.state is State.CLOSED

        reopened, events = reopen_after_closure(
            closed.finding, "obs-10", reason="contradiction admitted after closure"
        )
        assert reopened.state is State.REOPENED
        assert reopened.reopened_count == 1
        assert reopened.version == closed.finding.version + 1
        # The reopen is its own audited transaction, not a rollback.
        assert events and events[0][1]["action"] == "reopened_after_closure"

    def test_a_reopen_clears_the_prior_fix_so_review_starts_fresh(
        self, intent, pending_finding, receipt, ledger, now
    ):
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        closed = finalize(
            replace(intent, expected_finding_version=awaiting.version),
            awaiting,
            receipt,
            replace(ledger, finding_version=awaiting.version),
            now=now,
        )
        reopened, _ = reopen_after_closure(closed.finding, "obs-10", reason="recurred")
        assert reopened.fixed_revision == ""
        assert reopened.fixed_at is None
        assert reopened.remediation_owner == ""

    def test_reopen_after_closure_refuses_a_finding_that_is_not_closed(self, pending_finding):
        with pytest.raises(ValueError, match="only a closed finding"):
            reopen_after_closure(pending_finding, "obs-11", reason="x")


class TestC01D:
    """Crash between receipt verification and commit."""

    def test_recovery_repeats_eligibility_and_cannot_apply_a_stale_decision(
        self, intent, pending_finding, receipt, ledger, now
    ):
        """The receipt was verified, then the process died. On restart the
        finding has moved on, so the recovered decision must not be applied."""
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        pinned = replace(intent, expected_finding_version=awaiting.version)

        # While the process was down, a recurrence advanced the finding.
        recovered_finding, _ = observe(awaiting, "obs-12")
        view = replace(
            ledger,
            finding_version=recovered_finding.version,
            observation_watermark="obs-12",
            contradictory_observation_after_watermark=True,
        )

        result = finalize(pinned, recovered_finding, receipt, view, now=now)
        assert not result.decision.allowed
        assert R.FINDING_VERSION_CONFLICT in result.decision.reasons
        assert R.CONTRADICTORY_OBSERVATION_ADMITTED in result.decision.reasons

    def test_recovery_succeeds_when_nothing_changed(
        self, intent, pending_finding, receipt, ledger, now
    ):
        """A crash alone does not invalidate an otherwise eligible closure."""
        awaiting = replace(pending_finding, state=State.CLOSURE_AWAITING_ANCHOR)
        result = finalize(
            replace(intent, expected_finding_version=awaiting.version),
            awaiting,
            receipt,
            replace(ledger, finding_version=awaiting.version),
            now=now + timedelta(minutes=20),
        )
        assert result.decision.allowed
        assert result.finding.state is State.CLOSED


def test_the_intent_binding_digest_pins_every_decision_relevant_field(intent):
    """A receipt cannot authorize a newer decision, so the binding must change."""
    baseline = intent.binding_digest
    for change in (
        {"expected_finding_version": 99},
        {"evidence_set_revision": 4},
        {"repaired_artifact_revision": "rev-fixed-9"},
        {"observation_watermark": "obs-99"},
        {"reviewer_decision_id": "rd-10"},
        {"audit_sequence": 42},
    ):
        assert replace(intent, **change).binding_digest != baseline


def test_an_intent_records_the_versions_it_was_pinned_to(pending_finding, verification, now):
    built = build_intent(
        pending_finding,
        verification,
        intent_id="intent-7",
        control="zap.40012",
        rule_version="rules-v1",
        audit_sequence=50,
        audit_head=AUDIT_HEAD,
        created_at=now,
    )
    assert built.expected_finding_version == pending_finding.version
    assert built.repaired_artifact_revision == pending_finding.fixed_revision
    assert built.observation_watermark == pending_finding.observation_watermark
    assert built.evidence_set_revision == verification.evidence_set_revision
    assert built.active


def test_invalidate_requires_a_reason(intent, now):
    with pytest.raises(ValueError, match="record its reason"):
        invalidate(intent, "", at=now)


def test_profile_and_target_constants_are_used_consistently(intent):
    """Guards the fixtures themselves: the intent inherits the tenant boundary."""
    assert intent.organization == ORG
    assert intent.target_id == TARGET
    assert intent.profile_digest == PROFILE
