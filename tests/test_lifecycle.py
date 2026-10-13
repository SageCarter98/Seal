"""U05 -- lifecycle, recurrence and dispositions kept on separate axes.

Acceptance evidence: "Reopen and expiry scenarios". W02 adds "every transition
checks role and organization; reason/reviewer/expiry captured; expired
exceptions return to attention; accepted risk is not verified closure."
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from seal.core import reasons as R
from seal.core.lifecycle import (
    ALLOWED_TRANSITIONS,
    Disposition,
    Exception_,
    State,
    expire_disposition,
    observe,
    record_disposition,
    transition,
)


def exception_for(finding, now, **overrides) -> Exception_:
    base = {
        "exception_id": "exc-1",
        "finding_id": finding.finding_id,
        "disposition": Disposition.RISK_ACCEPTED,
        "reviewer": "reviewer.esi",
        "reason": "compensating control in place until the next release",
        "evidence_reference": "CHG-4412",
        "affected_scope": "lab web target /app",
        "created_at": now - timedelta(days=1),
        "expires_at": now + timedelta(days=30),
        "previous_state": finding.state,
    }
    base.update(overrides)
    return Exception_(**base)


class TestTransitions:
    def test_a_permitted_transition_advances_the_version(self, pending_finding, now):
        moved, decision = transition(
            replace(pending_finding, state=State.REMEDIATING),
            State.VERIFICATION_PENDING,
            actor="dev.yaw",
            role="remediation_owner",
            expected_version=pending_finding.version,
            now=now,
        )
        assert decision.allowed, decision.reasons
        assert moved.state is State.VERIFICATION_PENDING
        assert moved.version == pending_finding.version + 1

    def test_an_impermissible_transition_is_refused(self, pending_finding, now):
        _, decision = transition(
            replace(pending_finding, state=State.NEW),
            State.CLOSED,
            actor="reviewer.esi",
            role="reviewer",
            expected_version=pending_finding.version,
            now=now,
        )
        assert R.TRANSITION_NOT_ALLOWED in decision.reasons

    def test_a_stale_version_is_a_concurrency_conflict_not_an_overwrite(self, pending_finding, now):
        """Two reviewers must not overwrite each other's decisions."""
        unchanged, decision = transition(
            pending_finding,
            State.CLOSURE_AWAITING_ANCHOR,
            actor="reviewer.esi",
            role="reviewer",
            expected_version=pending_finding.version - 1,
            now=now,
        )
        assert R.CONCURRENT_MODIFICATION in decision.reasons
        assert unchanged is pending_finding

    def test_the_wrong_role_cannot_drive_a_transition(self, pending_finding, now):
        _, decision = transition(
            pending_finding,
            State.CLOSED,
            actor="dev.other",
            role="remediation_owner",
            expected_version=pending_finding.version,
            now=now,
        )
        assert R.ROLE_NOT_PERMITTED in decision.reasons

    def test_the_fixer_cannot_close_their_own_finding(self, pending_finding, now):
        """Approval cannot be inferred from the fixer marking work done."""
        _, decision = transition(
            pending_finding,
            State.CLOSED,
            actor=pending_finding.remediation_owner,
            role="reviewer",
            expected_version=pending_finding.version,
            now=now,
        )
        assert R.INDEPENDENT_REVIEW_REQUIRED in decision.reasons

    def test_the_assessor_cannot_close_their_own_finding(self, pending_finding, now):
        _, decision = transition(
            pending_finding,
            State.CLOSURE_AWAITING_ANCHOR,
            actor=pending_finding.assessor,
            role="reviewer",
            expected_version=pending_finding.version,
            now=now,
        )
        assert R.INDEPENDENT_REVIEW_REQUIRED in decision.reasons

    def test_naive_time_is_refused(self, pending_finding):
        from datetime import datetime

        _, decision = transition(
            pending_finding,
            State.CLOSED,
            actor="reviewer.esi",
            role="reviewer",
            expected_version=pending_finding.version,
            now=datetime(2026, 10, 12),
        )
        assert R.UTC_AWARE_TIME_REQUIRED in decision.reasons

    def test_recurrence_is_not_reachable_as_an_ordinary_transition(self):
        """U05 makes a repeat sighting an event, not a state change.

        Reopened is therefore reachable only from Closed -- no unresolved state
        may transition into it, because doing so would discard the work state
        that recurrence is supposed to preserve.
        """
        sources = {
            source for source, targets in ALLOWED_TRANSITIONS.items() if State.REOPENED in targets
        }
        assert sources == {State.CLOSED}


class TestRecurrence:
    def test_a_repeat_sighting_preserves_the_current_work_state(self, pending_finding):
        repeated, event = observe(pending_finding, "obs-8")
        assert event == "repeated"
        assert repeated.state is pending_finding.state
        assert repeated.observation_watermark == "obs-8"
        assert repeated.version == pending_finding.version + 1

    def test_a_sighting_after_closure_reopens(self, pending_finding):
        closed = replace(pending_finding, state=State.CLOSED)
        reopened, event = observe(closed, "obs-9")
        assert event == "reopened"
        assert reopened.state is State.REOPENED
        assert reopened.reopened_count == 1

    def test_a_reopen_clears_the_prior_assignment_and_fix(self, pending_finding):
        """Reopened requires fresh assignment and review."""
        closed = replace(pending_finding, state=State.CLOSED)
        reopened, _ = observe(closed, "obs-9")
        assert reopened.remediation_owner == ""
        assert reopened.fixed_revision == ""
        assert reopened.fixed_at is None

    @pytest.mark.parametrize(
        "state",
        [
            State.CONFIRMED,
            State.ASSIGNED,
            State.REMEDIATING,
            State.VERIFICATION_PENDING,
            State.REOPENED,
        ],
    )
    def test_recurrence_in_any_unresolved_state_only_repeats(self, pending_finding, state):
        repeated, event = observe(replace(pending_finding, state=state), "obs-10")
        assert event == "repeated"
        assert repeated.state is state

    def test_repeated_reopens_accumulate(self, pending_finding):
        finding = replace(pending_finding, state=State.CLOSED)
        first, _ = observe(finding, "obs-1")
        second, _ = observe(replace(first, state=State.CLOSED), "obs-2")
        assert second.reopened_count == 2


class TestDispositions:
    def test_an_accepted_risk_does_not_change_the_work_state(self, pending_finding, now):
        """Risk acceptance is not a verified fix; the work state is untouched."""
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        updated, decision = record_disposition(
            confirmed,
            exception_for(confirmed, now),
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        assert decision.allowed, decision.reasons
        assert updated.state is State.CONFIRMED
        assert updated.disposition is Disposition.RISK_ACCEPTED

    def test_an_accepted_finding_still_counts_as_unresolved_exposure(self, pending_finding, now):
        """C03's rule, enforced on the finding itself."""
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        updated, _ = record_disposition(
            confirmed,
            exception_for(confirmed, now),
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        assert updated.is_unresolved_exposure

    @pytest.mark.parametrize("disposition", [Disposition.RISK_ACCEPTED, Disposition.SUPPRESSED])
    def test_accepted_and_suppressed_both_remain_exposure(self, pending_finding, now, disposition):
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        updated, _ = record_disposition(
            confirmed,
            exception_for(confirmed, now, disposition=disposition),
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        assert updated.is_unresolved_exposure

    def test_a_validated_false_positive_is_not_exposure(self, pending_finding):
        corrected = replace(
            pending_finding,
            state=State.CONFIRMED,
            disposition=Disposition.FALSE_POSITIVE,
        )
        assert not corrected.is_unresolved_exposure

    def test_a_disposition_requires_reviewer_reason_and_evidence(self, pending_finding, now):
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        for missing in ("reviewer", "reason", "evidence_reference"):
            _, decision = record_disposition(
                confirmed,
                exception_for(confirmed, now, **{missing: ""}),
                actor_role="reviewer",
                expected_version=confirmed.version,
                now=now,
            )
            assert R.DISPOSITION_REVIEWER_REQUIRED in decision.reasons

    def test_only_a_reviewer_or_security_lead_may_record_one(self, pending_finding, now):
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        _, decision = record_disposition(
            confirmed,
            exception_for(confirmed, now),
            actor_role="remediation_owner",
            expected_version=confirmed.version,
            now=now,
        )
        assert R.ROLE_NOT_PERMITTED in decision.reasons

    def test_an_already_expired_exception_cannot_be_recorded(self, pending_finding, now):
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        _, decision = record_disposition(
            confirmed,
            exception_for(
                confirmed,
                now,
                created_at=now - timedelta(days=60),
                expires_at=now - timedelta(days=1),
            ),
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        assert R.DISPOSITION_EXPIRED in decision.reasons

    def test_a_new_observation_stays_visible_during_an_active_exception(self, pending_finding, now):
        """Spec Section 5: a new observation remains visible while an exception
        is active."""
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        accepted, _ = record_disposition(
            confirmed,
            exception_for(confirmed, now),
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        observed, event = observe(accepted, "obs-11")
        assert event == "repeated"
        assert observed.observation_watermark == "obs-11"
        assert observed.disposition is Disposition.RISK_ACCEPTED


class TestExpiry:
    def test_expiry_restores_the_previous_unresolved_state(self, pending_finding, now):
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        exception = exception_for(confirmed, now)
        accepted, _ = record_disposition(
            confirmed,
            exception,
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )

        later = now + timedelta(days=31)
        restored, decision = expire_disposition(accepted, exception, now=later)
        assert decision.allowed
        assert restored.disposition is None
        assert restored.exception_id == ""
        assert restored.state is State.CONFIRMED

    def test_expiry_demands_a_reassessment(self, pending_finding, now):
        """U06: expired exceptions trigger recalculation and visible escalation."""
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        exception = exception_for(confirmed, now)
        accepted, _ = record_disposition(
            confirmed,
            exception,
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        _, decision = expire_disposition(accepted, exception, now=now + timedelta(days=31))
        assert decision.detail["requires_reassessment"] is True

    def test_an_active_exception_is_not_expired(self, pending_finding, now):
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        exception = exception_for(confirmed, now)
        accepted, _ = record_disposition(
            confirmed,
            exception,
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        _, decision = expire_disposition(accepted, exception, now=now)
        assert R.DISPOSITION_EXPIRED in decision.reasons

    def test_expiring_the_wrong_exception_is_refused(self, pending_finding, now):
        confirmed = replace(pending_finding, state=State.CONFIRMED)
        exception = exception_for(confirmed, now)
        accepted, _ = record_disposition(
            confirmed,
            exception,
            actor_role="reviewer",
            expected_version=confirmed.version,
            now=now,
        )
        other = exception_for(
            confirmed,
            now,
            exception_id="exc-99",
            created_at=now - timedelta(days=60),
            expires_at=now - timedelta(days=1),
        )
        _, decision = expire_disposition(accepted, other, now=now)
        assert R.CONCURRENT_MODIFICATION in decision.reasons


class TestStateSemantics:
    def test_only_closed_is_resolved(self):
        resolved = [state for state in State if state.is_resolved]
        assert resolved == [State.CLOSED]

    def test_awaiting_anchor_is_not_resolved(self):
        """C01's substate must stay out of C03's numerator."""
        assert not State.CLOSURE_AWAITING_ANCHOR.is_resolved

    def test_new_is_not_in_the_confirmed_cohort(self):
        assert not State.NEW.is_confirmed
        for state in State:
            if state is not State.NEW:
                assert state.is_confirmed

    def test_high_severity_requires_an_anchor(self, pending_finding):
        assert pending_finding.requires_anchor
        assert not replace(pending_finding, severity_score=6.9).requires_anchor
        assert replace(pending_finding, severity_score=7.0).requires_anchor
