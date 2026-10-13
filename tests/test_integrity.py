"""C02 -- stop active assessment when integrity becomes unavailable.

C02's four named acceptance scenarios:

* **C02-A** with ten active lab jobs, inject each Untrusted trigger and measure
  egress requests, renewal/retry denials and termination against five/thirty
  seconds.
* **C02-B** partition worker, policy or integrity state: cached grants expire
  within budget and direct egress stays denied.
* **C02-C** restore services with queued retries: jobs stay stopped until
  explicit resume and renewed checks.
* **C02-D** lose both sink and primary audit path: stop still works, no
  undurable acknowledgment, emergency records reconcile.

C02 itself says "acceptance awaits runtime evidence" -- the timing assertions
here check the *budget arithmetic* against synthetic measurements, not a
measured system.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from seal.core import reasons as R
from seal.core.authorization import ExecutionGrant, JobRequest, validate_grant
from seal.core.coverage import CoverageStatus
from seal.core.integrity import (
    EGRESS_STOP_BUDGET,
    MAX_INTEGRITY_STATE_AGE,
    WORKER_TERMINATION_BUDGET,
    Admission,
    IntegrityState,
    Permit,
    Trigger,
    admit_request,
    apply_stop,
    detect,
    resume,
    stop_coverage_status,
    validate_permit,
)

#: C02-A's ten active laboratory jobs.
TEN_JOBS = {
    f"job-{index}": {"had_failures": False, "any_completed": index % 2 == 0}
    for index in range(1, 11)
}


class TestAdmissionState:
    def test_a_trusted_fresh_state_admits_requests(self, trusted_integrity, now):
        assert admit_request(trusted_integrity, now=now).allowed

    @pytest.mark.parametrize("trigger", list(Trigger))
    def test_every_trigger_makes_admission_untrusted(self, trusted_integrity, now, trigger):
        """C02-A: inject each Untrusted trigger."""
        stopped = detect(trusted_integrity, trigger=trigger, now=now)
        assert stopped.admission is Admission.UNTRUSTED
        assert stopped.trigger is trigger
        assert stopped.detected_at == now
        assert not admit_request(stopped, now=now).allowed

    def test_detection_increments_the_generation(self, trusted_integrity, now):
        """The generation is what revokes outstanding grants without hunting them."""
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        assert stopped.generation == trusted_integrity.generation + 1

    def test_re_detection_preserves_the_first_detection_time(self, trusted_integrity, now):
        """The stop budget runs from first detection, not from a later re-check."""
        first = detect(trusted_integrity, trigger=Trigger.ANCHOR_OVERDUE, now=now)
        again = detect(first, trigger=Trigger.SIGNATURE_FAILURE, now=now + timedelta(seconds=9))
        assert again.detected_at == now
        assert again.generation == first.generation

    def test_a_stale_trusted_state_is_not_a_trusted_state(self, trusted_integrity, now):
        """C02 lists stale integrity state as an Untrusted trigger in its own right."""
        stale_at = now - MAX_INTEGRITY_STATE_AGE - timedelta(seconds=1)
        stale = replace(trusted_integrity, observed_at=stale_at)
        decision = admit_request(stale, now=now)
        assert not decision.allowed
        assert R.INTEGRITY_STATE_STALE in decision.reasons
        assert stale.is_trustworthy(now) is False

    def test_a_future_dated_state_is_not_current(self, trusted_integrity, now):
        future = replace(trusted_integrity, observed_at=now + timedelta(seconds=10))
        assert not admit_request(future, now=now).allowed

    def test_naive_time_is_refused(self, trusted_integrity):
        from datetime import datetime

        assert (
            R.UTC_AWARE_TIME_REQUIRED
            in admit_request(trusted_integrity, now=datetime(2026, 10, 12)).reasons
        )

    def test_detect_refuses_naive_time(self, trusted_integrity):
        from datetime import datetime

        with pytest.raises(ValueError):
            detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=datetime(2026, 1, 1))


class TestC02A:
    """Ten active jobs, each trigger, measured against five and thirty seconds."""

    def stop(self, state, now, *, egress_offset, termination_offset, **extra):
        return apply_stop(
            state,
            active_jobs=TEN_JOBS,
            detected_at=now,
            last_egress_at=now + egress_offset,
            workers_terminated_at=now + termination_offset,
            **extra,
        )

    def test_a_stop_inside_both_budgets_passes(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        outcome = self.stop(
            stopped,
            now,
            egress_offset=timedelta(seconds=3),
            termination_offset=timedelta(seconds=22),
        )
        assert len(outcome.jobs_stopped) == 10
        assert outcome.meets_budgets().allowed

    def test_egress_after_five_seconds_fails_the_budget(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.ANCHOR_OVERDUE, now=now)
        outcome = self.stop(
            stopped,
            now,
            egress_offset=timedelta(seconds=6),
            termination_offset=timedelta(seconds=20),
        )
        decision = outcome.meets_budgets()
        assert not decision.allowed
        assert "EGRESS_STOP_BUDGET_EXCEEDED" in decision.reasons
        assert decision.detail["egress_latency_seconds"] == 6.0

    def test_termination_after_thirty_seconds_fails_the_budget(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.SIGNATURE_FAILURE, now=now)
        outcome = self.stop(
            stopped,
            now,
            egress_offset=timedelta(seconds=2),
            termination_offset=timedelta(seconds=31),
        )
        decision = outcome.meets_budgets()
        assert "WORKER_TERMINATION_BUDGET_EXCEEDED" in decision.reasons

    def test_workers_never_terminated_fails_the_budget(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        outcome = apply_stop(
            stopped,
            active_jobs=TEN_JOBS,
            detected_at=now,
            last_egress_at=now + timedelta(seconds=1),
            workers_terminated_at=None,
        )
        assert "WORKER_TERMINATION_BUDGET_EXCEEDED" in outcome.meets_budgets().reasons

    def test_no_stopped_job_is_left_claiming_complete_coverage(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        outcome = self.stop(
            stopped,
            now,
            egress_offset=timedelta(seconds=1),
            termination_offset=timedelta(seconds=5),
        )
        assert set(outcome.coverage_marked) == set(TEN_JOBS)
        assert CoverageStatus.COMPLETE not in outcome.coverage_marked.values()

    def test_residual_exposure_from_transmitted_requests_is_recorded(self, trusted_integrity, now):
        """Already-transmitted requests cannot be recalled -- so they are reported."""
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        outcome = self.stop(
            stopped,
            now,
            egress_offset=timedelta(seconds=1),
            termination_offset=timedelta(seconds=4),
            requests_in_flight=3,
        )
        decision = outcome.meets_budgets()
        assert decision.detail["residual_exposure_requests"] == 3

    def test_every_active_job_counts_as_a_denied_renewal(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        outcome = self.stop(
            stopped,
            now,
            egress_offset=timedelta(seconds=1),
            termination_offset=timedelta(seconds=4),
        )
        assert outcome.denied_renewals == 10

    def test_apply_stop_refuses_a_trusted_state(self, trusted_integrity, now):
        with pytest.raises(ValueError, match="Untrusted"):
            apply_stop(
                trusted_integrity,
                active_jobs=TEN_JOBS,
                detected_at=now,
                last_egress_at=now,
                workers_terminated_at=now,
            )


class TestC02B:
    """Partitioned state: cached grants expire within budget, egress stays denied."""

    def permit(self, now, *, generation=7, lifetime=EGRESS_STOP_BUDGET):
        return Permit(
            permit_id="permit-1",
            job_id="job-1",
            generation=generation,
            issued_at=now,
            expires_at=now + lifetime,
        )

    def test_a_permit_within_the_stop_budget_is_valid_while_trusted(self, trusted_integrity, now):
        assert validate_permit(self.permit(now), trusted_integrity, now=now).allowed

    def test_a_permit_longer_than_the_stop_budget_is_refused(self, trusted_integrity, now):
        """A cached approval must not outlive the five-second stop ceiling."""
        decision = validate_permit(
            self.permit(now, lifetime=timedelta(seconds=30)), trusted_integrity, now=now
        )
        assert R.PERMIT_EXCEEDS_STOP_BUDGET in decision.reasons

    def test_a_cached_permit_expires_within_the_budget(self, trusted_integrity, now):
        decision = validate_permit(
            self.permit(now), trusted_integrity, now=now + EGRESS_STOP_BUDGET
        )
        assert R.GRANT_EXPIRED in decision.reasons

    def test_a_permit_from_before_the_failure_stops_validating(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.INTEGRITY_STATE_STALE, now=now)
        decision = validate_permit(self.permit(now), stopped, now=now)
        assert R.GRANT_GENERATION_STALE in decision.reasons
        assert R.INTEGRITY_UNTRUSTED in decision.reasons

    def test_an_outstanding_grant_fails_after_detection_without_being_revoked(
        self, trusted_integrity, now
    ):
        """The generation mechanism: no grant has to be found and deleted."""
        grant = ExecutionGrant(
            grant_id="grant-1",
            organization="org-lab-1",
            job_id="job-1",
            target_id="target-lab-web-1",
            profile_digest="p",
            authorization_revision=1,
            destination="10.10.0.5",
            expires=now + timedelta(seconds=30),
            integrity_generation=trusted_integrity.generation,
        )
        request = JobRequest("org-lab-1", "target-lab-web-1", "p", 1, job_id="job-1")

        before = validate_grant(
            grant,
            request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=trusted_integrity.generation,
        )
        assert before.allowed

        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        after = validate_grant(
            grant,
            request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=stopped.generation,
        )
        assert R.GRANT_GENERATION_STALE in after.reasons

    def test_direct_egress_stays_denied_while_untrusted(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.REVOCATION_STATE_STALE, now=now)
        for offset in (0, 1, 60, 3600):
            decision = admit_request(
                replace(stopped, observed_at=now + timedelta(seconds=offset)),
                now=now + timedelta(seconds=offset),
            )
            assert R.INTEGRITY_UNTRUSTED in decision.reasons


class TestC02C:
    """Restore services with queued retries: jobs stay stopped until resume."""

    def test_restarting_a_service_does_not_restart_scans(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        # A "restart" that merely refreshes the observation time changes nothing.
        refreshed = replace(stopped, observed_at=now + timedelta(seconds=60))
        decision = admit_request(refreshed, now=now + timedelta(seconds=60))
        assert R.INTEGRITY_UNTRUSTED in decision.reasons

    def test_resume_requires_a_named_authority(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        state, decision = resume(stopped, authorized_by="", reconciled=True, now=now)
        assert R.RESUME_NOT_AUTHORIZED in decision.reasons
        assert state.admission is Admission.UNTRUSTED

    def test_resume_requires_completed_reconciliation(self, trusted_integrity, now):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        state, decision = resume(stopped, authorized_by="assurance.lead", reconciled=False, now=now)
        assert R.RESUME_NOT_AUTHORIZED in decision.reasons
        assert state.admission is Admission.UNTRUSTED

    def test_an_authorized_reconciled_resume_restores_trust_with_a_new_generation(
        self, trusted_integrity, now
    ):
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        resumed, decision = resume(
            stopped, authorized_by="assurance.lead", reconciled=True, now=now
        )
        assert decision.allowed
        assert resumed.admission is Admission.TRUSTED
        assert resumed.generation == stopped.generation + 1
        assert resumed.resume_authorized_by == "assurance.lead"

    def test_grants_minted_during_the_outage_cannot_be_revived_by_resume(
        self, trusted_integrity, now
    ):
        """Resume increments the generation again, so nothing stale comes back."""
        stopped = detect(trusted_integrity, trigger=Trigger.CHAIN_MISMATCH, now=now)
        outage_permit = Permit(
            permit_id="p-outage",
            job_id="job-1",
            generation=stopped.generation,
            issued_at=now,
            expires_at=now + EGRESS_STOP_BUDGET,
        )
        resumed, _ = resume(stopped, authorized_by="assurance.lead", reconciled=True, now=now)
        decision = validate_permit(outage_permit, resumed, now=now)
        assert R.GRANT_GENERATION_STALE in decision.reasons

    def test_resuming_a_state_that_was_never_stopped_is_refused(self, trusted_integrity, now):
        _, decision = resume(
            trusted_integrity, authorized_by="assurance.lead", reconciled=True, now=now
        )
        assert R.RESUME_NOT_AUTHORIZED in decision.reasons


class TestC02D:
    """Lose both sink and primary audit path: stop still works."""

    def test_stop_enforcement_does_not_depend_on_durable_journaling(self, trusted_integrity, now):
        """C02: "Stop enforcement must not depend on successful journaling"."""
        stopped = detect(trusted_integrity, trigger=Trigger.AUDIT_APPEND_NOT_DURABLE, now=now)
        assert not admit_request(stopped, now=now).allowed

        outcome = apply_stop(
            stopped,
            active_jobs=TEN_JOBS,
            detected_at=now,
            last_egress_at=now + timedelta(seconds=2),
            workers_terminated_at=now + timedelta(seconds=10),
            journal_durable=False,
        )
        decision = outcome.meets_budgets()
        # The stop met its budgets even though journaling failed, and the
        # journal failure is reported rather than hidden.
        assert decision.allowed
        assert decision.detail["journal_durable"] is False

    def test_the_budgets_are_the_values_c02_names(self):
        assert EGRESS_STOP_BUDGET == timedelta(seconds=5)
        assert WORKER_TERMINATION_BUDGET == timedelta(seconds=30)


class TestStoppedCoverage:
    @pytest.mark.parametrize(
        ("had_failures", "any_completed", "expected"),
        [
            (True, True, CoverageStatus.FAILED),
            (True, False, CoverageStatus.FAILED),
            (False, True, CoverageStatus.PARTIAL),
            (False, False, CoverageStatus.STOPPED),
        ],
    )
    def test_complete_is_unreachable_for_an_interrupted_job(
        self, had_failures, any_completed, expected
    ):
        assert (
            stop_coverage_status(had_failures=had_failures, any_completed=any_completed) is expected
        )

    def test_no_input_combination_yields_complete(self):
        for had_failures in (True, False):
            for any_completed in (True, False):
                assert (
                    stop_coverage_status(had_failures=had_failures, any_completed=any_completed)
                    is not CoverageStatus.COMPLETE
                )


def test_integrity_state_trustworthiness_requires_both_trust_and_freshness(now):
    fresh_trusted = IntegrityState(Admission.TRUSTED, 1, now)
    assert fresh_trusted.is_trustworthy(now)

    stale_trusted = IntegrityState(
        Admission.TRUSTED, 1, now - MAX_INTEGRITY_STATE_AGE - timedelta(seconds=1)
    )
    assert not stale_trusted.is_trustworthy(now)

    fresh_untrusted = IntegrityState(Admission.UNTRUSTED, 2, now)
    assert not fresh_untrusted.is_trustworthy(now)
