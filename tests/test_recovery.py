"""U12 -- recovery without duplicate or unauthorized execution.

Spec Section 8: "Queue messages carry an idempotency key and lease generation.
Only one current lease may execute a job. A retry rechecks authorization,
revocation, profile, stop state and remaining budget; **it does not replay a
prior HTTP request automatically**. Persist checkpoints without credentials or
raw private responses. A stopped job remains stopped across restarts."

F06's acceptance evidence restates it as four properties, and they are the four
test classes below: "Duplicate delivery does not duplicate unauthorized work;
cancellation is not undone by retry; restart requires renewed scope check; stop
timings measured."

Note what is absent from the module under test: there is no ``replay`` function.
A retry is a *fresh decision requiring all five rechecks*, not a reissue of a
recorded request, so the automatic replay spec Section 8 forbids has no
implementation to call.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from conftest import ORG, OTHER_ORG

from seal.core import reasons as R
from seal.core.recovery import (
    FAILED_WORKER_DETECTION_TARGET,
    QUEUE_RECOVERY_TARGET,
    SAFE_FAIL_DECISION_TARGET,
    DeliveryLog,
    Lease,
    QueueMessage,
    RetryContext,
    acquire_lease,
    admit_delivery,
    checkpoint_is_safe,
    may_retry,
    recovery_within_targets,
)


@pytest.fixture
def message(now) -> QueueMessage:
    return QueueMessage(
        message_id="msg-1",
        idempotency_key="job-1:attempt-scope-v1",
        job_id="job-1",
        organization=ORG,
        lease_generation=3,
        attempt=1,
        enqueued_at=now,
    )


@pytest.fixture
def lease(now) -> Lease:
    return Lease(
        lease_id="lease-1",
        job_id="job-1",
        organization=ORG,
        generation=3,
        holder="worker-7",
        acquired_at=now,
        expires_at=now + timedelta(minutes=5),
    )


@pytest.fixture
def retry_context() -> RetryContext:
    """All five rechecks passing. Tests fail them one at a time."""
    return RetryContext(
        authorization_valid=True,
        revoked=False,
        profile_unchanged=True,
        stop_active=False,
        remaining_request_budget=100,
    )


class TestDuplicateDelivery:
    """Duplicate delivery does not duplicate unauthorized work."""

    def test_a_first_delivery_is_admitted(self, message):
        log = DeliveryLog()
        decision = admit_delivery(message, log)
        assert decision.allowed, decision.reasons

    def test_a_redelivered_message_is_refused(self, message):
        log = DeliveryLog()
        admit_delivery(message, log)
        decision = admit_delivery(message, log)
        assert not decision.allowed
        assert R.DUPLICATE_DELIVERY in decision.reasons

    def test_redelivery_under_a_new_message_id_is_still_refused(self, message):
        """At-least-once queues redeliver with a fresh envelope. The
        idempotency key, not the message id, is what must dedupe."""
        log = DeliveryLog()
        admit_delivery(message, log)
        decision = admit_delivery(replace(message, message_id="msg-2"), log)
        assert R.DUPLICATE_DELIVERY in decision.reasons

    def test_a_different_job_with_its_own_key_is_admitted(self, message):
        log = DeliveryLog()
        admit_delivery(message, log)
        other = replace(
            message,
            job_id="job-2",
            idempotency_key="job-2:attempt-scope-v1",
            message_id="msg-3",
        )
        assert admit_delivery(other, log).allowed

    def test_one_tenant_cannot_suppress_another_by_reusing_its_key(self, message):
        """Keys live in per-tenant namespaces, so a collision is impossible.

        Rejecting a cross-tenant collision instead would hand an attacker the
        very capability this guards against: burn a key in tenant A and tenant
        B's legitimate delivery gets refused. Isolation, not rejection.
        """
        log = DeliveryLog()
        admit_delivery(message, log)

        other_tenant = replace(message, organization=OTHER_ORG)
        decision = admit_delivery(other_tenant, log)
        assert decision.allowed, decision.reasons
        # Each tenant sees only its own key.
        assert log.has_seen(ORG, message.idempotency_key)
        assert log.has_seen(OTHER_ORG, message.idempotency_key)

    def test_a_delivery_with_no_organization_is_refused(self, message):
        """Tenant scoping is only sound if the tenant is actually present."""
        decision = admit_delivery(replace(message, organization=""), DeliveryLog())
        assert not decision.allowed
        assert R.CHAIN_TENANT_MISMATCH in decision.reasons

    def test_an_empty_idempotency_key_is_refused(self, message):
        log = DeliveryLog()
        decision = admit_delivery(replace(message, idempotency_key=""), log)
        assert R.IDEMPOTENCY_KEY_REQUIRED in decision.reasons

    def test_the_log_records_what_it_has_seen(self, message):
        log = DeliveryLog()
        admit_delivery(message, log)
        assert log.has_seen(ORG, message.idempotency_key)
        assert not log.has_seen(OTHER_ORG, message.idempotency_key)


class TestSingleCurrentLease:
    """Only one current lease may execute a job."""

    def test_acquiring_a_lease_when_none_is_held_succeeds(self, lease, now):
        decision = acquire_lease(current=None, requested=lease, now=now)
        assert decision.allowed, decision.reasons

    def test_a_second_concurrent_lease_is_refused(self, lease, now):
        contender = replace(lease, lease_id="lease-2", holder="worker-9", generation=3)
        decision = acquire_lease(current=lease, requested=contender, now=now)
        assert not decision.allowed
        assert R.LEASE_ALREADY_HELD in decision.reasons

    def test_a_stale_generation_cannot_take_the_lease(self, lease, now):
        """A worker resuming after a partition carries an older generation."""
        stale = replace(lease, lease_id="lease-3", holder="worker-old", generation=2)
        decision = acquire_lease(current=None, requested=stale, now=now, current_generation=3)
        assert R.LEASE_GENERATION_STALE in decision.reasons

    def test_an_expired_lease_can_be_taken_over(self, lease, now):
        """A failed worker's lease lapses, making the job executable again."""
        later = now + timedelta(seconds=1)
        expired = replace(lease, expires_at=now - timedelta(seconds=1))
        contender = replace(
            lease,
            lease_id="lease-4",
            holder="worker-9",
            acquired_at=later,
            expires_at=later + timedelta(minutes=5),
        )
        decision = acquire_lease(current=expired, requested=contender, now=later)
        assert decision.allowed, decision.reasons

    def test_a_contender_whose_own_window_has_passed_is_refused(self, lease, now):
        """Guards the construction that made the test above misleading."""
        already_stale = replace(
            lease, lease_id="lease-7", holder="worker-9", expires_at=now - timedelta(seconds=1)
        )
        decision = acquire_lease(
            current=None, requested=already_stale, now=now + timedelta(seconds=1)
        )
        assert R.GRANT_EXPIRED in decision.reasons

    def test_a_lease_for_another_job_cannot_be_acquired_against_this_one(self, lease, now):
        other_job = replace(lease, lease_id="lease-5", job_id="job-99")
        decision = acquire_lease(current=lease, requested=other_job, now=now)
        assert not decision.allowed

    def test_a_cross_tenant_lease_is_refused(self, lease, now):
        foreign = replace(lease, lease_id="lease-6", organization=OTHER_ORG)
        decision = acquire_lease(current=lease, requested=foreign, now=now)
        assert R.CHAIN_TENANT_MISMATCH in decision.reasons

    def test_a_lease_longer_than_its_expiry_is_not_current(self, lease, now):
        assert lease.is_current(now)
        assert not lease.is_current(now + timedelta(minutes=6))


class TestRetryRevalidation:
    """A retry rechecks all five conditions. Cancellation is not undone by retry."""

    def test_a_retry_with_every_check_passing_is_permitted(self, message, retry_context, now):
        decision = may_retry(message, retry_context, now=now)
        assert decision.allowed, decision.reasons

    def test_an_active_stop_denies_a_retry(self, message, retry_context, now):
        """Cancellation is not undone by retry -- the headline F06 property."""
        decision = may_retry(message, replace(retry_context, stop_active=True), now=now)
        assert not decision.allowed
        assert R.STOP_ACTIVE in decision.reasons

    def test_revocation_denies_a_retry(self, message, retry_context, now):
        decision = may_retry(message, replace(retry_context, revoked=True), now=now)
        assert R.AUTHORIZATION_REVOKED in decision.reasons

    def test_an_invalid_authorization_denies_a_retry(self, message, retry_context, now):
        decision = may_retry(message, replace(retry_context, authorization_valid=False), now=now)
        assert R.STALE_AUTHORIZATION in decision.reasons

    def test_a_changed_profile_denies_a_retry(self, message, retry_context, now):
        decision = may_retry(message, replace(retry_context, profile_unchanged=False), now=now)
        assert R.PROFILE_MISMATCH in decision.reasons

    def test_an_exhausted_budget_denies_a_retry(self, message, retry_context, now):
        decision = may_retry(message, replace(retry_context, remaining_request_budget=0), now=now)
        assert R.GRANT_BUDGET_EXCEEDED in decision.reasons

    def test_every_failing_check_is_reported_together(self, message, now):
        """The operator should see all five problems, not discover them serially."""
        broken = RetryContext(
            authorization_valid=False,
            revoked=True,
            profile_unchanged=False,
            stop_active=True,
            remaining_request_budget=0,
        )
        decision = may_retry(message, broken, now=now)
        for reason in (
            R.STALE_AUTHORIZATION,
            R.AUTHORIZATION_REVOKED,
            R.PROFILE_MISMATCH,
            R.STOP_ACTIVE,
            R.GRANT_BUDGET_EXCEEDED,
        ):
            assert reason in decision.reasons

    def test_exceeding_the_attempt_ceiling_denies_a_retry(self, message, retry_context, now):
        exhausted = replace(message, attempt=99)
        decision = may_retry(exhausted, retry_context, now=now)
        assert R.RETRY_LIMIT_EXCEEDED in decision.reasons

    def test_there_is_no_automatic_replay_function(self):
        """Spec Section 8 forbids replaying a prior HTTP request automatically,
        so no such capability exists to be called."""
        import seal.core.recovery as recovery

        for forbidden in ("replay", "replay_request", "resend", "reissue"):
            assert not hasattr(recovery, forbidden)


class TestStopSurvivesRestart:
    """A stopped job remains stopped across restarts."""

    def test_a_stopped_job_stays_denied_however_many_restarts_occur(
        self, message, retry_context, now
    ):
        stopped = replace(retry_context, stop_active=True)
        for restart in range(5):
            decision = may_retry(replace(message, attempt=restart + 1), stopped, now=now)
            assert R.STOP_ACTIVE in decision.reasons

    def test_a_fresh_lease_generation_does_not_clear_a_stop(self, message, retry_context, now):
        """Restarting the service raises the generation; the stop is unaffected."""
        stopped = replace(retry_context, stop_active=True)
        decision = may_retry(replace(message, lease_generation=99), stopped, now=now)
        assert R.STOP_ACTIVE in decision.reasons


class TestCheckpointSafety:
    """Persist checkpoints without credentials or raw private responses."""

    def test_a_clean_checkpoint_is_accepted(self):
        decision = checkpoint_is_safe(
            {"job_id": "job-1", "requests_made": 12, "last_path": "/app/users"}
        )
        assert decision.allowed, decision.reasons

    @pytest.mark.parametrize(
        "field_name",
        [
            "password",
            "api_key",
            "token",
            "secret",
            "authorization",
            "cookie",
            "session_id",
            "private_key",
            "bearer_token",
            "credentials",
        ],
    )
    def test_a_credential_bearing_field_is_refused(self, field_name):
        decision = checkpoint_is_safe({"job_id": "job-1", field_name: "whatever"})
        assert not decision.allowed
        assert R.CHECKPOINT_CONTAINS_CREDENTIAL in decision.reasons

    def test_field_name_matching_is_case_insensitive(self):
        decision = checkpoint_is_safe({"Authorization": "Bearer abc"})
        assert R.CHECKPOINT_CONTAINS_CREDENTIAL in decision.reasons

    def test_a_credential_field_nested_in_the_checkpoint_is_refused(self):
        """A nested dict is the obvious way a header map sneaks in."""
        decision = checkpoint_is_safe(
            {"job_id": "job-1", "request": {"headers": {"cookie": "sid=abc"}}}
        )
        assert R.CHECKPOINT_CONTAINS_CREDENTIAL in decision.reasons

    @pytest.mark.parametrize("field_name", ["response_body", "raw_response", "body", "content"])
    def test_a_raw_response_field_is_refused(self, field_name):
        decision = checkpoint_is_safe({"job_id": "job-1", field_name: "<html>..."})
        assert R.CHECKPOINT_CONTAINS_RAW_RESPONSE in decision.reasons

    def test_an_oversized_checkpoint_is_refused(self):
        """A checkpoint is progress state, not a place to park a payload."""
        decision = checkpoint_is_safe({"job_id": "job-1", "note": "x" * 100_000})
        assert R.CHECKPOINT_TOO_LARGE in decision.reasons

    def test_a_non_dict_checkpoint_is_refused(self):
        for bad in ("a string", 42, None, ["a", "list"]):
            assert not checkpoint_is_safe(bad).allowed


class TestRecoveryTargets:
    def test_the_targets_are_the_values_v1_3_recorded(self):
        assert FAILED_WORKER_DETECTION_TARGET == timedelta(seconds=30)
        assert SAFE_FAIL_DECISION_TARGET == timedelta(minutes=5)
        assert QUEUE_RECOVERY_TARGET == timedelta(minutes=15)

    def test_a_recovery_inside_every_target_passes(self):
        decision = recovery_within_targets(
            worker_detection=timedelta(seconds=20),
            fail_decision=timedelta(minutes=3),
            queue_recovery=timedelta(minutes=10),
        )
        assert decision.allowed, decision.reasons

    def test_slow_worker_detection_fails_its_target(self):
        decision = recovery_within_targets(
            worker_detection=timedelta(seconds=45),
            fail_decision=timedelta(minutes=3),
            queue_recovery=timedelta(minutes=10),
        )
        assert R.WORKER_DETECTION_TARGET_EXCEEDED in decision.reasons

    def test_slow_queue_recovery_fails_its_target(self):
        decision = recovery_within_targets(
            worker_detection=timedelta(seconds=20),
            fail_decision=timedelta(minutes=3),
            queue_recovery=timedelta(minutes=30),
        )
        assert R.QUEUE_RECOVERY_TARGET_EXCEEDED in decision.reasons

    def test_a_missing_measurement_is_not_a_pass(self):
        """An unmeasured target is unverified, never satisfied by default."""
        decision = recovery_within_targets(
            worker_detection=None,
            fail_decision=timedelta(minutes=3),
            queue_recovery=timedelta(minutes=10),
        )
        assert not decision.allowed
        assert R.MEASUREMENT_MISSING in decision.reasons

    def test_the_decision_carries_the_measurements_it_judged(self):
        decision = recovery_within_targets(
            worker_detection=timedelta(seconds=20),
            fail_decision=timedelta(minutes=3),
            queue_recovery=timedelta(minutes=10),
        )
        assert decision.detail["worker_detection_seconds"] == 20.0
        assert decision.detail["queue_recovery_seconds"] == 600.0
