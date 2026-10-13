"""U01 -- authorization revalidation and execution grants.

Acceptance evidence named in the traceability table: "Revoked and stale jobs
denied".
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from conftest import ORG, OTHER_ORG, PROFILE, TARGET

from seal.core import reasons as R
from seal.core._canonical import digest
from seal.core.authorization import (
    Checkpoint,
    ExecutionGrant,
    JobRequest,
    PolicyState,
    RequestBudget,
    authorize,
    validate_grant,
)


def check(authorization, job_request, policy_state, now, checkpoint=Checkpoint.DISPATCH):
    return authorize(authorization, job_request, policy_state, checkpoint=checkpoint, now=now)


class TestEveryCheckpoint:
    @pytest.mark.parametrize("checkpoint", list(Checkpoint))
    def test_valid_authorization_passes_at_each_checkpoint(
        self, authorization, job_request, policy_state, now, checkpoint
    ):
        decision = check(authorization, job_request, policy_state, now, checkpoint)
        assert decision.allowed, decision.reasons
        assert decision.detail["checkpoint"] == checkpoint.value

    @pytest.mark.parametrize("checkpoint", list(Checkpoint))
    def test_revocation_denies_at_each_checkpoint(
        self, authorization, job_request, policy_state, now, checkpoint
    ):
        """Revocation invalidates queued work and active leases, not just new jobs."""
        revoked = replace(policy_state, revoked=True)
        decision = check(authorization, job_request, revoked, now, checkpoint)
        assert not decision.allowed
        assert R.AUTHORIZATION_REVOKED in decision.reasons


class TestFailsClosed:
    def test_unavailable_policy_service_denies(self, authorization, job_request, now):
        """Loss of the policy service fails closed (spec Section 3)."""
        decision = check(authorization, job_request, PolicyState.unavailable(observed_at=now), now)
        assert not decision.allowed
        assert R.POLICY_STATE_UNAVAILABLE in decision.reasons

    def test_stale_revocation_state_denies(self, authorization, job_request, policy_state, now):
        """Current revocation information must be fresh, not merely present."""
        stale = replace(policy_state, observed_at=now - timedelta(minutes=5))
        decision = check(authorization, job_request, policy_state=stale, now=now)
        assert not decision.allowed
        assert R.REVOCATION_STATE_STALE in decision.reasons

    def test_future_dated_state_is_not_fresh(self, authorization, job_request, policy_state, now):
        future = replace(policy_state, observed_at=now + timedelta(minutes=1))
        decision = check(authorization, job_request, future, now)
        assert R.REVOCATION_STATE_STALE in decision.reasons

    def test_untrusted_integrity_denies_new_work(
        self, authorization, job_request, policy_state, now
    ):
        decision = check(
            authorization, job_request, replace(policy_state, integrity_trusted=False), now
        )
        assert R.INTEGRITY_UNTRUSTED in decision.reasons

    def test_active_stop_denies(self, authorization, job_request, policy_state, now):
        decision = check(authorization, job_request, replace(policy_state, stop_active=True), now)
        assert R.STOP_ACTIVE in decision.reasons

    def test_phase0_not_approved_denies(self, authorization, job_request, policy_state, now):
        """No flag in this package grants institutional authority (spec Section 3)."""
        decision = check(
            authorization, job_request, replace(policy_state, phase0_approved=False), now
        )
        assert R.PHASE0_NOT_APPROVED in decision.reasons


class TestStaleRevisions:
    def test_amendment_makes_a_queued_job_stale_not_more_permissive(
        self, authorization, job_request, policy_state, now
    ):
        """An amendment creates a new version; the queued entry does not inherit it."""
        amended = authorization.amend(allowed_methods=frozenset({"GET", "HEAD", "POST"}))
        current = replace(policy_state, authorization_revision=amended.revision)

        # The queue entry still references revision 1.
        decision = authorize(amended, job_request, current, checkpoint=Checkpoint.DISPATCH, now=now)
        assert not decision.allowed
        assert R.STALE_AUTHORIZATION in decision.reasons

    def test_amend_refuses_a_caller_supplied_revision(self, authorization):
        with pytest.raises(ValueError, match="assigned by amend"):
            authorization.amend(revision=99)

    def test_revoke_advances_the_revision(self, authorization):
        revoked = authorization.revoke()
        assert revoked.revoked is True
        assert revoked.revision == authorization.revision + 1


class TestTenantAndTargetBoundary:
    def test_organization_from_the_request_cannot_cross_tenants(
        self, authorization, policy_state, now
    ):
        """U09: organization comes from authenticated membership, not the caller."""
        foreign = JobRequest(
            organization=OTHER_ORG,
            target_id=TARGET,
            profile_digest=PROFILE,
            authorization_revision=1,
        )
        decision = check(authorization, foreign, policy_state, now)
        assert not decision.allowed
        assert R.MEMBERSHIP_REQUIRED in decision.reasons
        assert R.TENANT_MISMATCH in decision.reasons

    def test_target_mismatch_denies(self, authorization, policy_state, now):
        decision = check(
            authorization,
            JobRequest(ORG, "target-other", PROFILE, 1),
            policy_state,
            now,
        )
        assert R.TARGET_MISMATCH in decision.reasons

    def test_empty_target_is_ambiguous_and_denied(self, authorization, policy_state, now):
        decision = check(authorization, JobRequest(ORG, "", PROFILE, 1), policy_state, now)
        assert R.TARGET_MISMATCH in decision.reasons

    def test_profile_mismatch_denies(self, authorization, policy_state, now):
        decision = check(
            authorization,
            JobRequest(ORG, TARGET, digest({"profile": "active-web"}), 1),
            policy_state,
            now,
        )
        assert R.PROFILE_MISMATCH in decision.reasons


class TestWindowAndEvidence:
    def test_expired_window_denies(self, authorization, job_request, policy_state, now):
        decision = check(authorization, job_request, policy_state, now + timedelta(hours=5))
        assert R.OUTSIDE_WINDOW in decision.reasons

    def test_window_not_yet_open_denies(self, authorization, job_request, policy_state, now):
        decision = check(authorization, job_request, policy_state, now - timedelta(hours=2))
        assert R.OUTSIDE_WINDOW in decision.reasons

    def test_naive_now_is_refused_rather_than_interpreted(
        self, authorization, job_request, policy_state
    ):
        from datetime import datetime

        decision = check(authorization, job_request, policy_state, datetime(2026, 10, 12))
        assert R.UTC_AWARE_TIME_REQUIRED in decision.reasons

    def test_missing_ownership_evidence_denies(self, authorization, job_request, policy_state, now):
        decision = check(
            replace(authorization, ownership_evidence_digest="pending"),
            job_request,
            policy_state,
            now,
        )
        assert R.AUTHORIZATION_EVIDENCE_REQUIRED in decision.reasons

    def test_self_approval_denies(self, authorization, job_request, policy_state, now):
        """Separation of duties: the requester cannot be the approver."""
        decision = check(
            replace(authorization, approver=authorization.requester),
            job_request,
            policy_state,
            now,
        )
        assert R.INDEPENDENT_APPROVER_REQUIRED in decision.reasons

    def test_external_target_is_disabled(self, authorization, job_request, policy_state, now):
        """External targets remain unavailable until separate gates are satisfied."""
        decision = check(replace(authorization, owned_lab=False), job_request, policy_state, now)
        assert R.EXTERNAL_TARGET_DISABLED in decision.reasons

    def test_unauthorized_method_denies(self, authorization, job_request, policy_state, now):
        decision = check(authorization, replace(job_request, method="POST"), policy_state, now)
        assert R.METHOD_NOT_AUTHORIZED in decision.reasons


def test_every_failing_contract_is_reported_not_just_the_first(authorization, policy_state, now):
    """The scope screen must explain every denied condition before submission (U13)."""
    broken = authorize(
        replace(authorization, owned_lab=False, approver=authorization.requester),
        JobRequest(OTHER_ORG, "wrong-target", "wrong-profile", 99),
        replace(policy_state, phase0_approved=False),
        checkpoint=Checkpoint.QUEUE,
        now=now,
    )
    assert not broken.allowed
    assert len(broken.reasons) >= 6
    for expected in (
        R.PHASE0_NOT_APPROVED,
        R.EXTERNAL_TARGET_DISABLED,
        R.MEMBERSHIP_REQUIRED,
        R.TARGET_MISMATCH,
        R.PROFILE_MISMATCH,
        R.STALE_AUTHORIZATION,
        R.INDEPENDENT_APPROVER_REQUIRED,
    ):
        assert expected in broken.reasons


class TestExecutionGrants:
    def grant(self, now, **changes):
        base = {
            "grant_id": "grant-1",
            "organization": ORG,
            "job_id": "job-1",
            "target_id": TARGET,
            "profile_digest": PROFILE,
            "authorization_revision": 1,
            "destination": "10.10.0.5",
            "expires": now + timedelta(seconds=30),
            "integrity_generation": 7,
        }
        base.update(changes)
        return ExecutionGrant(**base)

    def test_valid_grant_passes_at_the_boundary(self, job_request, now):
        decision = validate_grant(
            self.grant(now),
            job_request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=7,
        )
        assert decision.allowed, decision.reasons

    def test_worker_minted_grant_is_refused(self, job_request, now):
        """Workers cannot mint or extend a grant (spec Section 3)."""
        decision = validate_grant(
            self.grant(now, issuer="worker-17"),
            job_request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=7,
        )
        assert R.GRANT_NOT_TRUSTED_ISSUER in decision.reasons

    def test_stale_generation_is_refused(self, job_request, now):
        """C02: a grant from before an integrity failure stops validating."""
        decision = validate_grant(
            self.grant(now),
            job_request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=8,
        )
        assert R.GRANT_GENERATION_STALE in decision.reasons

    def test_expired_grant_is_refused(self, job_request, now):
        decision = validate_grant(
            self.grant(now, expires=now - timedelta(seconds=1)),
            job_request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=7,
        )
        assert R.GRANT_EXPIRED in decision.reasons

    def test_destination_substitution_is_refused(self, job_request, now):
        decision = validate_grant(
            self.grant(now),
            job_request,
            destination="169.254.169.254",
            now=now,
            current_integrity_generation=7,
        )
        assert R.GRANT_BINDING_MISMATCH in decision.reasons

    def test_in_flight_ceiling_is_enforced(self, job_request, now):
        decision = validate_grant(
            self.grant(now, budget=RequestBudget(max_in_flight=1)),
            job_request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=7,
            in_flight=1,
        )
        assert R.CONCURRENCY_LIMIT_EXCEEDED in decision.reasons

    def test_request_budget_ceiling_is_enforced(self, job_request, now):
        decision = validate_grant(
            self.grant(now, budget=RequestBudget(max_requests=10)),
            job_request,
            destination="10.10.0.5",
            now=now,
            current_integrity_generation=7,
            requests_made=10,
        )
        assert R.GRANT_BUDGET_EXCEEDED in decision.reasons

    def test_binding_digest_changes_with_any_bound_field(self, now):
        base = self.grant(now)
        assert base.binding_digest != self.grant(now, job_id="job-2").binding_digest
        assert base.binding_digest != self.grant(now, destination="10.10.0.6").binding_digest
