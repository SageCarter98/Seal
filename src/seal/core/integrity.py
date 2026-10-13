"""C02 -- stop active assessment when integrity becomes unavailable.

This is the amendment that extends the existing denial of *new* jobs and
High/Critical closure to work *already running*. Spec C02: "Maintain an
integrity-admission state and generation at the independent egress boundary."

The generation is the mechanism. Nothing has to hunt down and cancel individual
grants or leases when trust is lost: the generation increments, and every
outstanding grant fails ``validate_grant`` on its next use because the
generation it carries no longer matches. A worker holding a cached approval
cannot continue.

Two measured ceilings, both provisional per C02 ("provisional measured
acceptance ceilings, not instantaneous-stop claims"):

* no new outbound request more than 5 seconds after detection;
* affected workers terminated within 30 seconds.

Already-transmitted requests cannot be recalled. ``StopOutcome`` records
residual exposure rather than pretending otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum

from . import reasons as R
from ._canonical import require_aware
from .coverage import CoverageStatus
from .decision import Decision, allow, deny, evaluate

#: C02's two acceptance ceilings.
EGRESS_STOP_BUDGET = timedelta(seconds=5)
WORKER_TERMINATION_BUDGET = timedelta(seconds=30)

#: How stale the boundary's own copy of integrity state may be. Beyond this the
#: boundary must treat trust as unavailable -- C02 lists "unavailable/stale
#: integrity or revocation state" as an Untrusted trigger in its own right.
MAX_INTEGRITY_STATE_AGE = timedelta(seconds=5)


class Admission(str, Enum):
    TRUSTED = "Trusted"
    UNTRUSTED = "Untrusted"


class Trigger(str, Enum):
    """The conditions C02 names as making admission Untrusted."""

    SIGNATURE_FAILURE = "signature_failure"
    CHAIN_MISMATCH = "chain_mismatch"
    AUDIT_APPEND_NOT_DURABLE = "audit_append_not_durable"
    ANCHOR_OVERDUE = "anchor_overdue"
    INTEGRITY_STATE_STALE = "integrity_state_stale"
    REVOCATION_STATE_STALE = "revocation_state_stale"


@dataclass(frozen=True)
class IntegrityState:
    """The admission state and generation, as the egress boundary holds it.

    ``observed_at`` matters as much as ``admission``: a stale Trusted reading is
    not a Trusted state. ``is_current`` folds that in, so a caller cannot
    accidentally honour a snapshot from a partitioned policy service.
    """

    admission: Admission
    generation: int
    observed_at: datetime
    trigger: Trigger | None = None
    detected_at: datetime | None = None
    #: Set by an authorized resume decision. Restarting a service is explicitly
    #: not enough (C02): "restarting a service does not restart scans".
    resume_authorized_by: str = ""

    @property
    def trusted(self) -> bool:
        return self.admission is Admission.TRUSTED

    def is_current(self, now: datetime, max_age: timedelta = MAX_INTEGRITY_STATE_AGE) -> bool:
        if require_aware(observed_at=self.observed_at, now=now):
            return False
        age = now - self.observed_at
        return timedelta(0) <= age <= max_age

    def is_trustworthy(self, now: datetime) -> bool:
        """Trusted *and* fresh. The only condition under which egress proceeds."""
        return self.trusted and self.is_current(now)


def detect(
    state: IntegrityState,
    *,
    trigger: Trigger,
    now: datetime,
) -> IntegrityState:
    """Transition to Untrusted, incrementing the generation.

    Incrementing on entry to Untrusted (rather than on resume) is what revokes
    outstanding grants immediately. If the generation only moved on resume,
    every grant minted before the failure would stay valid during the outage --
    exactly the window C02 exists to close.
    """
    if require_aware(now=now):
        raise ValueError(R.UTC_AWARE_TIME_REQUIRED)
    if not state.trusted:
        # Already Untrusted. Keep the first detection time: the measured stop
        # budget runs from when the condition was first detected, not from a
        # later re-detection.
        return state
    return IntegrityState(
        admission=Admission.UNTRUSTED,
        generation=state.generation + 1,
        observed_at=now,
        trigger=trigger,
        detected_at=now,
    )


def resume(
    state: IntegrityState,
    *,
    authorized_by: str,
    reconciled: bool,
    now: datetime,
) -> tuple[IntegrityState, Decision]:
    """Return to Trusted under an explicit authorized resume decision.

    Requires a named authority and a completed reconciliation of the emergency
    journal and external anchors -- C02: "Reconcile the journal and external
    anchors under assurance review before restoring trust." The generation
    increments again so grants minted during the outage cannot be revived.
    """
    if require_aware(now=now):
        return state, deny(R.UTC_AWARE_TIME_REQUIRED)
    if state.trusted:
        return state, deny(R.RESUME_NOT_AUTHORIZED, note="not stopped")
    if not authorized_by:
        return state, deny(R.RESUME_NOT_AUTHORIZED, note="named authority required")
    if not reconciled:
        return state, deny(R.RESUME_NOT_AUTHORIZED, note="reconciliation incomplete")

    resumed = IntegrityState(
        admission=Admission.TRUSTED,
        generation=state.generation + 1,
        observed_at=now,
        resume_authorized_by=authorized_by,
    )
    return resumed, allow(generation=resumed.generation, authorized_by=authorized_by)


@dataclass(frozen=True)
class Permit:
    """A bounded permit a worker may hold between integrity-state reads.

    C02 allows the boundary to consult "trusted state or a bounded permit whose
    expiry cannot exceed the stop budget". ``validate_permit`` enforces that
    ceiling, because a permit longer than the stop budget would let traffic
    continue past the 5-second limit on a cached approval.
    """

    permit_id: str
    job_id: str
    generation: int
    issued_at: datetime
    expires_at: datetime

    @property
    def lifetime(self) -> timedelta:
        return self.expires_at - self.issued_at


def validate_permit(
    permit: Permit,
    state: IntegrityState,
    *,
    now: datetime,
    budget: timedelta = EGRESS_STOP_BUDGET,
) -> Decision:
    """Whether a cached permit may still authorize an outbound request."""
    if require_aware(now=now, issued_at=permit.issued_at, expires_at=permit.expires_at):
        return deny(R.UTC_AWARE_TIME_REQUIRED)

    return evaluate(
        [
            (permit.lifetime <= budget, R.PERMIT_EXCEEDS_STOP_BUDGET),
            (now < permit.expires_at, R.GRANT_EXPIRED),
            (permit.generation == state.generation, R.GRANT_GENERATION_STALE),
            (state.trusted, R.INTEGRITY_UNTRUSTED),
        ],
        permit_id=permit.permit_id,
        job_id=permit.job_id,
        lifetime_seconds=permit.lifetime.total_seconds(),
    )


def admit_request(state: IntegrityState, *, now: datetime) -> Decision:
    """The egress boundary's check on every new outbound request, retry and renewal.

    Separate from ``validate_grant`` on purpose: C02 requires the boundary to
    deny "every new outbound request, retry and lease/grant renewal" on
    Untrusted, so this answers that question from integrity state alone and
    cannot be satisfied by a grant that merely looks well-formed.
    """
    if require_aware(now=now):
        return deny(R.UTC_AWARE_TIME_REQUIRED)
    return evaluate(
        [
            (state.trusted, R.INTEGRITY_UNTRUSTED),
            (state.is_current(now), R.INTEGRITY_STATE_STALE),
        ],
        generation=state.generation,
        trigger=state.trigger.value if state.trigger else None,
    )


@dataclass
class StopOutcome:
    """What a stop actually achieved, measured against C02's budgets.

    Records residual exposure explicitly. C02: "Already-transmitted requests
    cannot be recalled: abort open connections where possible, send no follow-up
    traffic and record residual exposure." A stop that reports success while
    leaving transmitted requests unrecorded would be the dishonest version of
    this.
    """

    detected_at: datetime
    jobs_stopped: tuple[str, ...] = ()
    last_egress_at: datetime | None = None
    workers_terminated_at: datetime | None = None
    requests_in_flight_at_detection: int = 0
    denied_renewals: int = 0
    denied_requests: int = 0
    journal_durable: bool = True
    coverage_marked: dict[str, CoverageStatus] = field(default_factory=dict)

    @property
    def egress_latency(self) -> timedelta | None:
        if self.last_egress_at is None:
            return None
        return self.last_egress_at - self.detected_at

    @property
    def termination_latency(self) -> timedelta | None:
        if self.workers_terminated_at is None:
            return None
        return self.workers_terminated_at - self.detected_at

    def meets_budgets(
        self,
        *,
        egress_budget: timedelta = EGRESS_STOP_BUDGET,
        termination_budget: timedelta = WORKER_TERMINATION_BUDGET,
    ) -> Decision:
        """Measure the stop against the ceilings. Stop enforcement itself does
        not depend on this passing -- C02: "Stop enforcement must not depend on
        successful journaling or anchoring." This is the measurement, not the
        control.
        """
        egress = self.egress_latency
        termination = self.termination_latency

        checks = [
            (egress is None or egress <= egress_budget, "EGRESS_STOP_BUDGET_EXCEEDED"),
            (
                termination is not None and termination <= termination_budget,
                "WORKER_TERMINATION_BUDGET_EXCEEDED",
            ),
            # No affected job may be left claiming Complete coverage.
            (
                all(
                    status is not CoverageStatus.COMPLETE
                    for status in self.coverage_marked.values()
                ),
                "STOPPED_JOB_MARKED_COMPLETE",
            ),
        ]
        return evaluate(
            checks,
            egress_latency_seconds=egress.total_seconds() if egress else None,
            termination_latency_seconds=termination.total_seconds() if termination else None,
            residual_exposure_requests=self.requests_in_flight_at_detection,
            journal_durable=self.journal_durable,
        )


def stop_coverage_status(*, had_failures: bool, any_completed: bool) -> CoverageStatus:
    """The coverage status an interrupted job must be marked with.

    C02: affected coverage is "Stopped/Partial or Failed with the cause, never
    Complete by default". ``COMPLETE`` is unreachable from this function by
    construction.
    """
    if had_failures:
        return CoverageStatus.FAILED
    if any_completed:
        return CoverageStatus.PARTIAL
    return CoverageStatus.STOPPED


def apply_stop(
    state: IntegrityState,
    *,
    active_jobs: dict[str, dict[str, bool]],
    detected_at: datetime,
    last_egress_at: datetime | None,
    workers_terminated_at: datetime | None,
    requests_in_flight: int = 0,
    journal_durable: bool = True,
) -> StopOutcome:
    """Build the stop outcome for a set of active jobs.

    ``active_jobs`` maps job id to ``{"had_failures": bool, "any_completed": bool}``.
    Every job gets a non-Complete coverage status, and the residual exposure
    from requests already in flight is carried through rather than dropped.
    """
    if state.trusted:
        raise ValueError("apply_stop is only meaningful once admission is Untrusted")

    return StopOutcome(
        detected_at=detected_at,
        jobs_stopped=tuple(sorted(active_jobs)),
        last_egress_at=last_egress_at,
        workers_terminated_at=workers_terminated_at,
        requests_in_flight_at_detection=requests_in_flight,
        denied_renewals=len(active_jobs),
        journal_durable=journal_durable,
        coverage_marked={
            job_id: stop_coverage_status(
                had_failures=facts.get("had_failures", False),
                any_completed=facts.get("any_completed", False),
            )
            for job_id, facts in active_jobs.items()
        },
    )


def replace_state(state: IntegrityState, **changes: object) -> IntegrityState:
    """Refresh an integrity snapshot's observation time without changing trust."""
    return replace(state, **changes)
