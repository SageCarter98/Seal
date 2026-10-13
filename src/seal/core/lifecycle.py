"""U05 -- finding lifecycle, separated from recurrence and exceptions.

Spec Section 5 keeps three things apart that a naive design collapses into one
"status" field:

* **work state** -- New, Confirmed, Assigned, Remediating, Verification pending,
  Closed, Reopened, plus the C01 anchor substate;
* **recurrence** -- an observation event, which preserves the current work
  state rather than replacing it;
* **disposition** -- Risk accepted, Suppressed and False positive, which are
  reviewed decisions and *not* verified fixes.

The gap this closes is the U05 consequence: if risk acceptance shares a "closed"
label, unfixed exposure disappears from reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum

from . import reasons as R
from ._canonical import is_aware
from .decision import Decision, allow, deny


class State(str, Enum):
    """The work states. ``CLOSURE_AWAITING_ANCHOR`` is C01's substate.

    Spec Section 5: High and Critical closure "enters a Closure awaiting anchor
    verification substate after proof review" and is only finalized Closed once
    an independently verified receipt binds it to the signed external chain.
    """

    NEW = "New"
    CONFIRMED = "Confirmed"
    ASSIGNED = "Assigned"
    REMEDIATING = "Remediating"
    VERIFICATION_PENDING = "Verification pending"
    CLOSURE_AWAITING_ANCHOR = "Closure awaiting anchor"
    CLOSED = "Closed"
    REOPENED = "Reopened"

    @property
    def is_resolved(self) -> bool:
        """Only a finalized closure counts as resolved.

        ``CLOSURE_AWAITING_ANCHOR`` is excluded on purpose: C03 requires it
        outside the verified-Closed numerator, so treating it as resolved here
        would corrupt the exposure measures downstream.
        """
        return self is State.CLOSED

    @property
    def is_confirmed(self) -> bool:
        """Whether the finding has entered the confirmed cohort (C03)."""
        return self is not State.NEW


class Disposition(str, Enum):
    """Reviewed dispositions. None of these is a verified fix."""

    RISK_ACCEPTED = "Risk accepted"
    SUPPRESSED = "Suppressed"
    FALSE_POSITIVE = "False positive"


#: Permitted work-state transitions. Recurrence is NOT in here -- it goes
#: through ``observe``, because U05 makes a repeat sighting an event that
#: preserves the current state rather than a transition to a new one.
ALLOWED_TRANSITIONS: dict[State, frozenset[State]] = {
    State.NEW: frozenset({State.CONFIRMED}),
    State.CONFIRMED: frozenset({State.ASSIGNED}),
    State.ASSIGNED: frozenset({State.REMEDIATING, State.CONFIRMED}),
    State.REMEDIATING: frozenset({State.VERIFICATION_PENDING, State.ASSIGNED}),
    State.VERIFICATION_PENDING: frozenset(
        {State.CLOSURE_AWAITING_ANCHOR, State.CLOSED, State.REMEDIATING}
    ),
    # A pending anchor can time out back to verification, or be finalized.
    State.CLOSURE_AWAITING_ANCHOR: frozenset({State.CLOSED, State.VERIFICATION_PENDING}),
    State.CLOSED: frozenset({State.REOPENED}),
    State.REOPENED: frozenset({State.ASSIGNED, State.CONFIRMED}),
}

#: Which role may drive which transition. W02's acceptance evidence is "every
#: transition checks role and organization", and separation of duties (U04)
#: means the owner who fixes cannot be the reviewer who closes.
TRANSITION_ROLES: dict[State, frozenset[str]] = {
    State.CONFIRMED: frozenset({"assessor", "security_lead"}),
    State.ASSIGNED: frozenset({"assessor", "security_lead", "manager"}),
    State.REMEDIATING: frozenset({"remediation_owner"}),
    State.VERIFICATION_PENDING: frozenset({"remediation_owner"}),
    State.CLOSURE_AWAITING_ANCHOR: frozenset({"reviewer"}),
    State.CLOSED: frozenset({"reviewer"}),
    State.REOPENED: frozenset({"reviewer", "security_lead", "system"}),
}


@dataclass(frozen=True)
class Exception_:
    """An expiring, reviewed exception. Named with a trailing underscore to
    avoid shadowing the builtin.

    Spec Section 5: "Record reason, evidence, reviewer, affected scope and
    expiry. On expiry, restore the previous unresolved state and reassess
    current priority." ``previous_state`` is stored for exactly that restore --
    expiry must not leave the finding in limbo.
    """

    exception_id: str
    finding_id: str
    disposition: Disposition
    reviewer: str
    reason: str
    evidence_reference: str
    affected_scope: str
    created_at: datetime
    expires_at: datetime
    previous_state: State

    def is_active(self, now: datetime) -> bool:
        return is_aware(now) and self.created_at <= now < self.expires_at


@dataclass(frozen=True)
class Finding:
    """A finding, with its work state and disposition on separate axes.

    ``version`` is the optimistic-concurrency counter. Spec Section 5 requires
    it "to prevent two reviewers overwriting each other's decisions", and C01
    additionally finalizes closure by compare-and-swap against it -- so every
    state change here increments it.
    """

    finding_id: str
    organization: str
    target_id: str
    fingerprint: str
    rule: str
    profile_digest: str
    state: State = State.NEW
    version: int = 1
    assessor: str = ""
    remediation_owner: str = ""
    severity_score: float = 0.0
    #: Revision of the artifact the owner says contains the fix (U04).
    fixed_revision: str = ""
    fixed_at: datetime | None = None
    #: Dispositions currently recorded. A finding can carry one at a time in
    #: practice, but the field is a tuple so history is not overwritten.
    disposition: Disposition | None = None
    exception_id: str = ""
    #: Observation watermark -- the latest observation admitted against this
    #: finding. C01 compares a closure intent against this.
    observation_watermark: str = ""
    reopened_count: int = 0

    @property
    def requires_anchor(self) -> bool:
        """High and Critical closure needs the external anchor receipt (C01)."""
        return self.severity_score >= 7.0

    @property
    def is_unresolved_exposure(self) -> bool:
        """Whether this finding still counts as unresolved exposure (C03).

        Accepted and suppressed findings return True. That is the whole point of
        C03: "An unresolved exposure count includes accepted and suppressed
        findings with separate visible disposition counts."
        """
        if self.disposition is Disposition.FALSE_POSITIVE:
            return False
        return not self.state.is_resolved


def transition(
    finding: Finding,
    to: State,
    *,
    actor: str,
    role: str,
    expected_version: int,
    now: datetime,
) -> tuple[Finding, Decision]:
    """Move a finding to a new work state under role and concurrency checks.

    ``expected_version`` is the version the caller read. A mismatch is
    ``CONCURRENT_MODIFICATION`` and the finding is returned unchanged -- the
    second reviewer has to re-read and decide again rather than overwrite.
    """
    if not is_aware(now):
        return finding, deny(R.UTC_AWARE_TIME_REQUIRED)
    if finding.version != expected_version:
        return finding, deny(
            R.CONCURRENT_MODIFICATION, expected=expected_version, actual=finding.version
        )
    if to not in ALLOWED_TRANSITIONS.get(finding.state, frozenset()):
        return finding, deny(
            R.TRANSITION_NOT_ALLOWED, **{"from": finding.state.value, "to": to.value}
        )
    if role not in TRANSITION_ROLES.get(to, frozenset()):
        return finding, deny(R.ROLE_NOT_PERMITTED, role=role, to=to.value)

    # Separation of duties: whoever owned the remediation cannot be the one who
    # records the closure decision (U04, and F02's acceptance evidence).
    if to in (State.CLOSED, State.CLOSURE_AWAITING_ANCHOR) and actor in (
        finding.remediation_owner,
        finding.assessor,
    ):
        return finding, deny(R.INDEPENDENT_REVIEW_REQUIRED, actor=actor)

    moved = replace(finding, state=to, version=finding.version + 1)
    return moved, allow(**{"from": finding.state.value, "to": to.value, "actor": actor})


def observe(finding: Finding, observation_id: str) -> tuple[Finding, str]:
    """Record a repeat sighting. Returns the finding and the event name.

    U05: "Repeated is an observation event that preserves the current work
    state. A matching observation after Closed creates Reopened with fresh
    assignment and review."

    Note that a sighting during an active exception still lands here and still
    advances the watermark -- spec Section 5 requires a new observation to
    remain visible even while an exception is active.
    """
    if finding.state is State.CLOSED:
        reopened = replace(
            finding,
            state=State.REOPENED,
            version=finding.version + 1,
            observation_watermark=observation_id,
            reopened_count=finding.reopened_count + 1,
            # Reopening requires fresh assignment and review, so the prior
            # owner and fix revision are cleared rather than carried over.
            remediation_owner="",
            fixed_revision="",
            fixed_at=None,
        )
        return reopened, "reopened"

    repeated = replace(finding, version=finding.version + 1, observation_watermark=observation_id)
    return repeated, "repeated"


def record_disposition(
    finding: Finding,
    exception: Exception_,
    *,
    actor_role: str,
    expected_version: int,
    now: datetime,
) -> tuple[Finding, Decision]:
    """Attach a reviewed disposition. Never changes the work state.

    The work state is left alone deliberately. A Risk accepted finding stays in
    whatever unresolved state it was in, so C03's denominator and the unresolved
    exposure count both keep seeing it.
    """
    if finding.version != expected_version:
        return finding, deny(R.CONCURRENT_MODIFICATION)
    if actor_role not in ("reviewer", "security_lead"):
        return finding, deny(R.ROLE_NOT_PERMITTED, role=actor_role)
    if not (exception.reviewer and exception.reason and exception.evidence_reference):
        return finding, deny(R.DISPOSITION_REVIEWER_REQUIRED)
    if not exception.is_active(now):
        return finding, deny(R.DISPOSITION_EXPIRED)

    updated = replace(
        finding,
        disposition=exception.disposition,
        exception_id=exception.exception_id,
        version=finding.version + 1,
    )
    return updated, allow(disposition=exception.disposition.value)


def expire_disposition(
    finding: Finding, exception: Exception_, *, now: datetime
) -> tuple[Finding, Decision]:
    """Clear an expired disposition and restore the previous unresolved state.

    Returns an allowed decision carrying ``requires_reassessment`` so the caller
    recalculates priority -- U06 requires expired exceptions to trigger
    recalculation and visible escalation.
    """
    if exception.is_active(now):
        return finding, deny(R.DISPOSITION_EXPIRED, reason="not yet expired")
    if finding.exception_id != exception.exception_id:
        return finding, deny(R.CONCURRENT_MODIFICATION)

    restored = replace(
        finding,
        disposition=None,
        exception_id="",
        state=exception.previous_state,
        version=finding.version + 1,
    )
    return restored, allow(
        restored_state=exception.previous_state.value, requires_reassessment=True
    )


@dataclass
class Cohort:
    """A declared set of findings for reporting. See ``metrics`` for the rules."""

    cohort_id: str
    organization: str
    declared_at: datetime
    period_start: datetime
    period_end: datetime
    scope: str
    findings: list[Finding] = field(default_factory=list)
    #: Predeclared correction rule allowing a validated false positive to leave
    #: the confirmed cohort (C03). Absent means it may not.
    false_positive_correction_rule: str = ""
    #: Findings a reviewer has actually corrected out of the cohort under that
    #: rule. The rule alone does not remove anything -- C03 permits a false
    #: positive to leave "only under the predeclared reviewed correction rule",
    #: so the review has to have happened and be recorded here.
    corrected_finding_ids: list[str] = field(default_factory=list)
