"""U11 -- the incident path for an active compromise found inside approved scope.

Spec Section 8: "An active-compromise signal halts assessment and persists the
stop state, detection time, limited evidence, custody and hold. Route to the
named coordinator and target-owner contacts in the authorization. Record
acknowledgement, containment decision and legal/CERT reporting decision. Do not
autonomously contact external parties without explicit delegated authority."

Most of this module is about what Seal must refuse to do.

**It cannot contact an external party on its own.** ``notification_plan`` splits
recipients into an internal list, which is routable, and an external list, which
is *prepared only*. A party moves to ``external_authorized`` solely when a named
human authority is recorded against it. There is no function here that sends
anything, and ``NotificationPlan`` has no ``sent`` field to set.

**It cannot determine a legal duty.** Spec Section 8 carries v1.3's
twenty-four-hour reporting clock forward as "a baseline legal-review
requirement" and is explicit: "This proposal makes no new determination of
Ghanaian law. Counsel must confirm applicable duties and deadlines. Pending
guidance must be visibly owned and escalated, never silently treated as
approval."

So ``DutyStatus`` starts ``UNDETERMINED``, which is distinct from ``NO_DUTY``;
a status carrying no named determiner collapses back to ``UNDETERMINED``; and
exceeding the clock reports the elapsed time without asserting a breach of a
duty nobody has established.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum

from . import reasons as R
from ._canonical import is_aware, require_aware
from .coverage import CoverageStatus
from .decision import Decision, allow, deny

#: Carried forward from v1.3 as a consideration pending counsel, never as a
#: deadline Seal established. See ``ReportingClock``.
REPORTING_CLOCK_CONSIDERATION = timedelta(hours=24)


class IncidentSignal(str, Enum):
    """What was observed. Only an active compromise forces an assessment halt."""

    ACTIVE_COMPROMISE = "active_compromise"
    SUSPECTED_SECRET_EXPOSURE = "suspected_secret_exposure"
    THIRD_PARTY_DATA_OBSERVED = "third_party_data_observed"
    OUT_OF_SCOPE_DISCOVERY = "out_of_scope_discovery"

    @property
    def forces_halt(self) -> bool:
        return self is IncidentSignal.ACTIVE_COMPROMISE


class ExternalParty(str, Enum):
    """Parties outside the authorization's agreed contact list.

    The target owner is deliberately absent: their emergency contacts are
    recorded on the authorization itself (U01) and are the agreed route, so they
    belong to the internal list and need no delegation.
    """

    CERT = "cert"
    REGULATOR = "regulator"
    LAW_ENFORCEMENT = "law_enforcement"


class ContainmentDecision(str, Enum):
    ISOLATE = "isolate"
    MONITOR = "monitor"
    HAND_TO_TARGET_OWNER = "hand_to_target_owner"
    NO_ACTION = "no_action"


class DutyStatus(str, Enum):
    """Whether a reporting duty exists.

    ``UNDETERMINED`` is the starting value and is *not* a synonym for
    ``NO_DUTY``. Collapsing the two is precisely the "silently treated as
    approval" failure spec Section 8 names.
    """

    UNDETERMINED = "Undetermined - pending counsel"
    DUTY_CONFIRMED = "Duty confirmed by counsel"
    NO_DUTY = "No duty, determined by counsel"


@dataclass(frozen=True)
class Incident:
    """The persisted incident record.

    Evidence is referenced, never inlined. U08 requires minimization at
    collection, and an incident record that embedded response bodies would
    become an unsanitized copy of the very material under hold.
    """

    incident_id: str
    organization: str
    target_id: str
    job_id: str
    signal: IncidentSignal
    detected_at: datetime
    coordinator: str
    target_owner_contacts: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    halted: bool
    coverage_status: CoverageStatus
    incident_hold: bool = True
    acknowledged_by: str = ""
    acknowledged_at: datetime | None = None
    containment: ContainmentDecision | None = None
    containment_decided_by: str = ""
    containment_reason: str = ""
    #: Party -> the named human authority who delegated contact with them.
    delegated_external_authority: dict[ExternalParty, str] = field(default_factory=dict)
    #: Party -> whether a decision was taken to report to them.
    reporting_decisions: dict[ExternalParty, bool] = field(default_factory=dict)
    reporting_duty: DutyStatus = DutyStatus.UNDETERMINED
    reporting_duty_determined_by: str = ""


def declare(
    *,
    signal: IncidentSignal,
    incident_id: str,
    organization: str,
    target_id: str,
    job_id: str,
    coordinator: str,
    target_owner_contacts: tuple[str, ...],
    evidence_refs: tuple[str, ...],
    detected_at: datetime,
) -> tuple[Incident, tuple[str, ...]]:
    """Open an incident. Returns the record and the actions the caller must take.

    Actions are returned rather than performed: this module decides, and the
    orchestrator acts. ``halt_assessment`` appears only for an active
    compromise, matching spec Section 8's wording.
    """
    if not coordinator:
        raise ValueError("an incident requires a named coordinator")
    if require_aware(detected_at=detected_at):
        raise ValueError("timezone-aware detection time required")

    halted = signal.forces_halt
    incident = Incident(
        incident_id=incident_id,
        organization=organization,
        target_id=target_id,
        job_id=job_id,
        signal=signal,
        detected_at=detected_at,
        coordinator=coordinator,
        target_owner_contacts=tuple(target_owner_contacts),
        evidence_refs=tuple(evidence_refs),
        halted=halted,
        # Never Complete: an assessment interrupted by an incident did not
        # finish, and one not interrupted was not assessed past this point.
        coverage_status=CoverageStatus.STOPPED if halted else CoverageStatus.PARTIAL,
        incident_hold=True,
    )

    actions = ["record_incident_hold", "notify_internal"]
    if halted:
        actions.insert(0, "halt_assessment")
    return incident, tuple(actions)


@dataclass(frozen=True)
class NotificationPlan:
    """Who may be told, split by whether Seal is permitted to tell them.

    There is no ``sent`` field. ``as_display`` reports an always-empty sent list
    so a dashboard cannot imply Seal notified anyone.
    """

    internal: tuple[str, ...]
    external_prepared: tuple[ExternalParty, ...]
    external_authorized: tuple[ExternalParty, ...]

    def as_display(self) -> dict[str, object]:
        return {
            "internal": list(self.internal),
            "prepared": [party.value for party in self.external_prepared],
            "authorized": [party.value for party in self.external_authorized],
            "sent": [],
            "note": "Seal prepares external notifications; it never sends them (U11)",
        }


def notification_plan(incident: Incident) -> NotificationPlan:
    """Build the routing plan from recorded contacts only.

    Nothing is inferred. The internal list is the named coordinator followed by
    the target-owner contacts carried on the authorization.
    """
    authorized = tuple(
        party for party in ExternalParty if incident.delegated_external_authority.get(party)
    )
    prepared = tuple(party for party in ExternalParty if party not in authorized)

    return NotificationPlan(
        internal=(incident.coordinator, *incident.target_owner_contacts),
        external_prepared=prepared,
        external_authorized=authorized,
    )


def may_contact_external(incident: Incident, party: ExternalParty) -> Decision:
    """Whether Seal may contact one external party.

    Denied unless a named authority is recorded for that specific party. A blank
    name is a missing authority, not a permissive one.
    """
    authority = incident.delegated_external_authority.get(party, "")
    if not authority:
        return deny(
            R.EXTERNAL_CONTACT_NOT_DELEGATED,
            party=party.value,
            note="a named human authority must delegate contact with this party",
        )
    return allow(party=party.value, authority=authority)


@dataclass(frozen=True)
class ReportingClock:
    """Elapsed time against the carried-forward consideration.

    Reports facts (how long it has been) without asserting a conclusion (that a
    deadline was missed), because the duty itself is counsel's determination.
    """

    duty: DutyStatus
    determined_by: str
    elapsed: timedelta
    consideration: timedelta
    detected_at: datetime

    @property
    def consideration_exceeded(self) -> bool:
        return self.elapsed > self.consideration

    @property
    def requires_escalation(self) -> bool:
        """An undetermined duty must be visibly owned and escalated."""
        return self.duty is DutyStatus.UNDETERMINED

    @property
    def owner_required(self) -> bool:
        return self.requires_escalation

    def as_display(self) -> dict[str, object]:
        return {
            "duty": self.duty.value,
            "determined_by": self.determined_by or None,
            "elapsed_hours": round(self.elapsed.total_seconds() / 3600, 2),
            "consideration_hours": self.consideration.total_seconds() / 3600,
            "consideration_exceeded": self.consideration_exceeded,
            # Seal did not establish this clock and cannot assert a breach of a
            # duty that counsel has not determined.
            "basis": (
                "v1.3 twenty-four-hour consideration carried forward as a "
                "legal-review requirement, pending counsel determination"
            ),
            "deadline_established_by_seal": False,
            "breach_asserted": False,
            "requires_escalation": self.requires_escalation,
        }


def reporting_clock(incident: Incident, *, now: datetime) -> ReportingClock:
    """Evaluate the reporting clock for an incident.

    A duty status with no named determiner collapses to ``UNDETERMINED``: a
    status nobody signed is not a determination.
    """
    if not is_aware(now):
        raise ValueError("timezone-aware now required")

    duty = incident.reporting_duty
    if not incident.reporting_duty_determined_by:
        duty = DutyStatus.UNDETERMINED

    return ReportingClock(
        duty=duty,
        determined_by=incident.reporting_duty_determined_by,
        elapsed=now - incident.detected_at,
        consideration=REPORTING_CLOCK_CONSIDERATION,
        detected_at=incident.detected_at,
    )


def acknowledge(incident: Incident, *, by: str, at: datetime) -> tuple[Incident, Decision]:
    """Record acknowledgement by a named person, once."""
    if not by:
        return incident, deny(R.DISPOSITION_REVIEWER_REQUIRED, note="acknowledgement needs a name")
    if require_aware(at=at):
        return incident, deny(R.UTC_AWARE_TIME_REQUIRED)
    if incident.acknowledged_by:
        return incident, deny(R.ALREADY_FINALIZED, acknowledged_by=incident.acknowledged_by)
    return replace(incident, acknowledged_by=by, acknowledged_at=at), allow(acknowledged_by=by)


def record_containment(
    incident: Incident,
    choice: ContainmentDecision,
    *,
    decided_by: str,
    reason: str,
    at: datetime,
) -> tuple[Incident, Decision]:
    """Record the containment decision with its decider and reasoning."""
    if not decided_by or not reason:
        return incident, deny(
            R.DISPOSITION_REVIEWER_REQUIRED,
            note="containment requires a named decider and a reason",
        )
    if require_aware(at=at):
        return incident, deny(R.UTC_AWARE_TIME_REQUIRED)

    contained = replace(
        incident,
        containment=choice,
        containment_decided_by=decided_by,
        containment_reason=reason,
    )
    return contained, allow(containment=choice.value, decided_by=decided_by)


def record_reporting_decision(
    incident: Incident,
    *,
    party: ExternalParty,
    report: bool,
    decided_by: str,
    at: datetime,
) -> tuple[Incident, Decision]:
    """Record whether to report to an external party.

    Deciding *not* to report is always available. Deciding to report requires
    the delegation that would make the contact lawful for Seal to perform --
    recording an intention Seal cannot act on would be a decision in name only.
    """
    if not decided_by:
        return incident, deny(R.DISPOSITION_REVIEWER_REQUIRED)
    if require_aware(at=at):
        return incident, deny(R.UTC_AWARE_TIME_REQUIRED)

    if report:
        permitted = may_contact_external(incident, party)
        if not permitted.allowed:
            return incident, permitted

    decisions = {**incident.reporting_decisions, party: report}
    return replace(incident, reporting_decisions=decisions), allow(
        party=party.value, report=report, decided_by=decided_by
    )
