"""U06 -- explainable prioritization across four separate dimensions.

Spec Section 6 requires the dimensions kept apart and never collapsed:

* the source-reported CVSS vector and score, stored unchanged;
* any environment-adjusted vector and score, stored separately;
* dated EPSS probability and percentile, with missing data as Unknown;
* evidence confidence, which drives validation urgency without reducing
  severity.

FIRST advises against multiplying EPSS by CVSS [R5], so nothing here produces a
combined number. There is no "security score" -- spec Section 6 explicitly
forbids replacing the dimensions with one.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum

from . import reasons as R
from ._canonical import is_aware
from .decision import Decision, allow, deny

#: Identifies this decision tree in every stored outcome. Spec Section 6: this
#: is "Seal's proposed SSVC-style decision tree, not a claim to implement the
#: official CISA tree". A threshold change must bump this so historical
#: outcomes remain attributable to the policy that produced them.
POLICY_VERSION = "seal-priority-proposal-v1"

#: Both pending D10 security-lead review (spec Section 6).
EPSS_ACT_THRESHOLD = 0.10
EPSS_FRESHNESS = timedelta(hours=48)


class Action(str, Enum):
    """The outcome branches, plus ``TRIAGE`` for incomplete context.

    ``TRIAGE`` exists because of one sentence in spec Section 6: "Unknown
    exposure, impact or severity requires triage; it must not default to the
    least urgent branch." Without a distinct value, missing context silently
    becomes ``TRACK``.
    """

    ACT = "Act"
    ATTEND = "Attend"
    TRACK_STAR = "Track*"
    TRACK = "Track"
    TRIAGE = "Triage"


class Confidence(str, Enum):
    CONFIRMED = "Confirmed"
    HIGH = "High"
    MODERATE = "Moderate"
    LOW = "Low"


#: Proposed acknowledgement targets (spec Section 6). Workflow proposals, not
#: legal deadlines, and not a substitute for institutional service targets.
ACKNOWLEDGEMENT_TARGETS: dict[Action, timedelta | None] = {
    Action.ACT: timedelta(hours=4),
    Action.ATTEND: timedelta(days=1),
    Action.TRACK_STAR: timedelta(days=5),
    Action.TRACK: None,  # next planned review
    Action.TRIAGE: timedelta(hours=4),
}

#: Severity at or above which a low-confidence finding enters urgent validation
#: rather than waiting (spec Section 6: "Low-confidence High/Critical findings
#: enter urgent validation immediately").
URGENT_VALIDATION_SEVERITY = 7.0


@dataclass(frozen=True)
class Severity:
    """A CVSS reading, kept whole: vector, score and where it came from.

    Source and environmental readings are two instances of this type rather than
    two scores on one object -- that is what makes "source scores/evidence never
    overwritten" (W01) structurally true instead of a convention.
    """

    vector: str
    score: float
    version: str = "4.0"

    def __post_init__(self) -> None:
        if type(self.score) not in (int, float) or not 0 <= self.score <= 10:
            raise ValueError("CVSS score must be a finite number from 0 to 10")


@dataclass(frozen=True)
class Epss:
    """A dated EPSS reading. Stale or absent readings are Unknown, never zero."""

    probability: float
    percentile: float
    observed_at: datetime

    def __post_init__(self) -> None:
        for name, value in (("probability", self.probability), ("percentile", self.percentile)):
            if type(value) not in (int, float) or not 0 <= value <= 1:
                raise ValueError(f"EPSS {name} must be a finite value from 0 to 1")
        if not is_aware(self.observed_at):
            raise ValueError("EPSS reading requires a timezone-aware observation time")

    def is_fresh(self, now: datetime, within: timedelta = EPSS_FRESHNESS) -> bool:
        if not is_aware(now):
            return False
        age = now - self.observed_at
        # A future-dated reading is not fresh. Spec Section 10 lists
        # "future-dated intelligence" as a required adversarial scenario.
        return timedelta(0) <= age <= within


@dataclass(frozen=True)
class Context:
    """The environment facts the tree branches on.

    All three are tri-state (``None`` meaning unknown) because the honest
    answer early in triage is usually "we do not know yet", and encoding that as
    ``False`` would quietly route a serious finding to the least urgent branch.
    """

    exposed: bool | None
    serious_impact: bool | None
    known_exploitation: bool | None


@dataclass(frozen=True)
class Priority:
    """A priority outcome, carrying everything needed to explain it.

    U13 requires severity, likelihood date, priority reason, confidence, owner,
    deadline and exception status shown together, so the outcome keeps its
    reason and inputs rather than just the branch label.
    """

    action: Action
    reason: str
    policy_version: str
    confidence: Confidence
    urgent_validation: bool
    epss_status: str
    severity_score: float | None
    evaluated_at: datetime
    unknown_dimensions: tuple[str, ...] = ()

    @property
    def acknowledgement_due(self) -> datetime | None:
        target = ACKNOWLEDGEMENT_TARGETS[self.action]
        return None if target is None else self.evaluated_at + target


def prioritize(
    *,
    source_severity: Severity | None,
    context: Context,
    confidence: Confidence,
    now: datetime,
    environmental_severity: Severity | None = None,
    epss: Epss | None = None,
) -> Priority:
    """Evaluate the proposed Seal priority tree.

    The environmental reading is used for the decision when present, while the
    source reading stays untouched for reporting -- spec Section 6 keeps the
    source vector and score "unchanged" and any adjustment "separately".
    """
    if not is_aware(now):
        raise ValueError("timezone-aware now required")

    unknown = tuple(
        name
        for name, value in (
            ("severity", source_severity),
            ("exposed", context.exposed),
            ("serious_impact", context.serious_impact),
            ("known_exploitation", context.known_exploitation),
        )
        if value is None
    )

    effective = environmental_severity or source_severity
    score = effective.score if effective else None
    fresh_epss = epss is not None and epss.is_fresh(now)
    epss_status = "fresh" if fresh_epss else "unknown_or_stale"

    # Urgency from weak evidence is assessed before the tree, so a finding that
    # routes to TRIAGE still gets flagged for urgent validation.
    urgent = (
        score is not None and score >= URGENT_VALIDATION_SEVERITY and confidence is Confidence.LOW
    )

    if unknown:
        action = Action.TRIAGE
        reason = f"incomplete context: {', '.join(unknown)}"
    elif context.known_exploitation and (context.exposed or context.serious_impact):
        action = Action.ACT
        reason = "known exploitation with exposure or serious impact"
    elif (
        context.known_exploitation
        or context.serious_impact
        or score >= 9  # type: ignore[operator]
        or (context.exposed and score >= 7)  # type: ignore[operator]
    ):
        action = Action.ATTEND
        reason = "exploitation, serious impact or high-severity escalation"
    elif context.exposed and fresh_epss and epss.probability >= EPSS_ACT_THRESHOLD:  # type: ignore[union-attr]
        action = Action.ATTEND
        reason = f"exposed with fresh EPSS at least {EPSS_ACT_THRESHOLD}"
    elif score >= 4 or context.exposed:  # type: ignore[operator]
        action = Action.TRACK_STAR
        reason = "material severity or exposure"
    else:
        action = Action.TRACK
        reason = "lower observed severity and exposure"

    return Priority(
        action=action,
        reason=reason,
        policy_version=POLICY_VERSION,
        confidence=confidence,
        urgent_validation=urgent,
        epss_status=epss_status,
        severity_score=score,
        evaluated_at=now,
        unknown_dimensions=unknown,
    )


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------

#: An override may not take a finding below this when exploitation or serious
#: impact is known, unless an approved exception is recorded (spec Section 6).
PRIORITY_FLOOR = Action.ATTEND

_RANK = {
    Action.ACT: 4,
    Action.ATTEND: 3,
    Action.TRIAGE: 3,
    Action.TRACK_STAR: 2,
    Action.TRACK: 1,
}


@dataclass(frozen=True)
class Override:
    """A reviewer's reasoned departure from the computed outcome.

    Retains the old and new outcome, policy version, reviewer, reason, evidence,
    creation time and expiry -- spec Section 6's full list. ``expires`` is not
    optional: an override with no end date permanently rewrites the finding's
    priority, which that section forbids.
    """

    override_id: str
    finding_id: str
    computed: Action
    override_to: Action
    policy_version: str
    reviewer: str
    reason: str
    evidence_reference: str
    created_at: datetime
    expires_at: datetime
    exception_approved_by: str = ""

    def is_active(self, now: datetime) -> bool:
        return is_aware(now) and self.created_at <= now < self.expires_at


def apply_override(
    priority: Priority, override: Override | None, context: Context, *, now: datetime
) -> tuple[Priority, Decision]:
    """Apply an override if it is valid, and say why when it is not.

    Returns the effective priority alongside the decision. An expired override
    does not just stop applying: the recalculated outcome comes back with
    ``OVERRIDE_EXPIRED`` so the escalation U06 requires is visible rather than
    silent.
    """
    if override is None:
        return priority, allow()

    if not override.reviewer or not override.reason or not override.evidence_reference:
        return priority, deny(R.DISPOSITION_REVIEWER_REQUIRED)

    if not override.is_active(now):
        return priority, deny(R.OVERRIDE_EXPIRED, override_id=override.override_id)

    floor_applies = bool(context.known_exploitation) or bool(context.serious_impact)
    below_floor = _RANK[override.override_to] < _RANK[PRIORITY_FLOOR]
    if floor_applies and below_floor and not override.exception_approved_by:
        return priority, deny(
            R.PRIORITY_FLOOR_EXCEPTION_REQUIRED,
            floor=PRIORITY_FLOOR.value,
            requested=override.override_to.value,
        )

    overridden = replace(
        priority,
        action=override.override_to,
        reason=f"override by {override.reviewer}: {override.reason}",
    )
    return overridden, allow(override_id=override.override_id)
