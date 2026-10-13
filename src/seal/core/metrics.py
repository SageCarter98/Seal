"""U13 + C03 -- exposure measures that cannot be made to look better than reality.

C03 replaced any wording that could exclude accepted or suppressed findings from
the verified-closure denominator. The rule, stated exactly:

    verified closure rate = currently verified Closed findings
                            / all confirmed findings in that cohort

Risk accepted and Suppressed stay in the denominator and never enter the
numerator. Reopened and Closure awaiting anchor also stay out of the numerator.
Neither an override nor a change of display filter reduces exposure.

The spec's own worked fixture, which ``tests/test_metrics.py`` reproduces: ten
confirmed findings comprising three verified Closed, two Risk accepted, one
Suppressed and four other unresolved findings gives 3/10 = 30% with unresolved
exposure of seven. If one Closed finding recurs it becomes 2/10 = 20% and
unresolved exposure eight. Zero confirmed findings is "Not available", not 100%.

Every measure here returns ``None`` rather than a number when its denominator is
zero. That is deliberate friction: a caller has to decide what to display, and
cannot accidentally render a reassuring 100%.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import reasons as R
from .decision import Decision, allow, deny
from .lifecycle import Cohort, Disposition, Finding, State

#: The string a zero denominator must be reported as (U13).
NOT_AVAILABLE = "Not available"


@dataclass(frozen=True)
class Measure:
    """A measure with its denominator and sample size always attached.

    U13: "Display denominators, observation windows and sample size. A zero
    denominator is Not available." Bundling them means a measure cannot be
    passed around or rendered without them.
    """

    name: str
    numerator: int
    denominator: int
    window_start: datetime
    window_end: datetime
    note: str = ""

    @property
    def value(self) -> float | None:
        if self.denominator == 0:
            return None
        return self.numerator / self.denominator

    @property
    def display(self) -> str | float:
        value = self.value
        return NOT_AVAILABLE if value is None else round(value, 4)

    def as_display(self) -> dict[str, object]:
        return {
            "measure": self.name,
            "value": self.display,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "sample_size": self.denominator,
            "window": [self.window_start.isoformat(), self.window_end.isoformat()],
            "note": self.note,
        }


@dataclass(frozen=True)
class DenominatorAdjustment:
    """A reasoned change to a cohort's denominator, logged and never silent.

    C03: "Preserve initial and current denominator values and a reasoned
    adjustment log." A validated false positive is the only permitted reason,
    and only under a rule predeclared on the cohort.
    """

    at: datetime
    reviewer: str
    finding_id: str
    reason: str
    rule: str
    initial_denominator: int
    adjusted_denominator: int


@dataclass
class ExposureReport:
    """Everything a dashboard needs to show exposure honestly.

    ``filtered_view`` is separate from the totals rather than replacing them,
    because C03 requires both exposed: "Expose both all-disposition totals and
    any explicitly labeled filtered view; never present a filtered view as the
    overall closure rate."
    """

    cohort_id: str
    verified_closure_rate: Measure
    unresolved_exposure: int
    disposition_counts: dict[str, int]
    awaiting_anchor: int
    reopened: int
    initial_denominator: int
    adjustments: tuple[DenominatorAdjustment, ...] = ()

    def as_display(self) -> dict[str, object]:
        return {
            "cohort": self.cohort_id,
            "verified_closure_rate": self.verified_closure_rate.as_display(),
            "unresolved_exposure": self.unresolved_exposure,
            "dispositions": dict(self.disposition_counts),
            "awaiting_anchor": self.awaiting_anchor,
            "reopened": self.reopened,
            "initial_denominator": self.initial_denominator,
            "current_denominator": self.verified_closure_rate.denominator,
            "denominator_adjustments": [
                {
                    "at": adjustment.at.isoformat(),
                    "reviewer": adjustment.reviewer,
                    "finding_id": adjustment.finding_id,
                    "reason": adjustment.reason,
                    "rule": adjustment.rule,
                    "from": adjustment.initial_denominator,
                    "to": adjustment.adjusted_denominator,
                }
                for adjustment in self.adjustments
            ],
        }


def confirmed_cohort(cohort: Cohort) -> tuple[Finding, ...]:
    """The findings in the denominator.

    A validated false positive leaves the cohort only once a reviewer has
    actually corrected it out under the predeclared rule -- C03: "A validated
    False positive may leave the confirmed cohort only under the predeclared
    reviewed correction rule." Both conditions are required: declaring the rule
    removes nothing on its own, and a correction without a declared rule is
    refused by ``correct_false_positive``.
    """
    members = []
    for finding in cohort.findings:
        if not finding.state.is_confirmed:
            continue
        if (
            finding.disposition is Disposition.FALSE_POSITIVE
            and cohort.false_positive_correction_rule
            and finding.finding_id in cohort.corrected_finding_ids
        ):
            continue
        members.append(finding)
    return tuple(members)


def verified_closure_rate(
    cohort: Cohort, *, adjustments: tuple[DenominatorAdjustment, ...] = ()
) -> Measure:
    """C03's formula. Accepted and suppressed findings stay in the denominator."""
    denominator_members = confirmed_cohort(cohort)
    numerator = sum(
        1
        for finding in denominator_members
        # Only a finalized Closed counts, and only when no disposition is
        # standing in for a fix. An accepted risk in Closed state would be a
        # data error, but it must not be counted as verified either way.
        if finding.state.is_resolved and finding.disposition is None
    )
    return Measure(
        name="verified_closure_rate",
        numerator=numerator,
        denominator=len(denominator_members),
        window_start=cohort.period_start,
        window_end=cohort.period_end,
        note="accepted and suppressed findings remain in the denominator (C03)",
    )


def exposure_report(
    cohort: Cohort, *, adjustments: tuple[DenominatorAdjustment, ...] = ()
) -> ExposureReport:
    """Build the full exposure picture for a declared cohort."""
    members = confirmed_cohort(cohort)
    rate = verified_closure_rate(cohort, adjustments=adjustments)

    counts: dict[str, int] = {disposition.value: 0 for disposition in Disposition}
    for finding in members:
        if finding.disposition is not None:
            counts[finding.disposition.value] += 1

    initial = adjustments[0].initial_denominator if adjustments else len(members)

    return ExposureReport(
        cohort_id=cohort.cohort_id,
        verified_closure_rate=rate,
        unresolved_exposure=sum(1 for f in members if f.is_unresolved_exposure),
        disposition_counts=counts,
        awaiting_anchor=sum(1 for f in members if f.state is State.CLOSURE_AWAITING_ANCHOR),
        reopened=sum(1 for f in members if f.state is State.REOPENED),
        initial_denominator=initial,
        adjustments=adjustments,
    )


def filtered_view(
    cohort: Cohort, *, include: frozenset[Disposition | None], label: str
) -> dict[str, object]:
    """A labelled filtered view that also carries the unchanged overall totals.

    C03-B's acceptance case is exactly this: "apply disposition filters and
    verify the overall totals remain visible and unchanged." So the filter
    cannot be rendered on its own -- the overall report comes back with it.
    """
    if not label:
        raise ValueError("a filtered view must be explicitly labelled")

    overall = exposure_report(cohort)
    subset = [f for f in confirmed_cohort(cohort) if f.disposition in include]
    return {
        "label": label,
        "filtered_count": len(subset),
        "filtered_finding_ids": sorted(f.finding_id for f in subset),
        "overall": overall.as_display(),
        "warning": "a filtered view is never the overall closure rate (C03)",
    }


def correct_false_positive(
    cohort: Cohort,
    finding_id: str,
    *,
    reviewer: str,
    reason: str,
    at: datetime,
) -> tuple[Decision, DenominatorAdjustment | None]:
    """Apply the predeclared false-positive correction, emitting an adjustment.

    Refused outright when the cohort declared no correction rule -- C03-C
    requires the correction to emit a denominator adjustment and preserve
    history, which is impossible to do honestly against a rule that was never
    declared.
    """
    if not cohort.false_positive_correction_rule:
        return deny(R.ADJUSTMENT_NOT_PREDECLARED), None
    if not reviewer or not reason:
        return deny(R.DISPOSITION_REVIEWER_REQUIRED), None

    before = len(confirmed_cohort(cohort))
    target = next((f for f in cohort.findings if f.finding_id == finding_id), None)
    if target is None:
        return deny(R.COHORT_NOT_DECLARED, note="finding not in cohort"), None
    if target.disposition is not Disposition.FALSE_POSITIVE:
        return deny(R.DISPOSITION_REVIEWER_REQUIRED, note="not a validated false positive"), None
    if finding_id in cohort.corrected_finding_ids:
        return deny(R.ALREADY_FINALIZED, note="already corrected out of the cohort"), None

    # The finding keeps its observations; only the denominator changes.
    adjustment = DenominatorAdjustment(
        at=at,
        reviewer=reviewer,
        finding_id=finding_id,
        reason=reason,
        rule=cohort.false_positive_correction_rule,
        initial_denominator=before,
        adjusted_denominator=before - 1,
    )
    return allow(finding_id=finding_id, adjustment="denominator"), adjustment


# ---------------------------------------------------------------------------
# The remaining U13 dashboard measures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClosureDuration:
    """Confirmation-to-closure for one finding, used for the timing measure."""

    finding_id: str
    confirmed_at: datetime
    closed_at: datetime

    @property
    def duration(self) -> timedelta:
        return self.closed_at - self.confirmed_at


def time_to_verified_closure(
    durations: tuple[ClosureDuration, ...], *, unresolved_ages: tuple[timedelta, ...] = ()
) -> dict[str, object]:
    """Median and p90 from confirmation to final closure.

    Unresolved age is reported separately, never folded in -- U13: "report
    unresolved age separately". Mixing them would make a backlog of old open
    findings look like fast closure.
    """
    if not durations:
        return {
            "median": NOT_AVAILABLE,
            "p90": NOT_AVAILABLE,
            "sample_size": 0,
            "unresolved_count": len(unresolved_ages),
            "unresolved_median_age": (
                NOT_AVAILABLE
                if not unresolved_ages
                else statistics.median(age.total_seconds() for age in unresolved_ages)
            ),
        }

    seconds = sorted(d.duration.total_seconds() for d in durations)
    index = max(0, min(len(seconds) - 1, int(round(0.9 * (len(seconds) - 1)))))
    return {
        "median": statistics.median(seconds),
        "p90": seconds[index],
        "sample_size": len(seconds),
        "unresolved_count": len(unresolved_ages),
        "unresolved_median_age": (
            NOT_AVAILABLE
            if not unresolved_ages
            else statistics.median(age.total_seconds() for age in unresolved_ages)
        ),
    }


def reopen_rate(
    *, recurred: int, eligible_for_followup: int, window: tuple[datetime, datetime]
) -> Measure:
    """Previously verified closures that recurred, over closures eligible for follow-up."""
    return Measure(
        name="reopen_rate",
        numerator=recurred,
        denominator=eligible_for_followup,
        window_start=window[0],
        window_end=window[1],
        note="window shown with the rate (U13)",
    )


def assigned_finding_invalidation(
    *, invalidated: int, assigned: int, window: tuple[datetime, datetime]
) -> Measure:
    """Assigned findings later invalidated, over assigned findings in the cohort.

    Spec Section 10 keeps the 5% target but notes it "needs a defined assignment
    cohort and observation period" -- so this measure carries its window and
    sample size, and the target is not asserted here.
    """
    return Measure(
        name="assigned_finding_invalidation",
        numerator=invalidated,
        denominator=assigned,
        window_start=window[0],
        window_end=window[1],
    )


@dataclass
class ControlHealth:
    """U13's control-health measure: denials, stop performance, anchor lag.

    Not a score. Each component is reported on its own, because a single health
    number is exactly the "green screen" that can overstate protection.
    """

    authorization_denials: dict[str, int] = field(default_factory=dict)
    stop_egress_latency_seconds: tuple[float, ...] = ()
    stop_termination_latency_seconds: tuple[float, ...] = ()
    anchor_lag_seconds: tuple[float, ...] = ()
    integrity_incidents: int = 0

    def as_display(self) -> dict[str, object]:
        def worst(values: tuple[float, ...]) -> float | str:
            return max(values) if values else NOT_AVAILABLE

        return {
            "authorization_denials": dict(self.authorization_denials),
            "worst_stop_egress_seconds": worst(self.stop_egress_latency_seconds),
            "worst_stop_termination_seconds": worst(self.stop_termination_latency_seconds),
            "worst_anchor_lag_seconds": worst(self.anchor_lag_seconds),
            "integrity_incidents": self.integrity_incidents,
        }
