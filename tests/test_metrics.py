"""U13 + C03 -- exposure measures.

C03's worked acceptance fixture is reproduced verbatim in
``TestC03WorkedFixture``: ten confirmed findings comprising three verified
Closed, two Risk accepted, one Suppressed and four other unresolved findings
gives 3/10 = 30% with unresolved exposure of seven. One recurrence makes it
2/10 = 20% and unresolved exposure eight.

C03's four named acceptance scenarios:

* **C03-A** reproduce the ten-finding fixture including recurrence.
* **C03-B** apply disposition filters and verify the overall totals remain
  visible and unchanged.
* **C03-C** an approved false-positive correction emits a denominator adjustment
  and preserves history.
* **C03-D** a zero denominator is Not available.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from conftest import ORG, PROFILE, TARGET

from seal.core import reasons as R
from seal.core.lifecycle import Cohort, Disposition, Finding, State
from seal.core.metrics import (
    NOT_AVAILABLE,
    ClosureDuration,
    ControlHealth,
    assigned_finding_invalidation,
    correct_false_positive,
    exposure_report,
    filtered_view,
    reopen_rate,
    time_to_verified_closure,
    verified_closure_rate,
)


def finding(index: int, state: State, disposition: Disposition | None = None) -> Finding:
    return Finding(
        finding_id=f"F-{index:04d}",
        organization=ORG,
        target_id=TARGET,
        fingerprint=f"fp-{index}",
        rule="zap.40012",
        profile_digest=PROFILE,
        state=state,
        disposition=disposition,
        exception_id=f"exc-{index}" if disposition else "",
    )


@pytest.fixture
def ten_finding_cohort(now) -> Cohort:
    """C03's exact worked fixture.

    Three verified Closed, two Risk accepted, one Suppressed, four other
    unresolved.
    """
    return Cohort(
        cohort_id="cohort-2026-Q4",
        organization=ORG,
        declared_at=now - timedelta(days=30),
        period_start=now - timedelta(days=30),
        period_end=now,
        scope="owned lab web targets",
        findings=[
            finding(1, State.CLOSED),
            finding(2, State.CLOSED),
            finding(3, State.CLOSED),
            finding(4, State.ASSIGNED, Disposition.RISK_ACCEPTED),
            finding(5, State.CONFIRMED, Disposition.RISK_ACCEPTED),
            finding(6, State.CONFIRMED, Disposition.SUPPRESSED),
            finding(7, State.CONFIRMED),
            finding(8, State.ASSIGNED),
            finding(9, State.REMEDIATING),
            finding(10, State.VERIFICATION_PENDING),
        ],
    )


class TestC03WorkedFixture:
    def test_the_rate_is_three_over_ten(self, ten_finding_cohort):
        measure = verified_closure_rate(ten_finding_cohort)
        assert measure.numerator == 3
        assert measure.denominator == 10
        assert measure.value == pytest.approx(0.30)

    def test_unresolved_exposure_is_seven_including_the_three_exceptions(self, ten_finding_cohort):
        report = exposure_report(ten_finding_cohort)
        assert report.unresolved_exposure == 7
        assert report.disposition_counts[Disposition.RISK_ACCEPTED.value] == 2
        assert report.disposition_counts[Disposition.SUPPRESSED.value] == 1

    def test_one_recurrence_makes_it_two_over_ten_and_exposure_eight(self, ten_finding_cohort):
        """C03-A's recurrence half of the fixture."""
        ten_finding_cohort.findings[0] = replace(
            ten_finding_cohort.findings[0], state=State.REOPENED, reopened_count=1
        )
        measure = verified_closure_rate(ten_finding_cohort)
        report = exposure_report(ten_finding_cohort)

        assert measure.numerator == 2
        assert measure.denominator == 10
        assert measure.value == pytest.approx(0.20)
        assert report.unresolved_exposure == 8
        assert report.reopened == 1

    def test_accepting_an_unresolved_finding_changes_neither_side(self, ten_finding_cohort):
        """C03: changing an unresolved disposition to accepted or suppressed
        changes neither denominator nor closure numerator."""
        before = verified_closure_rate(ten_finding_cohort)
        before_exposure = exposure_report(ten_finding_cohort).unresolved_exposure

        ten_finding_cohort.findings[7] = replace(
            ten_finding_cohort.findings[7],
            disposition=Disposition.RISK_ACCEPTED,
            exception_id="exc-8",
        )

        after = verified_closure_rate(ten_finding_cohort)
        assert (after.numerator, after.denominator) == (
            before.numerator,
            before.denominator,
        )
        assert exposure_report(ten_finding_cohort).unresolved_exposure == before_exposure

    def test_an_accepted_risk_never_enters_the_numerator(self, ten_finding_cohort):
        """Even a data error that marks an accepted finding Closed is not counted."""
        ten_finding_cohort.findings[3] = replace(ten_finding_cohort.findings[3], state=State.CLOSED)
        measure = verified_closure_rate(ten_finding_cohort)
        assert measure.numerator == 3

    def test_awaiting_anchor_is_outside_the_numerator(self, ten_finding_cohort):
        """C01's substate is not a closure until the receipt is verified."""
        ten_finding_cohort.findings[0] = replace(
            ten_finding_cohort.findings[0], state=State.CLOSURE_AWAITING_ANCHOR
        )
        report = exposure_report(ten_finding_cohort)
        assert report.verified_closure_rate.numerator == 2
        assert report.awaiting_anchor == 1
        assert report.unresolved_exposure == 8


class TestC03B:
    """Filters never reduce the reported exposure."""

    def test_a_filtered_view_carries_the_unchanged_overall_totals(self, ten_finding_cohort):
        overall = exposure_report(ten_finding_cohort).as_display()
        view = filtered_view(
            ten_finding_cohort,
            include=frozenset({Disposition.RISK_ACCEPTED}),
            label="Risk accepted only",
        )
        assert view["filtered_count"] == 2
        assert view["overall"] == overall
        assert view["overall"]["verified_closure_rate"]["denominator"] == 10

    def test_filtering_to_nothing_still_shows_the_overall_rate(self, ten_finding_cohort):
        view = filtered_view(
            ten_finding_cohort,
            include=frozenset({Disposition.FALSE_POSITIVE}),
            label="False positives only",
        )
        assert view["filtered_count"] == 0
        assert view["overall"]["verified_closure_rate"]["value"] == pytest.approx(0.30)
        assert view["overall"]["unresolved_exposure"] == 7

    def test_a_filtered_view_must_be_labelled(self, ten_finding_cohort):
        with pytest.raises(ValueError, match="explicitly labelled"):
            filtered_view(ten_finding_cohort, include=frozenset(), label="")

    def test_the_view_warns_that_it_is_not_the_overall_rate(self, ten_finding_cohort):
        view = filtered_view(ten_finding_cohort, include=frozenset({None}), label="No disposition")
        assert "never the overall closure rate" in view["warning"]


class TestC03C:
    """An approved false-positive correction, with history preserved."""

    def test_a_correction_without_a_predeclared_rule_is_refused(self, ten_finding_cohort, now):
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        decision, adjustment = correct_false_positive(
            ten_finding_cohort,
            "F-0007",
            reviewer="reviewer.esi",
            reason="validated false positive",
            at=now,
        )
        assert R.ADJUSTMENT_NOT_PREDECLARED in decision.reasons
        assert adjustment is None

    def test_a_false_positive_stays_counted_without_a_rule(self, ten_finding_cohort):
        """Absent a predeclared rule, the finding does not silently leave the cohort."""
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        assert verified_closure_rate(ten_finding_cohort).denominator == 10

    def test_declaring_the_rule_alone_removes_nothing(self, ten_finding_cohort):
        """The rule is permission to correct, not the correction itself."""
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        assert verified_closure_rate(ten_finding_cohort).denominator == 10

    def test_a_correction_under_a_predeclared_rule_emits_an_adjustment(
        self, ten_finding_cohort, now
    ):
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        decision, adjustment = correct_false_positive(
            ten_finding_cohort,
            "F-0007",
            reviewer="reviewer.esi",
            reason="validated false positive",
            at=now,
        )
        assert decision.allowed
        assert adjustment is not None
        assert adjustment.initial_denominator == 10
        assert adjustment.adjusted_denominator == 9
        assert adjustment.rule == "FP-CORR-1"

    def test_recording_the_correction_is_what_changes_the_denominator(
        self, ten_finding_cohort, now
    ):
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        _, adjustment = correct_false_positive(
            ten_finding_cohort, "F-0007", reviewer="reviewer.esi", reason="validated", at=now
        )
        assert verified_closure_rate(ten_finding_cohort).denominator == 10

        ten_finding_cohort.corrected_finding_ids.append("F-0007")
        assert verified_closure_rate(ten_finding_cohort).denominator == 9

    def test_the_adjustment_log_preserves_both_denominators(self, ten_finding_cohort, now):
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        _, adjustment = correct_false_positive(
            ten_finding_cohort, "F-0007", reviewer="reviewer.esi", reason="validated", at=now
        )
        ten_finding_cohort.corrected_finding_ids.append("F-0007")

        display = exposure_report(ten_finding_cohort, adjustments=(adjustment,)).as_display()
        assert display["initial_denominator"] == 10
        assert display["current_denominator"] == 9
        assert display["denominator_adjustments"][0]["reviewer"] == "reviewer.esi"
        assert display["denominator_adjustments"][0]["rule"] == "FP-CORR-1"
        assert display["denominator_adjustments"][0]["from"] == 10
        assert display["denominator_adjustments"][0]["to"] == 9

    def test_correcting_the_same_finding_twice_is_refused(self, ten_finding_cohort, now):
        """One correction, one adjustment -- a replay must not shrink it again."""
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        correct_false_positive(
            ten_finding_cohort, "F-0007", reviewer="reviewer.esi", reason="validated", at=now
        )
        ten_finding_cohort.corrected_finding_ids.append("F-0007")

        decision, adjustment = correct_false_positive(
            ten_finding_cohort, "F-0007", reviewer="reviewer.esi", reason="again", at=now
        )
        assert not decision.allowed
        assert adjustment is None

    def test_the_original_observation_survives_the_correction(self, ten_finding_cohort, now):
        """C03: preserve the original observation and show the correction separately."""
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        ten_finding_cohort.findings[6] = replace(
            ten_finding_cohort.findings[6], disposition=Disposition.FALSE_POSITIVE
        )
        correct_false_positive(
            ten_finding_cohort, "F-0007", reviewer="reviewer.esi", reason="validated", at=now
        )
        ten_finding_cohort.corrected_finding_ids.append("F-0007")
        # Out of the denominator, still in the record.
        assert any(f.finding_id == "F-0007" for f in ten_finding_cohort.findings)

    def test_a_correction_requires_a_reviewer_and_reason(self, ten_finding_cohort, now):
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        decision, _ = correct_false_positive(
            ten_finding_cohort, "F-0007", reviewer="", reason="", at=now
        )
        assert R.DISPOSITION_REVIEWER_REQUIRED in decision.reasons

    def test_a_finding_that_is_not_a_validated_false_positive_cannot_be_corrected(
        self, ten_finding_cohort, now
    ):
        ten_finding_cohort.false_positive_correction_rule = "FP-CORR-1"
        decision, _ = correct_false_positive(
            ten_finding_cohort, "F-0007", reviewer="reviewer.esi", reason="x", at=now
        )
        assert not decision.allowed


class TestC03D:
    """A zero denominator is Not available, not 100%."""

    def test_an_empty_cohort_reports_not_available(self, now):
        empty = Cohort(
            cohort_id="empty",
            organization=ORG,
            declared_at=now,
            period_start=now - timedelta(days=7),
            period_end=now,
            scope="none",
        )
        measure = verified_closure_rate(empty)
        assert measure.denominator == 0
        assert measure.value is None
        assert measure.display == NOT_AVAILABLE

    def test_a_cohort_of_only_new_findings_has_no_confirmed_denominator(self, now):
        unconfirmed = Cohort(
            cohort_id="new-only",
            organization=ORG,
            declared_at=now,
            period_start=now - timedelta(days=7),
            period_end=now,
            scope="unconfirmed",
            findings=[finding(1, State.NEW), finding(2, State.NEW)],
        )
        assert verified_closure_rate(unconfirmed).display == NOT_AVAILABLE

    def test_zero_denominator_never_renders_as_a_perfect_score(self, now):
        empty = Cohort(
            cohort_id="empty",
            organization=ORG,
            declared_at=now,
            period_start=now,
            period_end=now,
            scope="none",
        )
        display = exposure_report(empty).as_display()
        assert display["verified_closure_rate"]["value"] == NOT_AVAILABLE
        assert display["verified_closure_rate"]["value"] != 1.0


class TestMeasureDisplay:
    def test_every_measure_carries_its_denominator_and_sample_size(self, ten_finding_cohort):
        display = verified_closure_rate(ten_finding_cohort).as_display()
        for key in ("value", "numerator", "denominator", "sample_size", "window"):
            assert key in display
        assert display["sample_size"] == display["denominator"]

    def test_reopen_rate_shows_its_window(self, now):
        measure = reopen_rate(
            recurred=2, eligible_for_followup=8, window=(now - timedelta(days=90), now)
        )
        assert measure.value == pytest.approx(0.25)
        assert measure.as_display()["window"][1] == now.isoformat()

    def test_reopen_rate_with_no_eligible_closures_is_not_available(self, now):
        measure = reopen_rate(recurred=0, eligible_for_followup=0, window=(now, now))
        assert measure.display == NOT_AVAILABLE

    def test_assigned_finding_invalidation_reports_without_asserting_the_target(self, now):
        measure = assigned_finding_invalidation(
            invalidated=1, assigned=40, window=(now - timedelta(days=30), now)
        )
        assert measure.value == pytest.approx(0.025)
        assert measure.denominator == 40


class TestTimeToClosure:
    def test_median_and_p90_are_reported_with_the_sample_size(self, now):
        durations = tuple(
            ClosureDuration(
                finding_id=f"F-{index}",
                confirmed_at=now - timedelta(days=index + 1),
                closed_at=now,
            )
            for index in range(1, 11)
        )
        result = time_to_verified_closure(durations)
        assert result["sample_size"] == 10
        assert result["median"] > 0
        assert result["p90"] >= result["median"]

    def test_unresolved_age_is_reported_separately_not_folded_in(self, now):
        durations = (ClosureDuration("F-1", now - timedelta(days=2), now),)
        result = time_to_verified_closure(
            durations, unresolved_ages=(timedelta(days=300), timedelta(days=400))
        )
        # A 300+ day backlog does not inflate the 2-day median closure time.
        assert result["median"] == timedelta(days=2).total_seconds()
        assert result["unresolved_count"] == 2
        assert result["unresolved_median_age"] == timedelta(days=350).total_seconds()

    def test_no_closures_is_not_available(self):
        result = time_to_verified_closure(())
        assert result["median"] == NOT_AVAILABLE
        assert result["p90"] == NOT_AVAILABLE
        assert result["sample_size"] == 0


class TestControlHealth:
    def test_health_components_are_reported_separately_not_as_a_score(self):
        health = ControlHealth(
            authorization_denials={R.AUTHORIZATION_REVOKED: 3, R.OUTSIDE_WINDOW: 1},
            stop_egress_latency_seconds=(1.2, 4.9),
            stop_termination_latency_seconds=(12.0, 28.5),
            anchor_lag_seconds=(60.0, 840.0),
            integrity_incidents=1,
        )
        display = health.as_display()
        assert display["worst_stop_egress_seconds"] == 4.9
        assert display["worst_stop_termination_seconds"] == 28.5
        assert display["worst_anchor_lag_seconds"] == 840.0
        assert display["authorization_denials"][R.AUTHORIZATION_REVOKED] == 3
        assert "score" not in display

    def test_absent_measurements_are_not_available_rather_than_zero(self):
        display = ControlHealth().as_display()
        assert display["worst_stop_egress_seconds"] == NOT_AVAILABLE
        assert display["worst_anchor_lag_seconds"] == NOT_AVAILABLE
