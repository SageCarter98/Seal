"""U06 -- explainable prioritization across four separate dimensions.

Acceptance evidence: "Context, stale-signal and override tests". Spec Section 10
adds "future-dated intelligence" as a required adversarial scenario.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from seal.core import reasons as R
from seal.core.priority import (
    ACKNOWLEDGEMENT_TARGETS,
    EPSS_ACT_THRESHOLD,
    EPSS_FRESHNESS,
    POLICY_VERSION,
    Action,
    Confidence,
    Context,
    Epss,
    Override,
    Severity,
    apply_override,
    prioritize,
)

KNOWN = Context(exposed=True, serious_impact=True, known_exploitation=True)
QUIET = Context(exposed=False, serious_impact=False, known_exploitation=False)


def severity(score: float) -> Severity:
    return Severity(vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", score=score)


def decide(now, *, score=5.0, context=QUIET, confidence=Confidence.CONFIRMED, **extra):
    return prioritize(
        source_severity=severity(score), context=context, confidence=confidence, now=now, **extra
    )


class TestTheTree:
    def test_exploitation_with_exposure_is_act(self, now):
        result = decide(now, score=8.0, context=KNOWN)
        assert result.action is Action.ACT
        assert "known exploitation" in result.reason

    def test_exploitation_with_serious_impact_but_no_exposure_is_act(self, now):
        result = decide(
            now,
            score=8.0,
            context=Context(exposed=False, serious_impact=True, known_exploitation=True),
        )
        assert result.action is Action.ACT

    def test_exploitation_alone_is_attend(self, now):
        result = decide(
            now,
            score=5.0,
            context=Context(exposed=False, serious_impact=False, known_exploitation=True),
        )
        assert result.action is Action.ATTEND

    def test_serious_impact_alone_is_attend(self, now):
        result = decide(
            now,
            score=5.0,
            context=Context(exposed=False, serious_impact=True, known_exploitation=False),
        )
        assert result.action is Action.ATTEND

    def test_severity_nine_is_attend_without_any_context(self, now):
        assert decide(now, score=9.0).action is Action.ATTEND

    def test_exposed_severity_seven_is_attend(self, now):
        result = decide(
            now,
            score=7.0,
            context=Context(exposed=True, serious_impact=False, known_exploitation=False),
        )
        assert result.action is Action.ATTEND

    def test_unexposed_severity_seven_is_only_track_star(self, now):
        assert decide(now, score=7.0).action is Action.TRACK_STAR

    def test_severity_four_is_track_star(self, now):
        assert decide(now, score=4.0).action is Action.TRACK_STAR

    def test_exposure_alone_is_track_star(self, now):
        result = decide(
            now,
            score=1.0,
            context=Context(exposed=True, serious_impact=False, known_exploitation=False),
        )
        assert result.action is Action.TRACK_STAR

    def test_low_severity_and_no_exposure_is_track(self, now):
        assert decide(now, score=3.9).action is Action.TRACK

    def test_every_outcome_carries_the_policy_version(self, now):
        assert decide(now).policy_version == POLICY_VERSION


class TestIncompleteContext:
    @pytest.mark.parametrize(
        "context",
        [
            Context(exposed=None, serious_impact=False, known_exploitation=False),
            Context(exposed=False, serious_impact=None, known_exploitation=False),
            Context(exposed=False, serious_impact=False, known_exploitation=None),
        ],
    )
    def test_unknown_context_is_triage_not_the_least_urgent_branch(self, now, context):
        """Spec Section 6: unknown context "must not default to the least
        urgent branch"."""
        result = decide(now, score=2.0, context=context)
        assert result.action is Action.TRIAGE
        assert result.action is not Action.TRACK

    def test_unknown_severity_is_triage(self, now):
        result = prioritize(
            source_severity=None,
            context=QUIET,
            confidence=Confidence.CONFIRMED,
            now=now,
        )
        assert result.action is Action.TRIAGE
        assert "severity" in result.reason

    def test_the_unknown_dimensions_are_named(self, now):
        result = prioritize(
            source_severity=None,
            context=Context(exposed=None, serious_impact=None, known_exploitation=None),
            confidence=Confidence.CONFIRMED,
            now=now,
        )
        assert set(result.unknown_dimensions) == {
            "severity",
            "exposed",
            "serious_impact",
            "known_exploitation",
        }

    def test_triage_still_flags_urgent_validation(self, now):
        """A severe low-confidence finding is urgent even before triage resolves."""
        result = decide(
            now,
            score=9.0,
            context=Context(exposed=None, serious_impact=None, known_exploitation=None),
            confidence=Confidence.LOW,
        )
        assert result.action is Action.TRIAGE
        assert result.urgent_validation


class TestEpss:
    def fresh(self, now, probability=0.2):
        return Epss(probability=probability, percentile=0.9, observed_at=now)

    def test_exposed_with_fresh_epss_above_the_threshold_is_attend(self, now):
        result = decide(
            now,
            score=5.0,
            context=Context(exposed=True, serious_impact=False, known_exploitation=False),
            epss=self.fresh(now),
        )
        assert result.action is Action.ATTEND
        assert result.epss_status == "fresh"

    def test_fresh_epss_below_the_threshold_does_not_escalate(self, now):
        result = decide(
            now,
            score=5.0,
            context=Context(exposed=True, serious_impact=False, known_exploitation=False),
            epss=self.fresh(now, probability=0.05),
        )
        assert result.action is Action.TRACK_STAR

    def test_stale_epss_is_unknown_not_zero(self, now):
        """A stale reading cannot escalate, and must not read as 0.0 either."""
        stale = Epss(
            probability=0.9,
            percentile=0.99,
            observed_at=now - EPSS_FRESHNESS - timedelta(hours=1),
        )
        result = decide(
            now,
            score=5.0,
            context=Context(exposed=True, serious_impact=False, known_exploitation=False),
            epss=stale,
        )
        assert result.epss_status == "unknown_or_stale"
        assert result.action is Action.TRACK_STAR

    def test_future_dated_intelligence_is_not_fresh(self, now):
        """Spec Section 10's required adversarial scenario."""
        future = Epss(probability=0.9, percentile=0.99, observed_at=now + timedelta(hours=2))
        assert not future.is_fresh(now)
        result = decide(
            now,
            score=5.0,
            context=Context(exposed=True, serious_impact=False, known_exploitation=False),
            epss=future,
        )
        assert result.epss_status == "unknown_or_stale"

    def test_absent_epss_is_unknown(self, now):
        assert decide(now).epss_status == "unknown_or_stale"

    def test_epss_at_exactly_the_freshness_limit_is_still_fresh(self, now):
        boundary = Epss(probability=0.2, percentile=0.9, observed_at=now - EPSS_FRESHNESS)
        assert boundary.is_fresh(now)

    def test_an_out_of_range_probability_is_refused(self, now):
        with pytest.raises(ValueError, match="EPSS probability"):
            Epss(probability=1.5, percentile=0.5, observed_at=now)

    def test_a_naive_observation_time_is_refused(self):
        from datetime import datetime

        with pytest.raises(ValueError, match="timezone-aware"):
            Epss(probability=0.2, percentile=0.5, observed_at=datetime(2026, 1, 1))

    def test_the_threshold_is_the_documented_proposal(self):
        assert EPSS_ACT_THRESHOLD == 0.10
        assert EPSS_FRESHNESS == timedelta(hours=48)


class TestSeparateDimensions:
    def test_the_environmental_reading_drives_the_decision(self, now):
        result = prioritize(
            source_severity=severity(4.0),
            environmental_severity=severity(9.5),
            context=QUIET,
            confidence=Confidence.CONFIRMED,
            now=now,
        )
        assert result.action is Action.ATTEND
        assert result.severity_score == 9.5

    def test_the_source_reading_is_never_mutated(self, now):
        source = severity(4.0)
        prioritize(
            source_severity=source,
            environmental_severity=severity(9.5),
            context=QUIET,
            confidence=Confidence.CONFIRMED,
            now=now,
        )
        assert source.score == 4.0
        assert source.vector.startswith("CVSS:4.0/")

    def test_confidence_does_not_reduce_severity(self, now):
        """Evidence confidence controls validation urgency, not severity."""
        confirmed = decide(now, score=9.0, confidence=Confidence.CONFIRMED)
        low = decide(now, score=9.0, confidence=Confidence.LOW)
        assert confirmed.action is low.action
        assert low.urgent_validation
        assert not confirmed.urgent_validation

    def test_no_combined_score_is_produced(self, now):
        """FIRST advises against multiplying EPSS by CVSS, so nothing does."""
        result = decide(now, score=8.0, epss=Epss(0.5, 0.9, now))
        assert not hasattr(result, "risk_score")
        assert not hasattr(result, "security_score")

    def test_an_out_of_range_cvss_score_is_refused(self):
        with pytest.raises(ValueError, match="0 to 10"):
            Severity(vector="x", score=11.0)

    def test_a_naive_now_is_refused(self):
        from datetime import datetime

        with pytest.raises(ValueError, match="timezone-aware"):
            prioritize(
                source_severity=severity(5.0),
                context=QUIET,
                confidence=Confidence.CONFIRMED,
                now=datetime(2026, 1, 1),
            )


class TestAcknowledgementTargets:
    def test_act_is_due_in_four_hours(self, now):
        result = decide(now, score=9.0, context=KNOWN)
        assert result.acknowledgement_due == now + timedelta(hours=4)

    def test_track_has_no_deadline_only_the_next_review(self, now):
        result = decide(now, score=1.0)
        assert result.action is Action.TRACK
        assert result.acknowledgement_due is None

    def test_every_action_has_a_declared_target(self):
        for action in Action:
            assert action in ACKNOWLEDGEMENT_TARGETS


class TestOverrides:
    def override(self, now, **changes):
        base = {
            "override_id": "ovr-1",
            "finding_id": "F-1001",
            "computed": Action.ATTEND,
            "override_to": Action.TRACK_STAR,
            "policy_version": POLICY_VERSION,
            "reviewer": "security.lead.kofi",
            "reason": "compensating network control confirmed",
            "evidence_reference": "CHG-4412",
            "created_at": now - timedelta(hours=1),
            "expires_at": now + timedelta(days=14),
        }
        base.update(changes)
        return Override(**base)

    def test_a_valid_override_applies(self, now):
        computed = decide(now, score=9.0)
        effective, decision = apply_override(computed, self.override(now), QUIET, now=now)
        assert decision.allowed
        assert effective.action is Action.TRACK_STAR
        assert "override by security.lead.kofi" in effective.reason

    def test_no_override_leaves_the_outcome_alone(self, now):
        computed = decide(now, score=9.0)
        effective, decision = apply_override(computed, None, QUIET, now=now)
        assert decision.allowed
        assert effective is computed

    def test_an_expired_override_recalculates_and_escalates_visibly(self, now):
        computed = decide(now, score=9.0)
        expired = self.override(
            now, created_at=now - timedelta(days=30), expires_at=now - timedelta(days=1)
        )
        effective, decision = apply_override(computed, expired, QUIET, now=now)
        assert not decision.allowed
        assert R.OVERRIDE_EXPIRED in decision.reasons
        # The computed outcome is restored, not silently kept at the override.
        assert effective.action is Action.ATTEND

    def test_known_exploitation_cannot_fall_below_attend(self, now):
        """U06's priority floor."""
        computed = decide(now, score=9.0, context=KNOWN)
        _, decision = apply_override(
            computed, self.override(now, override_to=Action.TRACK), KNOWN, now=now
        )
        assert R.PRIORITY_FLOOR_EXCEPTION_REQUIRED in decision.reasons

    def test_serious_impact_cannot_fall_below_attend(self, now):
        context = Context(exposed=False, serious_impact=True, known_exploitation=False)
        computed = decide(now, score=5.0, context=context)
        _, decision = apply_override(
            computed, self.override(now, override_to=Action.TRACK_STAR), context, now=now
        )
        assert R.PRIORITY_FLOOR_EXCEPTION_REQUIRED in decision.reasons

    def test_an_approved_exception_permits_falling_below_the_floor(self, now):
        computed = decide(now, score=9.0, context=KNOWN)
        effective, decision = apply_override(
            computed,
            self.override(
                now,
                override_to=Action.TRACK,
                exception_approved_by="executive.authority",
            ),
            KNOWN,
            now=now,
        )
        assert decision.allowed
        assert effective.action is Action.TRACK

    def test_the_floor_does_not_apply_without_exploitation_or_impact(self, now):
        computed = decide(now, score=9.0)
        effective, decision = apply_override(
            computed, self.override(now, override_to=Action.TRACK), QUIET, now=now
        )
        assert decision.allowed
        assert effective.action is Action.TRACK

    @pytest.mark.parametrize("missing", ["reviewer", "reason", "evidence_reference"])
    def test_an_override_requires_reviewer_reason_and_evidence(self, now, missing):
        computed = decide(now, score=9.0)
        _, decision = apply_override(computed, self.override(now, **{missing: ""}), QUIET, now=now)
        assert R.DISPOSITION_REVIEWER_REQUIRED in decision.reasons

    def test_an_override_cannot_rewrite_the_imported_observation(self, now):
        """U06: overrides never permanently rewrite imported observations."""
        computed = decide(now, score=9.0)
        effective, _ = apply_override(computed, self.override(now), QUIET, now=now)
        assert computed.action is Action.ATTEND
        assert effective is not computed
        assert effective.severity_score == computed.severity_score
