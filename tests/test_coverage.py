"""U03 -- the coverage contract.

Acceptance evidence: "Partial scan cannot appear clean". The ZAP exit-status
problem from spec Section 4 is the motivating case: no test here consults a
process exit value, because the production code must not either.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from seal.core import reasons as R
from seal.core.coverage import (
    CoverageExpectation,
    CoverageStatus,
    assessed_coverage,
    classify,
    verify_manifest,
)


class TestClassification:
    def test_all_expected_checks_completed_is_complete(self, complete_manifest, expected_checks):
        assert classify(complete_manifest, expected_checks) is CoverageStatus.COMPLETE

    def test_a_missing_check_is_partial_not_complete(self, complete_manifest, expected_checks):
        """The core U03 case: incomplete coverage cannot read as clean."""
        partial = replace(complete_manifest, checks_completed=frozenset({"check.a", "check.b"}))
        assert classify(partial, expected_checks) is CoverageStatus.PARTIAL

    def test_a_skipped_check_leaves_the_result_partial(self, complete_manifest, expected_checks):
        partial = replace(
            complete_manifest,
            checks_completed=frozenset({"check.a", "check.b"}),
            checks_skipped=frozenset({"check.c"}),
        )
        assert classify(partial, expected_checks) is CoverageStatus.PARTIAL

    def test_an_unsupported_check_is_never_a_passed_check(self, complete_manifest, expected_checks):
        """Unsupported checks cannot be represented as passed checks."""
        unsupported = replace(
            complete_manifest,
            checks_completed=frozenset({"check.a", "check.b"}),
            checks_unsupported=frozenset({"check.c"}),
        )
        assert classify(unsupported, expected_checks) is CoverageStatus.PARTIAL

    def test_a_failed_check_is_failed(self, complete_manifest, expected_checks):
        failed = replace(complete_manifest, checks_failed=frozenset({"check.c"}))
        assert classify(failed, expected_checks) is CoverageStatus.FAILED

    def test_unhealthy_is_failed_even_with_every_check_completed(
        self, complete_manifest, expected_checks
    ):
        unhealthy = replace(complete_manifest, healthy=False)
        assert classify(unhealthy, expected_checks) is CoverageStatus.FAILED

    def test_a_stopped_job_is_stopped_even_if_all_checks_finished(
        self, complete_manifest, expected_checks
    ):
        """C02: affected coverage is never Complete by default."""
        stopped = replace(complete_manifest, stopped=True, stop_cause="integrity_untrusted")
        assert classify(stopped, expected_checks) is CoverageStatus.STOPPED

    def test_truncation_is_partial(self, complete_manifest, expected_checks):
        truncated = replace(complete_manifest, truncated=True)
        assert classify(truncated, expected_checks) is CoverageStatus.PARTIAL

    def test_nothing_attempted_is_not_assessed(self, complete_manifest, expected_checks):
        nothing = replace(
            complete_manifest, checks_attempted=frozenset(), checks_completed=frozenset()
        )
        assert classify(nothing, expected_checks) is CoverageStatus.NOT_ASSESSED

    def test_no_expectation_is_not_assessed_not_complete(self, complete_manifest):
        """A scan with nothing expected has proved nothing."""
        assert classify(complete_manifest, frozenset()) is CoverageStatus.NOT_ASSESSED

    def test_only_complete_proves_coverage(self):
        proving = [s for s in CoverageStatus if s.proves_coverage]
        assert proving == [CoverageStatus.COMPLETE]


class TestAssessedCoverage:
    def test_ratio_and_denominator_are_both_reported(self, complete_manifest, expected_checks):
        report = assessed_coverage(complete_manifest, expected_checks)
        assert report.ratio == 1.0
        assert report.expected == 3
        assert report.completed == 3

    def test_partial_ratio_shows_the_shortfall(self, complete_manifest, expected_checks):
        partial = replace(complete_manifest, checks_completed=frozenset({"check.a", "check.b"}))
        report = assessed_coverage(partial, expected_checks)
        assert report.completed == 2
        assert report.expected == 3
        assert report.missing == ("check.c",)

    def test_zero_denominator_is_not_available_rather_than_one(self, complete_manifest):
        """U13: a zero denominator is Not available, never 100%."""
        report = assessed_coverage(complete_manifest, frozenset())
        assert report.ratio is None
        assert report.available is False
        assert report.as_display()["assessed_coverage"] == "Not available"

    def test_completed_out_of_scope_checks_do_not_inflate_the_numerator(
        self, complete_manifest, expected_checks
    ):
        """Completing eight checks nobody expected is not 8/3 coverage."""
        extra = replace(
            complete_manifest,
            checks_completed=expected_checks | {"check.x", "check.y"},
        )
        report = assessed_coverage(extra, expected_checks)
        assert report.completed == 3
        assert report.ratio == 1.0

    def test_unsupported_scope_is_shown_separately(self, complete_manifest, expected_checks):
        manifest = replace(complete_manifest, checks_unsupported=frozenset({"check.sqli-active"}))
        display = assessed_coverage(manifest, expected_checks).as_display()
        assert display["unsupported"] == ["check.sqli-active"]

    def test_display_carries_the_honest_context_u13_requires(
        self, complete_manifest, expected_checks
    ):
        display = assessed_coverage(complete_manifest, expected_checks).as_display()
        for key in (
            "status",
            "assessed_coverage",
            "completed",
            "expected",
            "unsupported",
            "skipped",
            "failed",
            "not_assessed",
            "truncated",
        ):
            assert key in display


class TestManifestVerification:
    def test_a_valid_manifest_verifies(self, complete_manifest, expected_checks, now):
        decision = verify_manifest(
            complete_manifest,
            expected_checks=expected_checks,
            committed_digest=complete_manifest.content_digest,
            now=now,
        )
        assert decision.allowed, decision.reasons

    def test_a_missing_manifest_is_refused(self, expected_checks, now):
        """Spec Section 5: an absent manifest is inconclusive, not proof."""
        decision = verify_manifest(
            None, expected_checks=expected_checks, committed_digest="x", now=now
        )
        assert R.MANIFEST_MISSING in decision.reasons

    def test_a_tampered_manifest_is_detected(self, complete_manifest, expected_checks, now):
        committed = complete_manifest.content_digest
        tampered = replace(complete_manifest, findings=0, checks_failed=frozenset())
        tampered = replace(tampered, target_revision="rev-other")
        decision = verify_manifest(
            tampered, expected_checks=expected_checks, committed_digest=committed, now=now
        )
        assert R.MANIFEST_DIGEST_MISMATCH in decision.reasons

    def test_incomplete_coverage_fails_verification(self, complete_manifest, expected_checks, now):
        partial = replace(complete_manifest, checks_completed=frozenset({"check.a"}))
        decision = verify_manifest(
            partial,
            expected_checks=expected_checks,
            committed_digest=partial.content_digest,
            now=now,
        )
        assert R.COVERAGE_INCOMPLETE in decision.reasons

    def test_unsupported_expected_checks_are_flagged(self, complete_manifest, expected_checks, now):
        """A profile promising coverage the adapter cannot deliver is a scope problem."""
        manifest = replace(complete_manifest, checks_unsupported=frozenset({"check.c"}))
        decision = verify_manifest(
            manifest,
            expected_checks=expected_checks,
            committed_digest=manifest.content_digest,
            now=now,
        )
        assert R.UNSUPPORTED_CHECKS_PRESENT in decision.reasons

    def test_a_future_dated_manifest_is_refused(self, complete_manifest, expected_checks, now):
        future = replace(
            complete_manifest,
            started=now + timedelta(hours=1),
            ended=now + timedelta(hours=2),
        )
        decision = verify_manifest(
            future,
            expected_checks=expected_checks,
            committed_digest=future.content_digest,
            now=now,
        )
        assert R.STALE_OR_FUTURE_VERIFICATION in decision.reasons

    def test_missing_expectation_is_refused(self, complete_manifest, now):
        decision = verify_manifest(
            complete_manifest,
            expected_checks=frozenset(),
            committed_digest=complete_manifest.content_digest,
            now=now,
        )
        assert R.COVERAGE_EXPECTATION_MISSING in decision.reasons


class TestPinnedRevisions:
    def test_the_revision_digest_covers_every_pinned_input(self, revisions):
        """U10: a changed rule, adapter or advisory database changes the digest."""
        baseline = revisions.revision_digest
        assert replace(revisions, rule_digest="other").revision_digest != baseline
        assert replace(revisions, adapter_version="0.2.0").revision_digest != baseline
        assert replace(revisions, transformation_version="normalize-2").revision_digest != baseline

    def test_manifest_digest_changes_when_revisions_change(self, complete_manifest, revisions):
        altered = replace(complete_manifest, revisions=replace(revisions, rule_digest="changed"))
        assert altered.content_digest != complete_manifest.content_digest

    def test_expectation_separates_supported_from_promised(self):
        expectation = CoverageExpectation(
            profile_digest="p",
            version=1,
            checks=frozenset({"a", "b", "c"}),
            unsupported_by_adapter=frozenset({"c"}),
        )
        assert expectation.supported == frozenset({"a", "b"})


@pytest.mark.parametrize(
    ("stopped", "failed", "truncated", "expected"),
    [
        (True, False, False, CoverageStatus.STOPPED),
        (False, True, False, CoverageStatus.FAILED),
        (False, False, True, CoverageStatus.PARTIAL),
        (True, True, True, CoverageStatus.STOPPED),
    ],
)
def test_no_optimistic_signal_can_promote_a_result(
    complete_manifest, expected_checks, stopped, failed, truncated, expected
):
    """Ordering check: the most serious condition always wins."""
    manifest = replace(
        complete_manifest,
        stopped=stopped,
        checks_failed=frozenset({"check.c"}) if failed else frozenset(),
        truncated=truncated,
    )
    assert classify(manifest, expected_checks) is expected
