"""U03 -- the coverage contract.

Spec Section 4 is blunt about why this exists: ZAP's ``passiveScan-wait`` waits
for queued passive work and its ``exitStatus`` can depend on alerts [R3], so a
process exit value cannot distinguish a completed clean assessment from partial
coverage. Nothing in this module reads an exit code. The manifest decides.

The rule this enforces everywhere: an unsupported check is not a passed check,
and "no findings" is only meaningful next to the scope that was actually
assessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from . import reasons as R
from ._canonical import digest, require_aware
from .decision import Decision, evaluate

#: Bumped when the manifest's canonical shape changes (U10).
MANIFEST_VERSION = 1


class CoverageStatus(str, Enum):
    """The five outcomes spec Section 4 requires results to distinguish.

    ``NOT_ASSESSED`` is for scope that was never attempted -- it is not a
    synonym for ``COMPLETE`` with nothing found, and keeping it separate is what
    stops a green screen overstating protection (U13).
    """

    COMPLETE = "Complete"
    PARTIAL = "Partial"
    FAILED = "Failed"
    STOPPED = "Stopped"
    NOT_ASSESSED = "Not assessed"

    @property
    def proves_coverage(self) -> bool:
        """Only ``COMPLETE`` may be used as proof of coverage for a closure."""
        return self is CoverageStatus.COMPLETE


@dataclass(frozen=True)
class ToolRevisions:
    """U10 -- everything that has to be pinned for a result to be reproducible.

    Spec Section 8 requires the scanner image digest, rule digest, advisory
    database digest and timestamp, adapter version, schema version and
    transformation version all recorded. A result missing any of these cannot be
    compared against a later one, which is what makes rule-equivalence review
    (U04) possible instead of guesswork.
    """

    scanner_image_digest: str
    rule_digest: str
    adapter_version: str
    schema_version: str
    transformation_version: str
    advisory_database_digest: str = ""
    advisory_database_at: datetime | None = None

    @property
    def revision_digest(self) -> str:
        return digest(
            {
                "scanner_image_digest": self.scanner_image_digest,
                "rule_digest": self.rule_digest,
                "adapter_version": self.adapter_version,
                "schema_version": self.schema_version,
                "transformation_version": self.transformation_version,
                "advisory_database_digest": self.advisory_database_digest,
                "advisory_database_at": (
                    self.advisory_database_at.isoformat() if self.advisory_database_at else None
                ),
            }
        )


@dataclass(frozen=True)
class CoverageManifest:
    """The versioned, tamper-evident record of what one job actually did.

    ``checks_*`` are sets of check identifiers rather than counts. Counts would
    let a job report "8 of 8 completed" while having completed eight checks
    nobody expected; comparing identifiers against ``expected_checks`` is the
    only way ``assessed_coverage`` means what U13 says it means.
    """

    job_id: str
    organization: str
    target_id: str
    target_revision: str
    profile_digest: str
    revisions: ToolRevisions
    started: datetime
    ended: datetime
    authorized_scope: tuple[str, ...]
    checks_attempted: frozenset[str] = frozenset()
    checks_completed: frozenset[str] = frozenset()
    checks_skipped: frozenset[str] = frozenset()
    checks_failed: frozenset[str] = frozenset()
    checks_unsupported: frozenset[str] = frozenset()
    findings: int = 0
    truncated: bool = False
    stopped: bool = False
    healthy: bool = True
    manifest_version: int = MANIFEST_VERSION
    #: Why a job stopped, when it did. Spec C02 requires the cause recorded
    #: rather than inferred.
    stop_cause: str = ""

    @property
    def content_digest(self) -> str:
        """Digest over the manifest's decision-relevant content.

        Tamper evidence in the real platform comes from this digest being
        committed to the audit chain; recomputing it and comparing is what
        ``verify_manifest`` does.
        """
        return digest(
            {
                "manifest_version": self.manifest_version,
                "job_id": self.job_id,
                "organization": self.organization,
                "target_id": self.target_id,
                "target_revision": self.target_revision,
                "profile_digest": self.profile_digest,
                "revisions": self.revisions.revision_digest,
                "started": self.started.isoformat(),
                "ended": self.ended.isoformat(),
                "authorized_scope": sorted(self.authorized_scope),
                "checks_attempted": sorted(self.checks_attempted),
                "checks_completed": sorted(self.checks_completed),
                "checks_skipped": sorted(self.checks_skipped),
                "checks_failed": sorted(self.checks_failed),
                "checks_unsupported": sorted(self.checks_unsupported),
                "findings": self.findings,
                "truncated": self.truncated,
                "stopped": self.stopped,
                "healthy": self.healthy,
                "stop_cause": self.stop_cause,
            }
        )


def classify(manifest: CoverageManifest, expected_checks: frozenset[str]) -> CoverageStatus:
    """Derive the coverage status from the manifest alone.

    Order matters and is deliberate: a stopped job is ``STOPPED`` even if every
    expected check happened to finish first, because C02 requires affected
    coverage marked "Stopped/Partial or Failed with the cause, never Complete by
    default". Failures outrank truncation, and truncation outranks a clean
    count, so no single optimistic signal can promote a result.
    """
    if not expected_checks:
        # Nothing was expected, so nothing can be claimed as assessed. This is
        # the honest answer, not an empty success.
        return CoverageStatus.NOT_ASSESSED
    if manifest.stopped:
        return CoverageStatus.STOPPED
    if not manifest.healthy or manifest.checks_failed:
        return CoverageStatus.FAILED
    if not manifest.checks_attempted:
        return CoverageStatus.NOT_ASSESSED
    if manifest.truncated:
        return CoverageStatus.PARTIAL

    outstanding = expected_checks - manifest.checks_completed
    if outstanding:
        # Everything left over is a skip, an unsupported check or a check that
        # simply never ran. None of those is a pass.
        return CoverageStatus.PARTIAL
    return CoverageStatus.COMPLETE


@dataclass(frozen=True)
class CoverageReport:
    """Assessed coverage with its denominator visible.

    U13 requires "Completed approved checks / expected approved checks; show
    unsupported scope separately" and a zero denominator reported as
    ``Not available`` -- so ``ratio`` is None rather than 1.0 when nothing was
    expected. A caller that wants a percentage has to handle the None.
    """

    status: CoverageStatus
    completed: int
    expected: int
    unsupported: tuple[str, ...]
    skipped: tuple[str, ...]
    failed: tuple[str, ...]
    missing: tuple[str, ...]
    truncated: bool
    stop_cause: str = ""

    @property
    def ratio(self) -> float | None:
        """Completed over expected, or None when the denominator is zero."""
        if self.expected == 0:
            return None
        return self.completed / self.expected

    @property
    def available(self) -> bool:
        return self.ratio is not None

    def as_display(self) -> dict[str, object]:
        """The shape U13 requires a screen to show -- never a bare percentage.

        Spec Section 1: "'No findings' must always appear beside assessed scope,
        skipped checks, scan health, revision and observation date."
        """
        return {
            "status": self.status.value,
            "assessed_coverage": "Not available" if self.ratio is None else round(self.ratio, 4),
            "completed": self.completed,
            "expected": self.expected,
            "unsupported": list(self.unsupported),
            "skipped": list(self.skipped),
            "failed": list(self.failed),
            "not_assessed": list(self.missing),
            "truncated": self.truncated,
            "stop_cause": self.stop_cause,
        }


def assessed_coverage(
    manifest: CoverageManifest, expected_checks: frozenset[str]
) -> CoverageReport:
    """Build the coverage report for a job, with unsupported scope separated."""
    completed_in_scope = manifest.checks_completed & expected_checks
    return CoverageReport(
        status=classify(manifest, expected_checks),
        completed=len(completed_in_scope),
        expected=len(expected_checks),
        unsupported=tuple(sorted(manifest.checks_unsupported)),
        skipped=tuple(sorted(manifest.checks_skipped)),
        failed=tuple(sorted(manifest.checks_failed)),
        missing=tuple(sorted(expected_checks - manifest.checks_completed)),
        truncated=manifest.truncated,
        stop_cause=manifest.stop_cause,
    )


def verify_manifest(
    manifest: CoverageManifest | None,
    *,
    expected_checks: frozenset[str],
    committed_digest: str,
    now: datetime,
) -> Decision:
    """Check a manifest is present, untampered and usable as coverage proof.

    ``committed_digest`` is the digest recorded in the audit chain when the job
    finished. Comparing against it here is what makes the manifest
    tamper-evident rather than merely hashed.
    """
    if manifest is None:
        return evaluate([(False, R.MANIFEST_MISSING)])

    naive = require_aware(started=manifest.started, ended=manifest.ended, now=now)
    status = classify(manifest, expected_checks)

    checks: list[tuple[bool, str]] = [
        (bool(expected_checks), R.COVERAGE_EXPECTATION_MISSING),
        (manifest.content_digest == committed_digest, R.MANIFEST_DIGEST_MISMATCH),
        (status.proves_coverage, R.COVERAGE_INCOMPLETE),
        (not manifest.truncated, R.RESULT_TRUNCATED),
        # Unsupported checks inside the expected set mean the profile promised
        # coverage the adapter cannot deliver. That is a scope problem to
        # resolve, not a result to accept.
        (not (manifest.checks_unsupported & expected_checks), R.UNSUPPORTED_CHECKS_PRESENT),
    ]

    if naive:
        checks.append((False, R.UTC_AWARE_TIME_REQUIRED))
    else:
        checks.append((manifest.started <= manifest.ended <= now, R.STALE_OR_FUTURE_VERIFICATION))

    return evaluate(
        checks,
        job_id=manifest.job_id,
        status=status.value,
        coverage=assessed_coverage(manifest, expected_checks).as_display(),
    )


@dataclass
class CoverageExpectation:
    """The checks a profile promises, as approved. Mutable by review only.

    Kept as its own type so the expected set is a reviewed artifact with a
    version, not an incidental argument. Spec Section 5 requires proving "the
    relevant route/control was reached and evaluated" -- that is only auditable
    if the expectation itself was recorded before the scan.
    """

    profile_digest: str
    version: int
    checks: frozenset[str] = field(default_factory=frozenset)
    unsupported_by_adapter: frozenset[str] = field(default_factory=frozenset)

    @property
    def supported(self) -> frozenset[str]:
        return self.checks - self.unsupported_by_adapter
