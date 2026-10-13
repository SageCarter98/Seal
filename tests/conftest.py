"""Shared fixtures.

Every fixture here is synthetic. The approval and proof booleans are *test
inputs*, exactly as the spec requires them to be read: "Supplied approval and
proof booleans are test inputs, not trusted production evidence."
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from seal.core._canonical import digest, utc
from seal.core.authorization import (
    Authorization,
    JobRequest,
    PolicyState,
)
from seal.core.coverage import CoverageManifest, CoverageStatus, ToolRevisions
from seal.core.egress import RegisteredTarget
from seal.core.integrity import Admission, IntegrityState
from seal.core.lifecycle import Finding, State

ORG = "org-lab-1"
OTHER_ORG = "org-lab-2"
TARGET = "target-lab-web-1"
PROFILE = digest({"profile": "passive-web-v1"})
OWNERSHIP = digest({"permission": "written-owned-lab-permission"})
NOW = utc(2026, 10, 12, 12, 0, 0)


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def authorization() -> Authorization:
    return Authorization(
        authorization_id="auth-1",
        organization=ORG,
        target_id=TARGET,
        ownership_evidence_digest=OWNERSHIP,
        profile_digest=PROFILE,
        starts=NOW - timedelta(hours=1),
        expires=NOW + timedelta(hours=4),
        requester="assessor.ama",
        approver="security.lead.kofi",
        revision=1,
        owned_lab=True,
        emergency_contacts=("owner@lab.invalid",),
    )


@pytest.fixture
def job_request() -> JobRequest:
    return JobRequest(
        organization=ORG,
        target_id=TARGET,
        profile_digest=PROFILE,
        authorization_revision=1,
        method="GET",
        job_id="job-1",
    )


@pytest.fixture
def policy_state() -> PolicyState:
    """A fully healthy trusted-service snapshot. Tests degrade it per scenario."""
    return PolicyState(
        organization=ORG,
        member_organizations=frozenset({ORG}),
        authorization_revision=1,
        revoked=False,
        observed_at=NOW,
        available=True,
        phase0_approved=True,
        stop_active=False,
        integrity_trusted=True,
    )


@pytest.fixture
def registered_target() -> RegisteredTarget:
    return RegisteredTarget(
        target_id=TARGET,
        organization=ORG,
        scheme="https",
        host="lab.internal.invalid",
        port=443,
        approved_paths=("/app", "/api/v1"),
        excluded_paths=("/app/admin",),
        lab_addresses=frozenset({"10.10.0.5"}),
    )


@pytest.fixture
def revisions() -> ToolRevisions:
    return ToolRevisions(
        scanner_image_digest=digest({"image": "zap@sha256:synthetic"}),
        rule_digest=digest({"rules": "passive-baseline-v1"}),
        adapter_version="zap-adapter-0.1.0",
        schema_version="adapter-result-1",
        transformation_version="normalize-1",
    )


EXPECTED_CHECKS = frozenset({"check.a", "check.b", "check.c"})


@pytest.fixture
def expected_checks() -> frozenset[str]:
    return EXPECTED_CHECKS


@pytest.fixture
def complete_manifest(revisions) -> CoverageManifest:
    return CoverageManifest(
        job_id="job-1",
        organization=ORG,
        target_id=TARGET,
        target_revision="rev-fixed-2",
        profile_digest=PROFILE,
        revisions=revisions,
        started=NOW - timedelta(minutes=10),
        ended=NOW - timedelta(minutes=1),
        authorized_scope=("/app", "/api/v1"),
        checks_attempted=EXPECTED_CHECKS,
        checks_completed=EXPECTED_CHECKS,
        findings=0,
        healthy=True,
    )


@pytest.fixture
def trusted_integrity() -> IntegrityState:
    return IntegrityState(admission=Admission.TRUSTED, generation=7, observed_at=NOW)


@pytest.fixture
def pending_finding() -> Finding:
    """A High-severity finding in Verification pending with a recorded fix.

    Severity 8.0 puts it above ``ANCHOR_REQUIRED_SEVERITY``, so closure must
    pass through the C01 anchor substate -- which is the interesting path.
    """
    return Finding(
        finding_id="F-1001",
        organization=ORG,
        target_id=TARGET,
        fingerprint=digest({"fp": "web-xss-login-q"}),
        rule="zap.40012",
        profile_digest=PROFILE,
        state=State.VERIFICATION_PENDING,
        version=4,
        assessor="assessor.ama",
        remediation_owner="dev.yaw",
        severity_score=8.0,
        fixed_revision="rev-fixed-2",
        fixed_at=NOW - timedelta(hours=2),
        observation_watermark="obs-7",
    )


@pytest.fixture
def complete_coverage() -> CoverageStatus:
    return CoverageStatus.COMPLETE
