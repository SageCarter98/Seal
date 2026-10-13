"""U01 -- the authorization contract.

Spec Section 3: check authorization before queueing, at dispatch, after a retry
or lease renewal, and before each outbound request. A scanner's assertion that
it is authorized is insufficient, so nothing here reads a worker-supplied claim:
every input is either a stored authorization version or trusted-service state.

Fails closed. Loss of the policy service or of current revocation information is
a denial, not a pass -- see ``PolicyState``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum

from . import reasons as R
from ._canonical import digest, is_digest, require_aware
from .decision import Decision, evaluate


class Checkpoint(str, Enum):
    """The four points spec Section 3 requires a revalidation at.

    They are distinct values rather than one flag because the acceptance tests
    assert that a job denied at one checkpoint is denied at the later ones too
    (U01: "revoked and stale jobs denied"), which needs the checkpoint recorded
    in the audit event.
    """

    QUEUE = "queue"
    DISPATCH = "dispatch"
    RENEWAL = "renewal"
    REQUEST = "request"


#: How stale trusted state may be before it stops counting as current. Spec
#: Section 3 requires failing closed on "loss of the policy service or current
#: revocation information"; C02 adds "unavailable/stale integrity or revocation
#: state". This ceiling is a reviewable proposal pending D06, not a measured
#: control.
MAX_STATE_AGE = timedelta(seconds=30)


@dataclass(frozen=True)
class Authorization:
    """One immutable version of a written authorization to assess a target.

    Spec Section 3: "An amendment creates a new version. Queue entries reference
    a version; they never silently inherit expanded permissions." So this is
    frozen and carries ``revision`` -- an amendment constructs a new instance,
    and a queue entry that still names the old revision is stale, not upgraded.
    """

    authorization_id: str
    organization: str
    target_id: str
    ownership_evidence_digest: str
    profile_digest: str
    starts: datetime
    expires: datetime
    requester: str
    approver: str
    revision: int = 1
    revoked: bool = False
    owned_lab: bool = True
    allowed_methods: frozenset[str] = frozenset({"GET", "HEAD"})
    emergency_contacts: tuple[str, ...] = ()

    def amend(self, **changes: object) -> Authorization:
        """Return the next revision. Never mutates the version in place."""
        if "revision" in changes:
            raise ValueError("revision is assigned by amend, not by the caller")
        return replace(self, revision=self.revision + 1, **changes)

    def revoke(self) -> Authorization:
        return replace(self, revoked=True, revision=self.revision + 1)


@dataclass(frozen=True)
class PolicyState:
    """A snapshot of trusted-service state, as read at the decision point.

    ``available`` is explicit so a caller that could not reach the policy
    service passes ``PolicyState.unavailable(...)`` rather than omitting the
    argument -- a missing policy answer must be a denial that says so, and an
    optional argument defaulting to "fine" is exactly the ambiguity U01 exists
    to remove.
    """

    organization: str
    member_organizations: frozenset[str]
    authorization_revision: int
    revoked: bool
    observed_at: datetime
    available: bool = True
    phase0_approved: bool = False
    stop_active: bool = False
    integrity_trusted: bool = False

    @classmethod
    def unavailable(cls, *, observed_at: datetime) -> PolicyState:
        """The fail-closed snapshot: no membership, revoked, nothing approved."""
        return cls(
            organization="",
            member_organizations=frozenset(),
            authorization_revision=-1,
            revoked=True,
            observed_at=observed_at,
            available=False,
        )

    def is_fresh(self, now: datetime, max_age: timedelta = MAX_STATE_AGE) -> bool:
        if require_aware(observed_at=self.observed_at, now=now):
            return False
        age = now - self.observed_at
        return timedelta(0) <= age <= max_age


@dataclass(frozen=True)
class JobRequest:
    """What a caller is asking to do, as the trusted core understands it.

    ``organization`` is derived from authenticated membership by the caller and
    cross-checked against ``PolicyState`` here; U09 forbids trusting an
    organization taken from a request body or URL, and the cross-check is what
    makes a mismatch a ``TENANT_MISMATCH`` denial instead of a silent switch.
    """

    organization: str
    target_id: str
    profile_digest: str
    authorization_revision: int
    method: str = "GET"
    job_id: str = ""


def authorize(
    authorization: Authorization,
    request: JobRequest,
    state: PolicyState,
    *,
    checkpoint: Checkpoint,
    now: datetime,
) -> Decision:
    """Evaluate one authorization checkpoint. Returns every failing contract."""
    naive = require_aware(starts=authorization.starts, expires=authorization.expires, now=now)

    checks: list[tuple[bool, str]] = [
        (state.available, R.POLICY_STATE_UNAVAILABLE),
        (state.is_fresh(now), R.REVOCATION_STATE_STALE),
        (state.phase0_approved, R.PHASE0_NOT_APPROVED),
        (state.integrity_trusted, R.INTEGRITY_UNTRUSTED),
        (not state.stop_active, R.STOP_ACTIVE),
        # Owned-lab only until the separate regulatory, privacy and
        # written-target authorization gates are satisfied (spec Section 3).
        (authorization.owned_lab, R.EXTERNAL_TARGET_DISABLED),
        (
            bool(request.organization) and request.organization in state.member_organizations,
            R.MEMBERSHIP_REQUIRED,
        ),
        (
            bool(request.organization)
            and authorization.organization == request.organization == state.organization,
            R.TENANT_MISMATCH,
        ),
        (
            bool(request.target_id) and authorization.target_id == request.target_id,
            R.TARGET_MISMATCH,
        ),
        (
            bool(request.profile_digest) and authorization.profile_digest == request.profile_digest,
            R.PROFILE_MISMATCH,
        ),
        # Both the stored version and the trusted service must agree the
        # requested revision is current. An amendment elsewhere makes a queued
        # job stale rather than more permissive.
        (
            authorization.revision
            == request.authorization_revision
            == state.authorization_revision,
            R.STALE_AUTHORIZATION,
        ),
        (not authorization.revoked and not state.revoked, R.AUTHORIZATION_REVOKED),
        (
            bool(authorization.requester)
            and bool(authorization.approver)
            and authorization.requester != authorization.approver,
            R.INDEPENDENT_APPROVER_REQUIRED,
        ),
        (is_digest(authorization.ownership_evidence_digest), R.AUTHORIZATION_EVIDENCE_REQUIRED),
        (request.method in authorization.allowed_methods, R.METHOD_NOT_AUTHORIZED),
    ]

    if naive:
        checks.append((False, R.UTC_AWARE_TIME_REQUIRED))
    else:
        checks.append((authorization.starts <= now < authorization.expires, R.OUTSIDE_WINDOW))

    return evaluate(
        checks,
        checkpoint=checkpoint.value,
        authorization_id=authorization.authorization_id,
        revision=authorization.revision,
        job_id=request.job_id,
    )


# ---------------------------------------------------------------------------
# Execution grants
# ---------------------------------------------------------------------------

#: Only the orchestrator in the trusted core may mint a grant. Spec Section 3:
#: "workers cannot mint or extend it." The issuer is a constant string here
#: because the pure core has no identity provider; the real platform replaces
#: this with a signed, short-lived credential from the trusted issuer.
TRUSTED_GRANT_ISSUER = "seal.orchestrator"


@dataclass(frozen=True)
class RequestBudget:
    """Per-target ceilings from spec Section 4.

    Proposed initial limits, described there as "reviewable ceilings, not
    evidence of harmlessness". They need D06 and D10 approval before they mean
    anything operationally.
    """

    requests_per_second: float = 1.0
    max_in_flight: int = 1
    max_requests: int = 1000
    max_response_bytes: int = 1024 * 1024
    request_timeout_seconds: float = 10.0


@dataclass(frozen=True)
class ExecutionGrant:
    """A short-lived permission to emit traffic, validated again at egress.

    Binds organization, job, target, profile, destination limits and expiry.
    ``integrity_generation`` is what makes C02 enforceable: when integrity
    becomes Untrusted the generation increments, and every outstanding grant
    stops validating without anyone having to find and delete it.
    """

    grant_id: str
    organization: str
    job_id: str
    target_id: str
    profile_digest: str
    authorization_revision: int
    destination: str
    expires: datetime
    integrity_generation: int
    issuer: str = TRUSTED_GRANT_ISSUER
    budget: RequestBudget = field(default_factory=RequestBudget)

    @property
    def binding_digest(self) -> str:
        """Digest of everything the grant is bound to, for audit reference."""
        return digest(
            {
                "organization": self.organization,
                "job_id": self.job_id,
                "target_id": self.target_id,
                "profile_digest": self.profile_digest,
                "authorization_revision": self.authorization_revision,
                "destination": self.destination,
            }
        )


def validate_grant(
    grant: ExecutionGrant,
    request: JobRequest,
    *,
    destination: str,
    now: datetime,
    current_integrity_generation: int,
    requests_made: int = 0,
    in_flight: int = 0,
) -> Decision:
    """Validate a grant at the egress boundary.

    Spec Section 3 puts grant validation "at the egress boundary as well as the
    worker", which is why this takes the current integrity generation from
    trusted state rather than reading it back out of the grant it is checking.
    """
    naive = require_aware(expires=grant.expires, now=now)

    checks: list[tuple[bool, str]] = [
        (grant.issuer == TRUSTED_GRANT_ISSUER, R.GRANT_NOT_TRUSTED_ISSUER),
        (
            grant.organization == request.organization
            and grant.job_id == request.job_id
            and grant.target_id == request.target_id
            and grant.profile_digest == request.profile_digest
            and grant.authorization_revision == request.authorization_revision
            and grant.destination == destination,
            R.GRANT_BINDING_MISMATCH,
        ),
        (grant.integrity_generation == current_integrity_generation, R.GRANT_GENERATION_STALE),
        (requests_made < grant.budget.max_requests, R.GRANT_BUDGET_EXCEEDED),
        (in_flight < grant.budget.max_in_flight, R.CONCURRENCY_LIMIT_EXCEEDED),
    ]

    if naive:
        checks.append((False, R.UTC_AWARE_TIME_REQUIRED))
    else:
        checks.append((now < grant.expires, R.GRANT_EXPIRED))

    return evaluate(checks, grant_id=grant.grant_id, destination=destination)
