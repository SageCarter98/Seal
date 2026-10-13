"""U12 -- recovery without duplicate or unauthorized execution.

Spec Section 8: "Queue messages carry an idempotency key and lease generation.
Only one current lease may execute a job. A retry rechecks authorization,
revocation, profile, stop state and remaining budget; it does not replay a prior
HTTP request automatically. Persist checkpoints without credentials or raw
private responses. A stopped job remains stopped across restarts."

Note what this module does not contain: there is no ``replay`` function, and no
stored request to replay. ``may_retry`` answers "may a fresh attempt be made",
which requires all five rechecks to pass; it never hands back a recorded
request to reissue. The automatic replay spec Section 8 forbids has no
implementation here to call, which is a stronger guarantee than a rule saying
not to call it.

The v1.3 recovery targets are carried forward as constants and measured by
``recovery_within_targets``. An unmeasured target is reported as unverified, not
satisfied -- the same rule the coverage contract applies to unassessed scope.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from . import reasons as R
from ._canonical import digest, require_aware
from .decision import Decision, allow, deny, evaluate

#: Carried forward from v1.3 (spec Section 8).
FAILED_WORKER_DETECTION_TARGET = timedelta(seconds=30)
SAFE_FAIL_DECISION_TARGET = timedelta(minutes=5)
QUEUE_RECOVERY_TARGET = timedelta(minutes=15)

#: Bounded retries (F06). A reviewable ceiling, not a measured control.
MAX_ATTEMPTS = 5

#: A checkpoint holds progress state. Spec Section 8 forbids credentials and
#: raw private responses in it, so these field names are refused outright
#: rather than redacted -- a redaction still means the value reached us.
CREDENTIAL_FIELD_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "cookie",
    "session",
    "private_key",
    "credential",
    "bearer",
)

RAW_RESPONSE_FIELD_MARKERS = (
    "response_body",
    "raw_response",
    "body",
    "content",
    "payload",
    "html",
)

#: Progress state is small by nature. A large checkpoint means something that
#: does not belong in one has been put there.
MAX_CHECKPOINT_BYTES = 16 * 1024


@dataclass(frozen=True)
class QueueMessage:
    """One delivery of a job.

    ``idempotency_key`` is what dedupes, not ``message_id``: an at-least-once
    queue redelivers the same work under a fresh envelope, so keying on the
    envelope would let duplicate work straight through.
    """

    message_id: str
    idempotency_key: str
    job_id: str
    organization: str
    lease_generation: int
    attempt: int
    enqueued_at: datetime


class DeliveryLog:
    """Records which (organization, idempotency key) pairs have been admitted.

    Tenant-scoped on purpose. A shared key namespace would let one tenant
    suppress another tenant's job by guessing or observing a key.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    @staticmethod
    def _scope(organization: str, key: str) -> str:
        return digest({"organization": organization, "idempotency_key": key})

    def has_seen(self, organization: str, key: str) -> bool:
        return self._scope(organization, key) in self._seen

    def record(self, organization: str, key: str) -> None:
        self._seen.add(self._scope(organization, key))

    #: Keys recorded, for reporting only.
    def __len__(self) -> int:
        return len(self._seen)


def admit_delivery(message: QueueMessage, log: DeliveryLog) -> Decision:
    """Admit one queue delivery, or refuse it as a duplicate.

    Records the key on admission, so a redelivery of the same work is refused
    even if it arrives under a different message id or a later generation.
    """
    if not message.idempotency_key:
        return deny(R.IDEMPOTENCY_KEY_REQUIRED, message_id=message.message_id)
    if not message.organization:
        return deny(R.CHAIN_TENANT_MISMATCH, note="a delivery belongs to one organization")

    if log.has_seen(message.organization, message.idempotency_key):
        return deny(
            R.DUPLICATE_DELIVERY,
            idempotency_key=message.idempotency_key,
            message_id=message.message_id,
        )

    log.record(message.organization, message.idempotency_key)
    return allow(idempotency_key=message.idempotency_key, job_id=message.job_id)


@dataclass(frozen=True)
class Lease:
    """The right to execute one job, held by one worker at a time."""

    lease_id: str
    job_id: str
    organization: str
    generation: int
    holder: str
    acquired_at: datetime
    expires_at: datetime

    def is_current(self, now: datetime) -> bool:
        if require_aware(acquired_at=self.acquired_at, expires_at=self.expires_at, now=now):
            return False
        return self.acquired_at <= now < self.expires_at


def acquire_lease(
    *,
    current: Lease | None,
    requested: Lease,
    now: datetime,
    current_generation: int | None = None,
) -> Decision:
    """Whether a worker may take the lease for a job.

    Refuses while another lease is current. An expired lease may be taken over,
    which is how a failed worker's job becomes executable again -- but only
    under the current generation, so a worker returning from a partition cannot
    resume on a stale one.
    """
    if require_aware(now=now):
        return deny(R.UTC_AWARE_TIME_REQUIRED)

    generation = current_generation if current_generation is not None else requested.generation

    checks: list[tuple[bool, str]] = [
        (bool(requested.organization), R.CHAIN_TENANT_MISMATCH),
        (requested.generation == generation, R.LEASE_GENERATION_STALE),
        (requested.is_current(now), R.GRANT_EXPIRED),
    ]

    if current is not None:
        checks.append((current.organization == requested.organization, R.CHAIN_TENANT_MISMATCH))
        checks.append((current.job_id == requested.job_id, R.LEASE_JOB_MISMATCH))
        # The decisive check: an existing lease that is still current blocks
        # every contender, so only one worker ever executes the job.
        checks.append((not current.is_current(now), R.LEASE_ALREADY_HELD))

    return evaluate(
        checks,
        job_id=requested.job_id,
        holder=requested.holder,
        generation=requested.generation,
    )


@dataclass(frozen=True)
class RetryContext:
    """The five conditions spec Section 8 requires a retry to recheck.

    Separate named fields rather than one "ok" flag, so a caller cannot satisfy
    the contract without having actually consulted each source.
    """

    authorization_valid: bool
    revoked: bool
    profile_unchanged: bool
    stop_active: bool
    remaining_request_budget: int


def may_retry(
    message: QueueMessage,
    context: RetryContext,
    *,
    now: datetime,
    max_attempts: int = MAX_ATTEMPTS,
) -> Decision:
    """Whether a fresh attempt at this job may proceed.

    Every failing condition is reported together, so an operator sees all five
    problems at once rather than discovering them one restart at a time.

    This grants permission to *attempt* the job again under renewed checks. It
    does not return, reconstruct or authorize the reissue of any earlier
    request.
    """
    if require_aware(now=now):
        return deny(R.UTC_AWARE_TIME_REQUIRED)

    checks: list[tuple[bool, str]] = [
        (context.authorization_valid, R.STALE_AUTHORIZATION),
        (not context.revoked, R.AUTHORIZATION_REVOKED),
        (context.profile_unchanged, R.PROFILE_MISMATCH),
        # A stop persists across restarts: nothing about a new attempt, a new
        # generation or a restarted service clears it.
        (not context.stop_active, R.STOP_ACTIVE),
        (context.remaining_request_budget > 0, R.GRANT_BUDGET_EXCEEDED),
        (message.attempt <= max_attempts, R.RETRY_LIMIT_EXCEEDED),
    ]

    return evaluate(
        checks,
        job_id=message.job_id,
        attempt=message.attempt,
        remaining_budget=context.remaining_request_budget,
    )


def _field_names(value: Any, depth: int = 0) -> list[str]:
    """Collect every key name in a nested structure, for marker matching."""
    if depth > 16 or not isinstance(value, dict):
        return []
    names: list[str] = []
    for key, nested in value.items():
        if isinstance(key, str):
            names.append(key)
        names.extend(_field_names(nested, depth + 1))
        if isinstance(nested, list):
            for item in nested:
                names.extend(_field_names(item, depth + 1))
    return names


def checkpoint_is_safe(checkpoint: Any) -> Decision:
    """Whether a checkpoint may be persisted.

    Field names are matched case-insensitively and at any nesting depth, since a
    captured header map is the usual way a cookie or bearer token arrives inside
    otherwise innocuous progress state.
    """
    if not isinstance(checkpoint, dict):
        return deny(R.FIELD_TYPE_INVALID, note="a checkpoint must be an object")

    names = [name.lower() for name in _field_names(checkpoint)]

    credential_hits = sorted(
        {name for name in names if any(marker in name for marker in CREDENTIAL_FIELD_MARKERS)}
    )
    raw_hits = sorted(
        {name for name in names if any(marker in name for marker in RAW_RESPONSE_FIELD_MARKERS)}
    )

    try:
        # Measured over the canonical serialization, so the ceiling means the
        # same thing here as it will in storage.
        size = len(
            json.dumps(checkpoint, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
        )
    except (TypeError, ValueError):
        return deny(R.FIELD_TYPE_INVALID, note="checkpoint is not serializable")

    return evaluate(
        [
            (not credential_hits, R.CHECKPOINT_CONTAINS_CREDENTIAL),
            (not raw_hits, R.CHECKPOINT_CONTAINS_RAW_RESPONSE),
            (size <= MAX_CHECKPOINT_BYTES, R.CHECKPOINT_TOO_LARGE),
        ],
        credential_fields=tuple(credential_hits),
        raw_response_fields=tuple(raw_hits),
        size_bytes=size,
    )


def recovery_within_targets(
    *,
    worker_detection: timedelta | None,
    fail_decision: timedelta | None,
    queue_recovery: timedelta | None,
) -> Decision:
    """Measure a recovery exercise against the v1.3 targets.

    A ``None`` measurement is ``MEASUREMENT_MISSING``, never a pass. Spec
    Section 8: "A backup existing is not proof that recovery works" -- and an
    unmeasured target is not a met one.
    """
    measurements = {
        "worker_detection": (worker_detection, FAILED_WORKER_DETECTION_TARGET),
        "fail_decision": (fail_decision, SAFE_FAIL_DECISION_TARGET),
        "queue_recovery": (queue_recovery, QUEUE_RECOVERY_TARGET),
    }

    missing = [name for name, (value, _) in measurements.items() if value is None]
    checks: list[tuple[bool, str]] = [(not missing, R.MEASUREMENT_MISSING)]

    exceeded = {
        "worker_detection": R.WORKER_DETECTION_TARGET_EXCEEDED,
        "fail_decision": R.FAIL_DECISION_TARGET_EXCEEDED,
        "queue_recovery": R.QUEUE_RECOVERY_TARGET_EXCEEDED,
    }
    for name, (value, target) in measurements.items():
        if value is not None:
            checks.append((value <= target, exceeded[name]))

    detail: dict[str, object] = {"missing": tuple(missing)}
    for name, (value, target) in measurements.items():
        detail[f"{name}_seconds"] = value.total_seconds() if value else None
        detail[f"{name}_target_seconds"] = target.total_seconds()

    return evaluate(checks, **detail)


@dataclass
class RecoveryRun:
    """A recorded recovery exercise, for the H02 evidence pack."""

    run_id: str
    performed_at: datetime
    worker_detection: timedelta | None = None
    fail_decision: timedelta | None = None
    queue_recovery: timedelta | None = None
    notes: str = ""
    restored_in_isolation: bool = False
    anchors_reconciled: bool = False
    evidence_digests_verified: bool = False
    jobs_reopened: tuple[str, ...] = field(default_factory=tuple)

    def readiness(self) -> Decision:
        """Spec Section 8's full restore condition, not just the timings.

        "Restore encrypted backups in an isolated environment, reconcile
        external anchors, and verify evidence digests before reopening jobs."
        """
        timings = recovery_within_targets(
            worker_detection=self.worker_detection,
            fail_decision=self.fail_decision,
            queue_recovery=self.queue_recovery,
        )
        checks: list[tuple[bool, str]] = [
            (timings.allowed, timings.reason or R.MEASUREMENT_MISSING),
            (self.restored_in_isolation, R.RESTORE_NOT_ISOLATED),
            (self.anchors_reconciled, R.ANCHORS_NOT_RECONCILED),
            (self.evidence_digests_verified, R.EVIDENCE_REQUIRED),
        ]
        return evaluate(checks, run_id=self.run_id, **timings.detail)
