"""U04 + C01 -- closure as a proof decision, and stale-intent rejection.

Closure happens in two stages, and conflating them is the bug C01 was written
to fix:

1. ``review_closure`` -- the proof review. Same organization, target, finding
   identity and tested control; the approved verification profile; successful
   coverage; a scan after the recorded fix; the repaired artifact revision;
   valid authorization; sanitized evidence and digest; and a reviewer
   independent of both assessor and fixer. An absent alert alone never proves
   closure.

2. ``finalize`` -- C01. After a receipt arrives and has been independently
   verified, the closure commits only if *nothing has changed since the intent
   was recorded*: the intent is still current, the finding is still at its
   expected version, the evidence revision is unchanged, and no contradictory
   observation has been admitted after the intent's watermark.

C01's core sentence, and the reason ``finalize`` takes a ``LedgerView`` of
committed state rather than booleans: "Observation admission, evidence revision
and closure finalization must share the same serialization boundary; checking in
application memory before an unconditional write is insufficient."

This module models that boundary as an explicit compare-and-swap. The real
platform's transaction is what actually enforces it; what is testable here is
that every eligibility condition is re-checked *at* finalization and that a
stale decision cannot be applied.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime

from . import reasons as R
from ._canonical import digest, is_digest, require_aware
from .audit import AnchorReceipt, EventKind
from .coverage import CoverageStatus
from .decision import Decision, allow, deny, evaluate
from .lifecycle import Finding, State

#: Severity at or above which C01's anchor receipt is mandatory before Closed.
ANCHOR_REQUIRED_SEVERITY = 7.0


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of a scoped verification job, as the trusted core sees it.

    The boolean attestations (``authorized``, ``integrity_valid``) stand in for
    trusted-service answers. Spec Section 5 is clear that "supplied approval and
    proof booleans are test inputs, not trusted production evidence" -- the real
    platform derives each one from the service that owns it.
    """

    job_id: str
    organization: str
    target_id: str
    fingerprint: str
    rule: str
    profile_digest: str
    tested_revision: str
    started: datetime
    finished: datetime
    reviewer: str
    reviewer_decision_id: str
    evidence_set_revision: int
    evidence_digest: str
    coverage_status: CoverageStatus
    #: True when the weakness was still observed. A detection is a reopen
    #: signal, not an inconclusive result.
    detected: bool = False
    authorized: bool = True
    integrity_valid: bool = True
    #: Set when the verification ran under a different rule or profile version
    #: than the original observation. Spec Section 5 requires "an explicitly
    #: reviewed equivalence record rather than silent comparison".
    rule_changed: bool = False
    rule_equivalence_reviewed_by: str = ""


@dataclass(frozen=True)
class ClosureIntent:
    """C01's immutable-by-version record of a reviewed closure decision.

    Every field here exists so a receipt can be bound to *one exact decision*.
    C01: "A receipt must identify the exact intent and audit event; it cannot
    authorize a newer decision."
    """

    intent_id: str
    organization: str
    target_id: str
    control: str
    finding_id: str
    expected_finding_version: int
    evidence_set_revision: int
    evidence_digest: str
    repaired_artifact_revision: str
    observation_watermark: str
    verification_job_id: str
    coverage_status: CoverageStatus
    profile_digest: str
    rule_version: str
    reviewer_decision_id: str
    audit_sequence: int
    audit_head: str
    created_at: datetime
    #: Superseded intents are retained as history, flagged rather than deleted.
    superseded_at: datetime | None = None
    invalidated_reason: str = ""

    @property
    def active(self) -> bool:
        return self.superseded_at is None and not self.invalidated_reason

    @property
    def binding_digest(self) -> str:
        """What a receipt must match to be about this intent and nothing else."""
        return digest(
            {
                "intent_id": self.intent_id,
                "organization": self.organization,
                "finding_id": self.finding_id,
                "expected_finding_version": self.expected_finding_version,
                "evidence_set_revision": self.evidence_set_revision,
                "evidence_digest": self.evidence_digest,
                "repaired_artifact_revision": self.repaired_artifact_revision,
                "observation_watermark": self.observation_watermark,
                "reviewer_decision_id": self.reviewer_decision_id,
                "audit_sequence": self.audit_sequence,
                "audit_head": self.audit_head,
            }
        )


@dataclass(frozen=True)
class LedgerView:
    """Committed state as read inside the finalization transaction.

    Deliberately a snapshot type rather than loose arguments: C01 requires the
    eligibility conditions evaluated against committed state at finalization,
    and a named snapshot makes it obvious at the call site that these values
    came from inside the serialization boundary -- not from whatever the request
    handler happened to have in memory.
    """

    #: The intent the store currently regards as active for this finding.
    active_intent_id: str
    #: The finding's committed version, for compare-and-swap.
    finding_version: int
    #: The committed evidence-set revision and digest.
    evidence_set_revision: int
    evidence_digest: str
    #: Latest observation admitted against the finding.
    observation_watermark: str
    #: True when any observation admitted *after* the intent's watermark
    #: contradicts the fix or invalidates its proof.
    contradictory_observation_after_watermark: bool = False
    #: True when the reviewer's decision has since been withdrawn.
    reviewer_decision_withdrawn: bool = False
    #: Findings already finalized, so a duplicate receipt is a no-op.
    already_finalized_intent_ids: frozenset[str] = frozenset()
    #: Trusted state at finalization. A stop or integrity restriction still
    #: blocks finalization where the baseline requires it (C01).
    integrity_trusted: bool = True
    stop_active: bool = False


# ---------------------------------------------------------------------------
# Stage 1: proof review
# ---------------------------------------------------------------------------


def review_closure(finding: Finding, result: VerificationResult, *, now: datetime) -> Decision:
    """Decide whether the verification evidence proves the fix.

    Returns an allowed decision whose detail carries ``next_state``: ``Closed``
    for a low-severity finding, ``Closure awaiting anchor`` when C01's receipt
    is still required, and a reopen when the weakness persists.

    Every denial is an *inconclusive* outcome in the sense of spec Section 5 --
    the finding stays in Verification pending and the reasons say what evidence
    is missing. There is no branch here that closes a finding on an absent alert
    alone.
    """
    naive = require_aware(
        started=result.started, finished=result.finished, now=now
    ) or require_aware(fixed_at=finding.fixed_at or now)

    checks: list[tuple[bool, str]] = [
        (finding.state is State.VERIFICATION_PENDING, R.NOT_PENDING),
        (
            finding.organization == result.organization
            and finding.target_id == result.target_id
            and finding.fingerprint == result.fingerprint
            and finding.rule == result.rule
            and finding.profile_digest == result.profile_digest
            and all(
                bool(value)
                for value in (
                    result.organization,
                    result.target_id,
                    result.fingerprint,
                    result.rule,
                    result.profile_digest,
                )
            ),
            R.VERIFICATION_BOUNDARY_MISMATCH,
        ),
        (
            bool(finding.fixed_revision) and finding.fixed_revision == result.tested_revision,
            R.WRONG_BUILD,
        ),
        (
            bool(result.reviewer)
            and result.reviewer not in (finding.remediation_owner, finding.assessor),
            R.INDEPENDENT_REVIEW_REQUIRED,
        ),
        # Only Complete coverage proves the relevant check actually ran.
        (result.coverage_status.proves_coverage, R.INCOMPLETE_COVERAGE),
        (result.authorized, R.UNAUTHORIZED_RESCAN),
        (result.integrity_valid, R.INVALID_INTEGRITY),
        (is_digest(result.evidence_digest), R.EVIDENCE_REQUIRED),
        (
            not result.rule_changed or bool(result.rule_equivalence_reviewed_by),
            R.RULE_EQUIVALENCE_UNREVIEWED,
        ),
    ]

    if naive:
        checks.append((False, R.UTC_AWARE_TIME_REQUIRED))
    else:
        # The verification must have run after the recorded fix and not be
        # future-dated.
        fixed_at = finding.fixed_at
        ordered = fixed_at is not None and fixed_at <= result.started <= result.finished <= now
        checks.append((ordered, R.STALE_OR_FUTURE_VERIFICATION))

    decision = evaluate(
        checks,
        finding_id=finding.finding_id,
        verification_job_id=result.job_id,
        coverage_status=result.coverage_status.value,
    )
    if not decision.allowed:
        return decision

    if result.detected:
        return allow(R.FINDING_PERSISTS, next_state=State.REOPENED.value)

    needs_anchor = finding.severity_score >= ANCHOR_REQUIRED_SEVERITY
    next_state = State.CLOSURE_AWAITING_ANCHOR if needs_anchor else State.CLOSED
    return allow(
        R.VERIFIED_ABSENT,
        next_state=next_state.value,
        anchor_required=needs_anchor,
    )


def build_intent(
    finding: Finding,
    result: VerificationResult,
    *,
    intent_id: str,
    control: str,
    rule_version: str,
    audit_sequence: int,
    audit_head: str,
    created_at: datetime,
) -> ClosureIntent:
    """Record the reviewed decision as an intent, pinned to current versions.

    Called after ``review_closure`` allows. The expected finding version is read
    here and compared again at finalization -- that pairing is the
    compare-and-swap C01 requires.
    """
    return ClosureIntent(
        intent_id=intent_id,
        organization=finding.organization,
        target_id=finding.target_id,
        control=control,
        finding_id=finding.finding_id,
        expected_finding_version=finding.version,
        evidence_set_revision=result.evidence_set_revision,
        evidence_digest=result.evidence_digest,
        repaired_artifact_revision=finding.fixed_revision,
        observation_watermark=finding.observation_watermark,
        verification_job_id=result.job_id,
        coverage_status=result.coverage_status,
        profile_digest=finding.profile_digest,
        rule_version=rule_version,
        reviewer_decision_id=result.reviewer_decision_id,
        audit_sequence=audit_sequence,
        audit_head=audit_head,
        created_at=created_at,
    )


def invalidate(intent: ClosureIntent, reason: str, *, at: datetime) -> ClosureIntent:
    """Invalidate a pending intent, preserving it as history.

    C01: "Any new contradictory observation, replacement evidence, changed
    repaired revision, withdrawn reviewer decision or superseding intent
    invalidates the pending intent and increments the finding version."
    """
    if not reason:
        raise ValueError("an invalidation must record its reason")
    return replace(intent, invalidated_reason=reason, superseded_at=at)


def supersede(intent: ClosureIntent, *, at: datetime) -> ClosureIntent:
    """Mark an intent superseded by a newer one. Retained, never deleted."""
    return replace(intent, superseded_at=at)


# ---------------------------------------------------------------------------
# Stage 2: C01 finalization
# ---------------------------------------------------------------------------


@dataclass
class FinalizationResult:
    """What finalization produced: the finding, the decision, and the events.

    ``audit_events`` is returned rather than written anywhere, because C01
    requires the closed state and its audit/outbox event committed *together*.
    Handing them back as one result makes it the caller's single transaction,
    not two independent writes that could partially succeed.
    """

    finding: Finding
    decision: Decision
    audit_events: tuple[tuple[EventKind, dict[str, object]], ...] = ()
    #: A rejected receipt is preserved without closing the finding (C01).
    preserved_receipt: AnchorReceipt | None = None


def finalize(
    intent: ClosureIntent,
    finding: Finding,
    receipt: AnchorReceipt,
    ledger: LedgerView,
    *,
    now: datetime,
) -> FinalizationResult:
    """Apply C01's finalization check and commit, or reject and preserve.

    The order of checks is chosen so the most specific answer wins. A duplicate
    receipt for an already-finalized intent is an idempotent no-op *before*
    anything else is evaluated -- re-delivering a receipt must not produce a
    conflict error for work that already succeeded.
    """
    if require_aware(now=now, received_at=receipt.received_at):
        return FinalizationResult(finding, deny(R.UTC_AWARE_TIME_REQUIRED))

    # Idempotency first: C01, "Duplicate receipts for the same already-finalized
    # intent are idempotent no-ops."
    if intent.intent_id in ledger.already_finalized_intent_ids:
        return FinalizationResult(finding, allow(R.ALREADY_FINALIZED, intent_id=intent.intent_id))

    checks: list[tuple[bool, str]] = [
        (receipt.verified, R.RECEIPT_UNVERIFIED),
        # The receipt must name this exact intent's audit event.
        (
            receipt.organization == intent.organization
            and receipt.sequence == intent.audit_sequence
            and receipt.head == intent.audit_head,
            R.RECEIPT_AUDIT_MISMATCH,
        ),
        (intent.organization == finding.organization, R.RECEIPT_INTENT_MISMATCH),
        (intent.finding_id == finding.finding_id, R.RECEIPT_INTENT_MISMATCH),
        # Still the current active intent.
        (intent.active, R.INTENT_INVALIDATED),
        (ledger.active_intent_id == intent.intent_id, R.INTENT_SUPERSEDED),
        # Compare-and-swap against the committed finding version.
        (
            ledger.finding_version == intent.expected_finding_version == finding.version,
            R.FINDING_VERSION_CONFLICT,
        ),
        # Unchanged evidence revision and digest.
        (
            ledger.evidence_set_revision == intent.evidence_set_revision
            and ledger.evidence_digest == intent.evidence_digest,
            R.EVIDENCE_REVISION_CHANGED,
        ),
        # Unchanged proof bindings.
        (
            finding.fixed_revision == intent.repaired_artifact_revision,
            R.WRONG_BUILD,
        ),
        (not ledger.reviewer_decision_withdrawn, R.REVIEWER_DECISION_WITHDRAWN),
        # No contradictory observation admitted after the watermark.
        (
            not ledger.contradictory_observation_after_watermark,
            R.CONTRADICTORY_OBSERVATION_ADMITTED,
        ),
        (
            ledger.observation_watermark == intent.observation_watermark,
            R.CONTRADICTORY_OBSERVATION_ADMITTED,
        ),
        # Eligible verification state.
        (
            finding.state in (State.CLOSURE_AWAITING_ANCHOR, State.VERIFICATION_PENDING),
            R.NOT_PENDING,
        ),
        (intent.coverage_status.proves_coverage, R.INCOMPLETE_COVERAGE),
        # Stop and integrity restrictions still block finalization.
        (ledger.integrity_trusted, R.INTEGRITY_UNTRUSTED),
        (not ledger.stop_active, R.STOP_ACTIVE),
    ]

    decision = evaluate(
        checks,
        intent_id=intent.intent_id,
        finding_id=finding.finding_id,
        receipt_sequence=receipt.sequence,
    )

    if not decision.allowed:
        # Reject a late receipt as stale; preserve it without closing the
        # finding. Unresolved work stays visible.
        return FinalizationResult(finding, decision, preserved_receipt=receipt)

    closed = replace(finding, state=State.CLOSED, version=finding.version + 1)
    events = (
        (
            EventKind.CLOSURE_FINALIZED,
            {
                "intent_id": intent.intent_id,
                "finding_id": finding.finding_id,
                "organization": finding.organization,
                "receipt_sequence": receipt.sequence,
                "receipt_head": receipt.head,
                "sink_id": receipt.sink_id,
                "intent_binding": intent.binding_digest,
                "finalized_at": now.isoformat(),
                "finding_version": closed.version,
            },
        ),
    )
    return FinalizationResult(closed, decision, audit_events=events)


def reopen_after_closure(
    finding: Finding, observation_id: str, *, reason: str
) -> tuple[Finding, tuple[tuple[EventKind, dict[str, object]], ...]]:
    """Reopen a closed finding in a subsequent audited transaction.

    C01: "If contradiction is admitted after closure commits, reopen in a
    subsequent audited transaction." Separate from ``finalize`` on purpose --
    this is a second transaction, not a rollback of the first, so the closure
    and its reversal both remain in the record.
    """
    if finding.state is not State.CLOSED:
        raise ValueError("only a closed finding is reopened by this path")
    reopened = replace(
        finding,
        state=State.REOPENED,
        version=finding.version + 1,
        observation_watermark=observation_id,
        reopened_count=finding.reopened_count + 1,
        remediation_owner="",
        fixed_revision="",
        fixed_at=None,
    )
    events = (
        (
            EventKind.CLOSURE_FINALIZED,
            {
                "finding_id": finding.finding_id,
                "organization": finding.organization,
                "action": "reopened_after_closure",
                "observation_id": observation_id,
                "reason": reason,
                "finding_version": reopened.version,
            },
        ),
    )
    return reopened, events


@dataclass
class IntentStore:
    """Tracks intents per finding so only one is ever active.

    Recording a new intent supersedes the previous one rather than replacing it,
    which is what makes C01-B testable: two racing intents produce one active
    intent and one retained superseded intent, and only the active one can
    finalize.
    """

    intents: dict[str, list[ClosureIntent]] = field(default_factory=dict)

    def record(self, intent: ClosureIntent, *, at: datetime) -> ClosureIntent:
        history = self.intents.setdefault(intent.finding_id, [])
        for index, existing in enumerate(history):
            if existing.active:
                history[index] = supersede(existing, at=at)
        history.append(intent)
        return intent

    def active(self, finding_id: str) -> ClosureIntent | None:
        for intent in reversed(self.intents.get(finding_id, [])):
            if intent.active:
                return intent
        return None

    def history(self, finding_id: str) -> tuple[ClosureIntent, ...]:
        return tuple(self.intents.get(finding_id, []))
