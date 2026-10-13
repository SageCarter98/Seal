"""U07 -- the audit hash chain and the transactional anchor outbox.

Spec Section 7 requires the chain anchored to a separately controlled signed
sink at least every fifteen minutes, at scan completion, and immediately for
authorization, override, High/Critical closure, incident and audit-control
events.

Two honesty notes carried from the v0.1.0 package, which still apply:

* The chain here validates against a checkpoint held *outside* the event list.
  It does not authenticate that checkpoint and does not implement external
  anchoring -- an unauthenticated head taken from the same list it is checking
  would prove nothing.
* ``AnchorReceipt.verified`` is an input. The real platform verifies a signature
  from the assurance domain; this module models what a verified receipt permits,
  not how to verify one.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import Enum

from . import reasons as R
from ._canonical import digest, is_digest, require_aware
from .decision import Decision, allow, deny, evaluate

#: Spec Section 7's anchor interval. Exceeding it makes integrity Untrusted
#: under C02.
ANCHOR_INTERVAL = timedelta(minutes=15)

#: The NOLOGIN role that owns the audit tables. Spec Section 7 requires it
#: retained "with no issued credentials, no routine assumption and two-person
#: break-glass control". Named here so F07's test can assert no runtime role
#: equals it.
AUDIT_OWNER_ROLE = "seal_audit_owner"

GENESIS_HASH = "0" * 64


class EventKind(str, Enum):
    """Event kinds that matter to the anchor policy.

    The ``requires_immediate_anchor`` set below is the list spec Section 7
    names; separating the enum from that set keeps the policy readable and
    reviewable rather than scattered through call sites.
    """

    AUTHORIZATION = "authorization"
    SCOPE_DENIAL = "scope_denial"
    SCAN_COMPLETE = "scan_complete"
    COVERAGE_MANIFEST = "coverage_manifest"
    PRIORITY_OVERRIDE = "priority_override"
    DISPOSITION = "disposition"
    CLOSURE_INTENT = "closure_intent"
    CLOSURE_FINALIZED = "closure_finalized"
    INCIDENT = "incident"
    AUDIT_CONTROL = "audit_control"
    INTEGRITY_STATE = "integrity_state"
    EVIDENCE_DISPOSAL = "evidence_disposal"


IMMEDIATE_ANCHOR_KINDS = frozenset(
    {
        EventKind.AUTHORIZATION,
        EventKind.PRIORITY_OVERRIDE,
        EventKind.CLOSURE_INTENT,
        EventKind.CLOSURE_FINALIZED,
        EventKind.INCIDENT,
        EventKind.AUDIT_CONTROL,
        EventKind.INTEGRITY_STATE,
    }
)


@dataclass(frozen=True)
class AuditEvent:
    """One link in the chain. Frozen: an amended event is a new event."""

    organization: str
    sequence: int
    previous: str
    kind: EventKind
    recorded_at: datetime
    payload: dict[str, object]
    hash: str = ""

    def computed_hash(self) -> str:
        return digest(
            {
                "organization": self.organization,
                "sequence": self.sequence,
                "previous": self.previous,
                "kind": self.kind.value,
                "recorded_at": self.recorded_at.isoformat(),
                "payload": self.payload,
            }
        )


@dataclass(frozen=True)
class Checkpoint:
    """An expected (count, head) pair, held outside the event list it checks."""

    count: int
    head: str


@dataclass(frozen=True)
class OutboxItem:
    """A pending anchor submission, committed in the same transaction as its event.

    Spec Section 7: "Commit accepted audit events durably before acknowledgement
    and record a transactional anchor-outbox item. Retries use sequence/head
    idempotency." The sequence and head here are that idempotency key -- a
    retried submission for the same pair is the same item, not a second anchor.
    """

    organization: str
    sequence: int
    head: str
    created_at: datetime
    attempts: int = 0
    submitted_at: datetime | None = None

    @property
    def idempotency_key(self) -> str:
        return digest(
            {"organization": self.organization, "sequence": self.sequence, "head": self.head}
        )


@dataclass(frozen=True)
class AnchorReceipt:
    """A sink's acknowledgement that it holds a given chain head.

    ``verified`` is a trusted-service input, not something this module
    establishes. Spec Section 5 is explicit that a receipt must be
    independently verified before finalization and that Seal must "never
    fabricate a receipt".
    """

    organization: str
    sequence: int
    head: str
    sink_id: str
    received_at: datetime
    verified: bool = False


class AuditLedger:
    """An append-only chain with its outbox. In-memory; no persistence here.

    The ledger returns an ``OutboxItem`` from ``append`` rather than queueing one
    internally, so a caller cannot acknowledge an event without also having
    taken the outbox item -- modelling the "commit both together" requirement
    structurally instead of by comment.
    """

    def __init__(self, organization: str) -> None:
        if not organization:
            raise ValueError("an audit chain belongs to exactly one organization")
        self.organization = organization
        self._events: list[AuditEvent] = []
        self._outbox: list[OutboxItem] = []
        self._last_anchor_at: datetime | None = None

    # -- reading ------------------------------------------------------------
    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @property
    def head(self) -> str:
        return self._events[-1].hash if self._events else GENESIS_HASH

    @property
    def checkpoint(self) -> Checkpoint:
        return Checkpoint(len(self._events), self.head)

    @property
    def pending_outbox(self) -> tuple[OutboxItem, ...]:
        return tuple(item for item in self._outbox if item.submitted_at is None)

    # -- writing ------------------------------------------------------------
    def append(
        self,
        kind: EventKind,
        payload: dict[str, object],
        *,
        organization: str,
        recorded_at: datetime,
        durable: bool = True,
    ) -> tuple[AuditEvent, OutboxItem]:
        """Append one event and return it with its outbox item.

        ``durable=False`` models a storage layer that did not commit. Spec
        Section 7 requires that "a successful API acknowledgment must mean the
        audit event is durably committed", so this raises rather than returning
        a half-written event -- there is no partial success to hand back.
        """
        if organization != self.organization:
            raise ValueError(R.CHAIN_TENANT_MISMATCH)
        if require_aware(recorded_at=recorded_at):
            raise ValueError(R.UTC_AWARE_TIME_REQUIRED)
        if not durable:
            raise RuntimeError(R.AUDIT_APPEND_NOT_DURABLE)

        event = AuditEvent(
            organization=organization,
            sequence=len(self._events) + 1,
            previous=self.head,
            kind=kind,
            recorded_at=recorded_at,
            payload=payload,
        )
        event = replace(event, hash=event.computed_hash())
        self._events.append(event)

        item = OutboxItem(
            organization=organization,
            sequence=event.sequence,
            head=event.hash,
            created_at=recorded_at,
        )
        self._outbox.append(item)
        return event, item

    def record_receipt(self, receipt: AnchorReceipt) -> Decision:
        """Reconcile a verified receipt against the outbox.

        An unverified receipt is refused outright. A receipt for a head the
        ledger never produced is refused too -- that is the tamper and replay
        case spec Section 7 requires testing.
        """
        if receipt.organization != self.organization:
            return deny(R.CHAIN_TENANT_MISMATCH)
        if not receipt.verified:
            return deny(R.RECEIPT_UNVERIFIED)

        for index, item in enumerate(self._outbox):
            if item.sequence == receipt.sequence and item.head == receipt.head:
                if item.submitted_at is not None:
                    # Duplicate receipts for an already-anchored head are
                    # idempotent no-ops (C01).
                    return allow(R.ALREADY_FINALIZED, sequence=item.sequence)
                self._outbox[index] = replace(item, submitted_at=receipt.received_at)
                self._last_anchor_at = receipt.received_at
                return allow(sequence=item.sequence, head=item.head)

        return deny(R.RECEIPT_AUDIT_MISMATCH, sequence=receipt.sequence, head=receipt.head)

    # -- verification -------------------------------------------------------
    def verify(self, checkpoint: Checkpoint) -> Decision:
        """Walk the chain and compare it against an externally held checkpoint."""
        previous = GENESIS_HASH
        for index, event in enumerate(self._events, start=1):
            if event.organization != self.organization:
                return deny(R.CHAIN_TENANT_MISMATCH, sequence=index)
            if event.sequence != index:
                return deny(R.CHAIN_SEQUENCE_MISMATCH, sequence=index)
            if event.previous != previous:
                return deny(R.CHAIN_LINK_MISMATCH, sequence=index)
            if event.computed_hash() != event.hash:
                return deny(R.CHAIN_EVENT_TAMPERED, sequence=index)
            previous = event.hash

        if checkpoint != Checkpoint(len(self._events), previous):
            return deny(
                R.CHECKPOINT_MISMATCH,
                expected=(checkpoint.count, checkpoint.head),
                actual=(len(self._events), previous),
            )
        return allow(count=len(self._events), head=previous)

    def anchor_status(self, now: datetime, interval: timedelta = ANCHOR_INTERVAL) -> Decision:
        """Whether anchoring is current enough for integrity to stay Trusted.

        With nothing yet anchored, the clock runs from the first event rather
        than from nothing -- a ledger that has never anchored but has events is
        overdue once the interval passes, which is the "sink outage" case.
        """
        if require_aware(now=now):
            return deny(R.UTC_AWARE_TIME_REQUIRED)
        if not self._events:
            return allow(anchored=True, note="no events to anchor")

        reference = self._last_anchor_at or self._events[0].recorded_at
        overdue = now - reference > interval
        pending = self.pending_outbox

        checks = [
            (not overdue, R.ANCHOR_OVERDUE),
        ]
        return evaluate(
            checks,
            last_anchor_at=self._last_anchor_at.isoformat() if self._last_anchor_at else None,
            pending_count=len(pending),
            age_seconds=(now - reference).total_seconds(),
        )


def requires_immediate_anchor(kind: EventKind) -> bool:
    """Whether this event kind must be anchored immediately, not on the interval."""
    return kind in IMMEDIATE_ANCHOR_KINDS


@dataclass
class EvidenceRecord:
    """U08 -- sanitized evidence with its holds and disposal state.

    ``sanitized`` and ``secret_quarantined`` are recorded rather than inferred:
    spec Section 7 requires minimization at collection and sanitization before
    ordinary retention, and a disposal that cannot state whether the content was
    sanitized is not auditable.
    """

    evidence_id: str
    organization: str
    revision: int
    content_digest: str
    collected_at: datetime
    sanitized: bool = False
    secret_quarantined: bool = False
    legal_hold: bool = False
    incident_hold: bool = False
    disposed_at: datetime | None = None
    access_log: list[tuple[str, datetime]] = field(default_factory=list)

    @property
    def held(self) -> bool:
        return self.legal_hold or self.incident_hold

    def may_dispose(self, *, now: datetime) -> Decision:
        """Spec Section 7: honor incident/legal holds before deletion."""
        checks = [
            (not self.held, R.HOLD_PREVENTS_DISPOSAL),
            (self.sanitized, R.EVIDENCE_NOT_SANITIZED),
            (self.disposed_at is None, R.ALREADY_FINALIZED),
            (is_digest(self.content_digest), R.EVIDENCE_REQUIRED),
            (not require_aware(now=now), R.UTC_AWARE_TIME_REQUIRED),
        ]
        return evaluate(checks, evidence_id=self.evidence_id)
