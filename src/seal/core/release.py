"""U14 -- binding a release claim to its evidence and authority.

Spec Section 10 gives U14 two obligations. The first is a separation, stated as
a heading: "Keep model checks and release tests separate". The reason follows
immediately -- this package's own tests "exercise pure decisions using synthetic
identities and attestations... They do not test real scanning, real MFA,
database permissions, container isolation, encrypted evidence or an external
signed sink." So a passing model check is evidence about the model, and that is
all it can ever be. The second obligation is the binding itself: a claim
travels with the evidence that supports it and the authority competent to
accept it, and a claim with nothing behind it is refused rather than deferred.

**This module cannot record an acceptance, and that is deliberate.** PM
Framework Section 3.3 gives each gate one accountable person and bans
self-approval; a gate decision is therefore a named human authority's action,
not a function call. ``acceptance_is_permitted`` answers whether an authority
*may* accept a claim -- never that anyone did. There is no ``approve``, no
``sign_off``, and no module-level structure a decision could be written into,
which ``tests/test_release.py::TestPermissionIsNotAcceptance`` checks at the
source level rather than trusting this paragraph.

Everything here is a decision about *evidence sufficiency*. ``verified`` on a
reference is an input, exactly like ``phase0_approved`` elsewhere in the core:
the real platform derives it from whoever did the checking. Setting it True in
a fixture grants nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from . import reasons as R
from ._canonical import is_digest, require_aware
from .decision import Decision, evaluate


class EvidenceKind(str, Enum):
    """Where a piece of evidence came from.

    The kind is what makes U14's separation enforceable: without it, a claim
    about a production control and a claim about a modelled decision would cite
    indistinguishable artifacts.
    """

    #: A test in this package. Exercises a pure decision over synthetic inputs.
    MODEL_CHECK = "model check"
    #: A test against the running platform -- integration, contract, isolation.
    RELEASE_TEST = "release test"
    #: An assessment by someone outside the delivery team (spec H01).
    INDEPENDENT_REVIEW = "independent review"
    #: An operational record: a deployment log, a measured run, an audit export.
    OPERATIONAL_RECORD = "operational record"


class ClaimClass(str, Enum):
    """What kind of thing is being claimed.

    The classes are separate because the evidence that can support them is
    separate. Collapsing them is precisely the error U14 exists to prevent: a
    green model suite reported as a working control.
    """

    #: "The modelled decision behaves as the specification describes."
    MODEL_BEHAVIOUR = "model behaviour"
    #: "The production control exists and works."
    PRODUCTION_CONTROL = "production control"
    #: "The evidence pack for this gate is complete."
    GATE_READINESS = "gate readiness"


#: Evidence kinds that can support a claim about something real. The model's own
#: checks are absent by construction, not by omission.
RELEASE_EVIDENCE_KINDS = frozenset(
    {
        EvidenceKind.RELEASE_TEST,
        EvidenceKind.INDEPENDENT_REVIEW,
        EvidenceKind.OPERATIONAL_RECORD,
    }
)

#: Claim classes that require evidence of the real system.
REAL_SYSTEM_CLAIMS = frozenset({ClaimClass.PRODUCTION_CONTROL, ClaimClass.GATE_READINESS})

_PERMITTED_NOTE = (
    "acceptance is permitted, not recorded: a gate decision is a named human "
    "authority's action (PM Framework 3.3)"
)


@dataclass(frozen=True)
class EvidenceReference:
    """A locatable, digest-bound pointer to one artifact.

    ``reference`` is how a reviewer finds it again -- a test node id, a CI run,
    a pull request, a document section. ``digest`` binds the claim to the
    artifact's content, so an artifact edited afterwards no longer supports the
    claim that cited it.
    """

    reference: str
    kind: EvidenceKind
    digest: str
    recorded_at: datetime
    revision: str
    produced_by: str
    #: Whether someone competent checked this artifact says what the claim says
    #: it says. An input, like every attestation in this package.
    verified: bool = False


@dataclass(frozen=True)
class ReleaseClaim:
    """One statement about this build, with the evidence offered for it."""

    claim_id: str
    organization: str
    statement: str
    claim_class: ClaimClass
    revision: str
    claimed_by: str
    claimed_at: datetime
    evidence: tuple[EvidenceReference, ...] = ()


@dataclass(frozen=True)
class Authority:
    """A recorded acceptance authority.

    ``may_accept`` is recorded rather than inferred from ``role``: the framework
    names one accountable person per gate, and which classes that person may
    accept is part of the record. Guessing it from a job title is how a
    separation of duties quietly stops existing.
    """

    name: str
    role: str
    may_accept: frozenset[ClaimClass]
    recorded_at: datetime


@dataclass(frozen=True)
class ReleasePack:
    """The statements a gate requires, and the claims offered against them."""

    gate: str
    organization: str
    revision: str
    required_statements: tuple[str, ...] = ()
    claims: tuple[ReleaseClaim, ...] = ()


@dataclass(frozen=True)
class PackStatus:
    """What the pack actually covers, with the gaps named.

    Three separate tuples rather than a percentage. A required statement with no
    claim at all and one whose claim is unsupported are different problems, and
    rounding either into a completion figure is the falsified-evidence failure
    the frameworks have zero tolerance for.
    """

    decision: Decision
    supported: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    detail: dict[str, object] = field(default_factory=dict)


def reference_is_locatable(reference: str) -> bool:
    """Whether a reviewer could use this string to find the artifact again.

    Blank, whitespace-only and control-character-bearing references are refused.
    This module cannot check that the target exists -- it has no I/O -- so it
    checks the one property it can: that the reference is a usable locator
    rather than a gesture at one.
    """
    if not isinstance(reference, str) or not reference.strip():
        return False
    return all(ord(character) >= 0x20 and ord(character) != 0x7F for character in reference)


def claim_is_supported(claim: ReleaseClaim, *, now: datetime) -> Decision:
    """Whether the evidence offered actually supports the claim made.

    Collects every failure rather than stopping at the first, so a claimant
    sees the whole gap in one pass.
    """
    times_comparable = not require_aware(claimed_at=claim.claimed_at, now=now)

    checks: list[tuple[bool, str]] = [
        (bool(claim.statement.strip()), R.CLAIM_STATEMENT_MISSING),
        (bool(claim.evidence), R.EVIDENCE_REQUIRED),
        (times_comparable, R.UTC_AWARE_TIME_REQUIRED),
    ]

    for reference in claim.evidence:
        reference_time_ok = not require_aware(recorded_at=reference.recorded_at)
        checks.extend(
            [
                (reference_is_locatable(reference.reference), R.EVIDENCE_REQUIRED),
                (is_digest(reference.digest), R.EVIDENCE_DIGEST_INVALID),
                (reference.revision == claim.revision, R.WRONG_BUILD),
                (bool(reference.produced_by), R.EVIDENCE_REQUIRED),
                (reference.verified, R.EVIDENCE_UNVERIFIED),
                (reference_time_ok, R.UTC_AWARE_TIME_REQUIRED),
                (
                    not (times_comparable and reference_time_ok)
                    or reference.recorded_at <= claim.claimed_at,
                    R.EVIDENCE_POSTDATES_CLAIM,
                ),
            ]
        )

    # Applied only when there is evidence to classify: an empty claim is already
    # refused above, and naming the separation as well would suggest the fix is
    # a different *kind* of evidence rather than any.
    if claim.evidence and claim.claim_class in REAL_SYSTEM_CLAIMS:
        checks.append(
            (
                any(reference.kind in RELEASE_EVIDENCE_KINDS for reference in claim.evidence),
                R.MODEL_CHECK_NOT_RELEASE_EVIDENCE,
            )
        )

    return evaluate(
        checks,
        claim_id=claim.claim_id,
        claim_class=claim.claim_class.value,
        evidence_count=len(claim.evidence),
    )


def acceptance_is_permitted(
    claim: ReleaseClaim,
    authority: Authority,
    *,
    now: datetime,
    organization: str | None = None,
) -> Decision:
    """Whether this authority may accept this claim.

    An allowed decision means the claim is supported and this person is
    competent and independent enough to accept it. It does not mean they have,
    and nothing here can say they have -- ``acceptance_recorded`` is False on
    every decision this function returns, allowed or not.
    """
    support = claim_is_supported(claim, now=now)
    checks: list[tuple[bool, str]] = [(False, reason) for reason in support.reasons]

    authority_time_ok = not require_aware(recorded_at=authority.recorded_at)
    claim_time_ok = not require_aware(claimed_at=claim.claimed_at)

    producers = frozenset(reference.produced_by for reference in claim.evidence)

    checks.extend(
        [
            (bool(authority.name.strip()), R.AUTHORITY_NOT_RECORDED),
            (authority_time_ok, R.AUTHORITY_NOT_RECORDED),
            (
                not (authority_time_ok and claim_time_ok)
                or authority.recorded_at <= claim.claimed_at,
                R.AUTHORITY_NOT_RECORDED,
            ),
            (claim.claim_class in authority.may_accept, R.ROLE_NOT_PERMITTED),
            (
                authority.name != claim.claimed_by and authority.name not in producers,
                R.INDEPENDENT_APPROVER_REQUIRED,
            ),
            (organization is None or claim.organization == organization, R.TENANT_MISMATCH),
        ]
    )

    return evaluate(
        checks,
        claim_id=claim.claim_id,
        authority=authority.name,
        acceptance_recorded=False,
        note=_PERMITTED_NOTE,
    )


def pack_status(pack: ReleasePack, *, now: datetime) -> PackStatus:
    """Which of a gate's required statements this pack actually supports.

    A claim counts only for its own tenant, its own revision and its own exact
    statement, and only when ``claim_is_supported`` allows it. Everything else
    is reported as a gap by name.

    The returned decision is about pack completeness. It is not the gate
    decision, which stays with the gate's accountable person --
    ``gate_decision_recorded`` is False on every decision returned here.
    """
    checks: list[tuple[bool, str]] = [(bool(pack.required_statements), R.CLAIM_STATEMENT_MISSING)]

    for claim in pack.claims:
        checks.append((claim.organization == pack.organization, R.TENANT_MISMATCH))
        checks.append((claim.revision == pack.revision, R.WRONG_BUILD))

    supported: list[str] = []
    unsupported: list[str] = []
    missing: list[str] = []
    claim_reasons: list[str] = []

    for statement in pack.required_statements:
        offered = tuple(
            claim
            for claim in pack.claims
            if claim.statement == statement
            and claim.organization == pack.organization
            and claim.revision == pack.revision
        )
        if not offered:
            missing.append(statement)
            continue

        decisions = tuple(claim_is_supported(claim, now=now) for claim in offered)
        if any(decision.allowed for decision in decisions):
            supported.append(statement)
        else:
            unsupported.append(statement)
            for decision in decisions:
                claim_reasons.extend(decision.reasons)

    checks.append((not missing, R.EVIDENCE_REQUIRED))
    checks.append((not unsupported, R.EVIDENCE_REQUIRED))

    decision = evaluate(
        checks,
        gate=pack.gate,
        revision=pack.revision,
        supported=len(supported),
        required=len(pack.required_statements),
        claim_reasons=tuple(sorted(set(claim_reasons))),
        gate_decision_recorded=False,
    )

    return PackStatus(
        decision,
        supported=tuple(supported),
        unsupported=tuple(unsupported),
        missing=tuple(missing),
    )
