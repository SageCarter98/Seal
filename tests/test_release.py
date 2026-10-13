"""U14 -- binding a release claim to its evidence and authority.

Spec Section 10 states U14 as two obligations. The first is a separation:
"Keep model checks and release tests separate", immediately followed by the
reason -- the offline model's tests "exercise pure decisions using synthetic
identities and attestations... They do not test real scanning, real MFA,
database permissions, container isolation, encrypted evidence or an external
signed sink." The second is the binding itself: a claim travels with the
evidence that supports it and the authority competent to accept it.

What this module deliberately cannot do is record the acceptance. PM Framework
Section 3.3 gives each gate one accountable person and bans self-approval, so
a gate decision is a named human authority's action. ``TestPermissionIsNotAcceptance``
asserts that absence at the source level: there is no ``approve``, no
``sign_off``, and no module-level place to put a decision even if someone wrote
one.
"""

from __future__ import annotations

import ast
import pathlib
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from conftest import ORG, OTHER_ORG

from seal.core import reasons as R
from seal.core._canonical import digest
from seal.core.release import (
    RELEASE_EVIDENCE_KINDS,
    Authority,
    ClaimClass,
    EvidenceKind,
    EvidenceReference,
    ReleaseClaim,
    ReleasePack,
    acceptance_is_permitted,
    claim_is_supported,
    pack_status,
)

RELEASE_SOURCE = (
    pathlib.Path(__file__).resolve().parents[1] / "src" / "seal" / "core" / "release.py"
).read_text(encoding="utf-8")

REVISION = "rev-release-candidate-3"


@pytest.fixture
def model_evidence(now) -> EvidenceReference:
    """A passing model test. Real evidence -- of a modelled decision only."""
    return EvidenceReference(
        reference="tests/test_export.py::TestCsvFormulaGuard",
        kind=EvidenceKind.MODEL_CHECK,
        digest=digest({"artifact": "pytest-report-668"}),
        recorded_at=now - timedelta(hours=2),
        revision=REVISION,
        produced_by="engineer.kwesi",
        verified=True,
    )


@pytest.fixture
def release_evidence(now) -> EvidenceReference:
    """An integration test against the running platform."""
    return EvidenceReference(
        reference="ci/run/4412#tenant-isolation",
        kind=EvidenceKind.RELEASE_TEST,
        digest=digest({"artifact": "integration-run-4412"}),
        recorded_at=now - timedelta(hours=1),
        revision=REVISION,
        produced_by="engineer.kwesi",
        verified=True,
    )


@pytest.fixture
def model_claim(now, model_evidence) -> ReleaseClaim:
    return ReleaseClaim(
        claim_id="CLAIM-1",
        organization=ORG,
        statement="the export decision refuses a cross-tenant row",
        claim_class=ClaimClass.MODEL_BEHAVIOUR,
        revision=REVISION,
        claimed_by="engineer.kwesi",
        claimed_at=now,
        evidence=(model_evidence,),
    )


@pytest.fixture
def control_claim(now, release_evidence) -> ReleaseClaim:
    return ReleaseClaim(
        claim_id="CLAIM-2",
        organization=ORG,
        statement="tenant isolation is enforced on every export path",
        claim_class=ClaimClass.PRODUCTION_CONTROL,
        revision=REVISION,
        claimed_by="engineer.kwesi",
        claimed_at=now,
        evidence=(release_evidence,),
    )


@pytest.fixture
def authority(now) -> Authority:
    """A recorded acceptance authority, competent for both claim classes.

    ``may_accept`` is recorded rather than inferred from the role string: the
    framework names one accountable person per gate, and which classes a person
    may accept is part of that record, not something code should guess.
    """
    return Authority(
        name="security.lead.kofi",
        role="security_lead",
        may_accept=frozenset({ClaimClass.MODEL_BEHAVIOUR, ClaimClass.PRODUCTION_CONTROL}),
        recorded_at=now - timedelta(days=7),
    )


class TestClaimNeedsEvidence:
    """ "Deny missing evidence" -- a claim with nothing behind it is refused."""

    def test_a_supported_claim_is_allowed(self, model_claim, now):
        assert claim_is_supported(model_claim, now=now)

    def test_a_claim_with_no_evidence_at_all_is_refused(self, model_claim, now):
        decision = claim_is_supported(replace(model_claim, evidence=()), now=now)
        assert not decision
        assert decision.reason == R.EVIDENCE_REQUIRED

    def test_an_unlocatable_reference_is_not_evidence(self, model_claim, now):
        vague = replace(model_claim.evidence[0], reference="   ")
        decision = claim_is_supported(replace(model_claim, evidence=(vague,)), now=now)
        assert not decision
        assert R.EVIDENCE_REQUIRED in decision.reasons

    def test_a_reference_that_is_not_digest_bound_is_refused(self, model_claim, now):
        undigested = replace(model_claim.evidence[0], digest="sha256-ish")
        decision = claim_is_supported(replace(model_claim, evidence=(undigested,)), now=now)
        assert not decision
        assert R.EVIDENCE_DIGEST_INVALID in decision.reasons

    def test_evidence_nobody_has_checked_does_not_support_a_claim(self, model_claim, now):
        # ``verified`` is an input, like every attestation in this package. The
        # point is that an unchecked artifact cannot be counted, not that this
        # module can do the checking.
        unchecked = replace(model_claim.evidence[0], verified=False)
        decision = claim_is_supported(replace(model_claim, evidence=(unchecked,)), now=now)
        assert not decision
        assert R.EVIDENCE_UNVERIFIED in decision.reasons

    def test_evidence_from_another_revision_does_not_support_this_one(self, model_claim, now):
        other_build = replace(model_claim.evidence[0], revision="rev-older-1")
        decision = claim_is_supported(replace(model_claim, evidence=(other_build,)), now=now)
        assert not decision
        assert R.WRONG_BUILD in decision.reasons

    def test_evidence_recorded_after_the_claim_cannot_have_supported_it(self, model_claim, now):
        later = replace(model_claim.evidence[0], recorded_at=now + timedelta(minutes=5))
        decision = claim_is_supported(replace(model_claim, evidence=(later,)), now=now)
        assert not decision
        assert R.EVIDENCE_POSTDATES_CLAIM in decision.reasons

    def test_one_bad_reference_among_good_ones_still_refuses_the_claim(
        self, model_claim, release_evidence, now
    ):
        bad = replace(release_evidence, verified=False)
        decision = claim_is_supported(
            replace(model_claim, evidence=(model_claim.evidence[0], bad)), now=now
        )
        assert not decision
        assert R.EVIDENCE_UNVERIFIED in decision.reasons

    def test_a_naive_timestamp_is_refused(self, model_claim, now):
        decision = claim_is_supported(
            replace(model_claim, claimed_at=datetime(2026, 10, 13, 12)), now=now
        )
        assert not decision
        assert R.UTC_AWARE_TIME_REQUIRED in decision.reasons

    def test_an_empty_statement_is_not_a_claim(self, model_claim, now):
        decision = claim_is_supported(replace(model_claim, statement="  "), now=now)
        assert not decision
        assert R.CLAIM_STATEMENT_MISSING in decision.reasons


class TestModelChecksAreNotReleaseEvidence:
    """U14's separation, enforced rather than noted.

    Spec Section 10 is explicit that the model's own tests "do not test real
    scanning, real MFA, database permissions, container isolation, encrypted
    evidence or an external signed sink". So a passing model check can support
    a claim *about the model* and nothing more.
    """

    def test_a_model_check_supports_a_claim_about_modelled_behaviour(self, model_claim, now):
        assert claim_is_supported(model_claim, now=now)

    def test_a_model_check_alone_cannot_support_a_production_control_claim(self, model_claim, now):
        promoted = replace(model_claim, claim_class=ClaimClass.PRODUCTION_CONTROL)
        decision = claim_is_supported(promoted, now=now)
        assert not decision
        assert R.MODEL_CHECK_NOT_RELEASE_EVIDENCE in decision.reasons

    def test_a_release_test_supports_a_production_control_claim(self, control_claim, now):
        assert claim_is_supported(control_claim, now=now)

    def test_a_production_claim_may_cite_model_checks_beside_a_release_test(
        self, control_claim, model_evidence, now
    ):
        both = replace(control_claim, evidence=(model_evidence, *control_claim.evidence))
        assert claim_is_supported(both, now=now)

    def test_the_kinds_that_count_as_release_evidence_exclude_the_model(self):
        assert EvidenceKind.MODEL_CHECK not in RELEASE_EVIDENCE_KINDS
        assert EvidenceKind.RELEASE_TEST in RELEASE_EVIDENCE_KINDS

    def test_every_release_evidence_kind_is_a_real_evidence_kind(self):
        """Guards the guard: a typo in the set would silently widen it."""
        assert RELEASE_EVIDENCE_KINDS <= frozenset(EvidenceKind)


class TestAuthorityIsNamedAndIndependent:
    """PM Framework Section 3.3: one accountable person, and never self-approval."""

    def test_a_recorded_independent_authority_may_accept(self, control_claim, authority, now):
        assert acceptance_is_permitted(control_claim, authority, now=now)

    def test_the_claimant_may_not_accept_their_own_claim(self, control_claim, now):
        claimant = Authority(
            name=control_claim.claimed_by,
            role="security_lead",
            may_accept=frozenset({ClaimClass.PRODUCTION_CONTROL}),
            recorded_at=now - timedelta(days=7),
        )
        decision = acceptance_is_permitted(control_claim, claimant, now=now)
        assert not decision
        assert R.INDEPENDENT_APPROVER_REQUIRED in decision.reasons

    def test_whoever_produced_the_evidence_may_not_accept_the_claim(
        self, control_claim, authority, now
    ):
        producer = replace(authority, name=control_claim.evidence[0].produced_by)
        decision = acceptance_is_permitted(control_claim, producer, now=now)
        assert not decision
        assert R.INDEPENDENT_APPROVER_REQUIRED in decision.reasons

    def test_an_authority_not_recorded_for_this_class_may_not_accept(
        self, control_claim, authority, now
    ):
        narrow = replace(authority, may_accept=frozenset({ClaimClass.MODEL_BEHAVIOUR}))
        decision = acceptance_is_permitted(control_claim, narrow, now=now)
        assert not decision
        assert R.ROLE_NOT_PERMITTED in decision.reasons

    def test_an_unnamed_authority_is_no_authority(self, control_claim, authority, now):
        decision = acceptance_is_permitted(control_claim, replace(authority, name=""), now=now)
        assert not decision
        assert R.AUTHORITY_NOT_RECORDED in decision.reasons

    def test_an_authority_recorded_after_the_claim_cannot_accept_it_yet(
        self, control_claim, authority, now
    ):
        late = replace(authority, recorded_at=now + timedelta(days=1))
        decision = acceptance_is_permitted(control_claim, late, now=now)
        assert not decision
        assert R.AUTHORITY_NOT_RECORDED in decision.reasons

    def test_an_unsupported_claim_cannot_be_accepted_however_senior_the_authority(
        self, control_claim, authority, now
    ):
        unsupported = replace(control_claim, evidence=())
        decision = acceptance_is_permitted(unsupported, authority, now=now)
        assert not decision
        assert R.EVIDENCE_REQUIRED in decision.reasons

    def test_a_claim_from_another_tenant_is_refused(self, control_claim, authority, now):
        decision = acceptance_is_permitted(
            replace(control_claim, organization=OTHER_ORG), authority, now=now, organization=ORG
        )
        assert not decision
        assert R.TENANT_MISMATCH in decision.reasons


class TestPermissionIsNotAcceptance:
    """The gate decision stays outside this package, structurally.

    An allowed decision here says *this authority may accept this claim*. It
    does not say anyone did. Nothing in the module can record that they did.
    """

    def test_the_allowed_decision_says_permitted_not_accepted(self, control_claim, authority, now):
        decision = acceptance_is_permitted(control_claim, authority, now=now)
        assert decision.detail["acceptance_recorded"] is False
        assert "permitted" in decision.detail["note"]

    def test_the_module_defines_no_function_that_records_a_decision(self):
        tree = ast.parse(RELEASE_SOURCE, filename="release.py")
        names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        forbidden = ("approve", "sign", "accept_claim", "record", "decide", "authorize_gate")
        offenders = [name for name in names if any(word in name.lower() for word in forbidden)]
        assert not offenders, f"a gate decision is not code: {offenders}"

    def test_the_module_holds_no_mutable_state_a_decision_could_be_written_into(self):
        tree = ast.parse(RELEASE_SOURCE, filename="release.py")
        mutable = [
            target.id
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and isinstance(node.value, ast.List | ast.Dict)
        ]
        assert not mutable, f"module-level mutable state: {mutable}"


class TestReleasePack:
    """ "Combined gate pack and decision" -- the pack half, named honestly."""

    def test_a_pack_whose_every_required_statement_is_supported_is_complete(
        self, control_claim, now
    ):
        pack = ReleasePack(
            gate="G4",
            organization=ORG,
            revision=REVISION,
            required_statements=(control_claim.statement,),
            claims=(control_claim,),
        )
        status = pack_status(pack, now=now)
        assert status.decision
        assert status.supported == (control_claim.statement,)
        assert status.missing == ()

    def test_a_missing_statement_is_named_rather_than_rounded_up(self, control_claim, now):
        pack = ReleasePack(
            gate="G4",
            organization=ORG,
            revision=REVISION,
            required_statements=(control_claim.statement, "key custody is separated"),
            claims=(control_claim,),
        )
        status = pack_status(pack, now=now)
        assert not status.decision
        assert status.missing == ("key custody is separated",)
        assert R.EVIDENCE_REQUIRED in status.decision.reasons

    def test_an_unsupported_claim_leaves_its_statement_unsupported(self, control_claim, now):
        weak = replace(control_claim, evidence=())
        pack = ReleasePack(
            gate="G4",
            organization=ORG,
            revision=REVISION,
            required_statements=(control_claim.statement,),
            claims=(weak,),
        )
        status = pack_status(pack, now=now)
        assert not status.decision
        assert status.unsupported == (control_claim.statement,)
        assert status.supported == ()

    def test_a_claim_for_another_revision_does_not_count_toward_this_pack(self, control_claim, now):
        pack = ReleasePack(
            gate="G4",
            organization=ORG,
            revision="rev-release-candidate-4",
            required_statements=(control_claim.statement,),
            claims=(control_claim,),
        )
        status = pack_status(pack, now=now)
        assert not status.decision
        assert R.WRONG_BUILD in status.decision.reasons

    def test_a_claim_from_another_tenant_does_not_count_either(self, control_claim, now):
        foreign = replace(control_claim, organization=OTHER_ORG)
        pack = ReleasePack(
            gate="G4",
            organization=ORG,
            revision=REVISION,
            required_statements=(control_claim.statement,),
            claims=(foreign,),
        )
        status = pack_status(pack, now=now)
        assert not status.decision
        assert R.TENANT_MISMATCH in status.decision.reasons

    def test_a_pack_with_no_required_statements_is_not_a_pack(self, now):
        pack = ReleasePack(
            gate="G4", organization=ORG, revision=REVISION, required_statements=(), claims=()
        )
        status = pack_status(pack, now=now)
        assert not status.decision
        assert R.CLAIM_STATEMENT_MISSING in status.decision.reasons

    def test_a_complete_pack_is_still_not_a_gate_decision(self, control_claim, now):
        pack = ReleasePack(
            gate="G4",
            organization=ORG,
            revision=REVISION,
            required_statements=(control_claim.statement,),
            claims=(control_claim,),
        )
        status = pack_status(pack, now=now)
        assert status.decision
        assert status.decision.detail["gate_decision_recorded"] is False
