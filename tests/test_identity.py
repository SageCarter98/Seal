"""U05 -- fingerprints, and reviewed reversible aliases.

L04's acceptance evidence: ">=95% selected same-finding mutations retain/
correctly alias identity; zero seeded distinct findings silently merged; tenant/
target boundary retained."
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from conftest import ORG, OTHER_ORG, TARGET

from seal.core.identity import (
    FINGERPRINT_VERSION,
    AliasDecision,
    AliasRegistry,
    Family,
    Observation,
    fingerprint,
)

WEB_IDENTITY = {
    "alert_class": "zap.40012",
    "route_template": "/app/users/{id}",
    "method_class": "safe",
    "parameter": "q",
}
DEPENDENCY_IDENTITY = {
    "ecosystem": "pypi",
    "package": "requests",
    "vulnerability": "CVE-2026-0001",
}
SOURCE_IDENTITY = {
    "rule": "semgrep.sqli",
    "repository": "lab/app",
    "structural_context": "UserRepo.find",
}


def web(**overrides) -> str:
    identity = {**WEB_IDENTITY, **overrides}
    return fingerprint(organization=ORG, target_id=TARGET, family=Family.WEB, **identity)


class TestStability:
    def test_the_same_identity_yields_the_same_fingerprint(self):
        assert web() == web()

    def test_volatile_detail_is_not_part_of_the_identity(self):
        """A line number change must not re-identify the finding.

        Volatile fields are refused outright rather than ignored, so a caller
        cannot quietly pass one and believe it mattered.
        """
        with pytest.raises(ValueError, match="volatile fields"):
            fingerprint(
                organization=ORG,
                target_id=TARGET,
                family=Family.WEB,
                line=42,
                **WEB_IDENTITY,
            )

    @pytest.mark.parametrize(
        "volatile", ["line", "line_number", "column", "layer", "build_digest", "commit"]
    )
    def test_each_volatile_field_is_refused(self, volatile):
        with pytest.raises(ValueError, match="volatile"):
            fingerprint(
                organization=ORG,
                target_id=TARGET,
                family=Family.DEPENDENCY,
                **{**DEPENDENCY_IDENTITY, volatile: "x"},
            )

    def test_a_dependency_identity_excludes_the_build_digest(self):
        """Dependency identity excludes build digests but retains them as evidence."""
        identity = fingerprint(
            organization=ORG, target_id=TARGET, family=Family.DEPENDENCY, **DEPENDENCY_IDENTITY
        )
        observation = Observation(
            observation_id="obs-1",
            organization=ORG,
            target_id=TARGET,
            fingerprint=identity,
            job_id="job-1",
            observed_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            evidence={"build_digest": "sha256:abc", "layer": 3},
        )
        assert observation.evidence["build_digest"] == "sha256:abc"
        assert identity == fingerprint(
            organization=ORG, target_id=TARGET, family=Family.DEPENDENCY, **DEPENDENCY_IDENTITY
        )


class TestDistinctness:
    def test_a_different_parameter_is_a_different_finding(self):
        assert web(parameter="search") != web()

    def test_a_different_route_template_is_a_different_finding(self):
        assert web(route_template="/app/orders/{id}") != web()

    def test_a_different_alert_class_is_a_different_finding(self):
        assert web(alert_class="zap.40018") != web()

    def test_distinct_vulnerabilities_in_one_package_stay_distinct(self):
        """Dependency identity must preserve distinct vulnerabilities."""
        first = fingerprint(
            organization=ORG, target_id=TARGET, family=Family.DEPENDENCY, **DEPENDENCY_IDENTITY
        )
        second = fingerprint(
            organization=ORG,
            target_id=TARGET,
            family=Family.DEPENDENCY,
            **{**DEPENDENCY_IDENTITY, "vulnerability": "CVE-2026-0002"},
        )
        assert first != second

    def test_the_family_is_part_of_the_identity(self):
        """A source and a dependency finding cannot collide."""
        source = fingerprint(
            organization=ORG, target_id=TARGET, family=Family.SOURCE, **SOURCE_IDENTITY
        )
        dependency = fingerprint(
            organization=ORG, target_id=TARGET, family=Family.DEPENDENCY, **DEPENDENCY_IDENTITY
        )
        assert source != dependency


class TestTenantBoundary:
    def test_the_same_weakness_in_two_tenants_has_two_identities(self):
        """U09: the organization is hashed content, not just a lookup key."""
        mine = web()
        theirs = fingerprint(
            organization=OTHER_ORG, target_id=TARGET, family=Family.WEB, **WEB_IDENTITY
        )
        assert mine != theirs

    def test_the_same_weakness_on_two_targets_has_two_identities(self):
        assert web() != fingerprint(
            organization=ORG, target_id="target-other", family=Family.WEB, **WEB_IDENTITY
        )

    @pytest.mark.parametrize(("org", "target"), [("", TARGET), (ORG, ""), ("", "")])
    def test_a_missing_boundary_is_refused(self, org, target):
        with pytest.raises(ValueError, match="identity boundary"):
            fingerprint(organization=org, target_id=target, family=Family.WEB, **WEB_IDENTITY)


class TestExactIdentityRequired:
    def test_a_partial_identity_is_refused(self):
        with pytest.raises(ValueError, match="exact identity"):
            fingerprint(
                organization=ORG,
                target_id=TARGET,
                family=Family.WEB,
                alert_class="zap.40012",
            )

    def test_an_unexpected_field_is_refused(self):
        with pytest.raises(ValueError, match="unexpected"):
            fingerprint(
                organization=ORG,
                target_id=TARGET,
                family=Family.WEB,
                extra="x",
                **WEB_IDENTITY,
            )

    def test_an_empty_identity_field_is_refused(self):
        with pytest.raises(ValueError, match="non-empty"):
            fingerprint(
                organization=ORG,
                target_id=TARGET,
                family=Family.WEB,
                **{**WEB_IDENTITY, "parameter": "   "},
            )

    def test_a_non_string_identity_field_is_refused(self):
        with pytest.raises(ValueError, match="non-empty"):
            fingerprint(
                organization=ORG,
                target_id=TARGET,
                family=Family.WEB,
                **{**WEB_IDENTITY, "parameter": 7},
            )

    def test_the_fingerprint_is_versioned(self):
        """A rule change becomes a reviewed migration, not a silent re-identification."""
        assert FINGERPRINT_VERSION == 1


class TestAliases:
    def decision(self, now, **overrides):
        base = {
            "decision_id": "alias-1",
            "organization": ORG,
            "primary_fingerprint": "fp-primary",
            "alias_fingerprint": "fp-alias",
            "reviewer": "reviewer.esi",
            "reason": "same weakness via a renamed route",
            "decided_at": now,
        }
        base.update(overrides)
        return AliasDecision(**base)

    def test_an_alias_resolves_to_its_primary(self, now):
        registry = AliasRegistry([self.decision(now)])
        primary, path = registry.resolve(ORG, "fp-alias")
        assert primary == "fp-primary"
        assert path == ("fp-alias",)

    def test_an_unaliased_fingerprint_resolves_to_itself(self, now):
        registry = AliasRegistry([self.decision(now)])
        assert registry.resolve(ORG, "fp-other") == ("fp-other", ())

    def test_an_alias_requires_a_named_reviewer(self, now):
        registry = AliasRegistry()
        with pytest.raises(ValueError, match="named reviewer"):
            registry.add(self.decision(now, reviewer=""))

    def test_a_fingerprint_cannot_alias_itself(self, now):
        registry = AliasRegistry()
        with pytest.raises(ValueError, match="cannot alias itself"):
            registry.add(self.decision(now, alias_fingerprint="fp-primary"))

    def test_an_alias_does_not_cross_tenants(self, now):
        registry = AliasRegistry([self.decision(now)])
        assert registry.resolve(OTHER_ORG, "fp-alias") == ("fp-alias", ())

    def test_distinct_findings_are_not_merged(self, now):
        """L04: zero seeded distinct findings silently merged."""
        registry = AliasRegistry([self.decision(now)])
        assert registry.distinct(ORG, "fp-a", "fp-b")
        assert not registry.distinct(ORG, "fp-alias", "fp-primary")

    def test_a_reversal_restores_the_original_identity(self, now):
        registry = AliasRegistry()
        registry.add(self.decision(now))
        assert registry.resolve(ORG, "fp-alias")[0] == "fp-primary"

        reversed_decision = registry.reverse(
            "alias-1", reviewer="reviewer.kofi", at=now + timedelta(days=1)
        )
        assert registry.resolve(ORG, "fp-alias")[0] == "fp-alias"
        # The decision survives its reversal as history.
        assert reversed_decision.reversed_at is not None
        assert reversed_decision.reversed_by == "reviewer.kofi"
        assert not reversed_decision.active

    def test_reversing_an_unknown_decision_raises(self, now):
        registry = AliasRegistry([self.decision(now)])
        with pytest.raises(KeyError):
            registry.reverse("alias-99", reviewer="r", at=now)

    def test_reversing_twice_raises(self, now):
        registry = AliasRegistry()
        registry.add(self.decision(now))
        registry.reverse("alias-1", reviewer="r", at=now)
        with pytest.raises(KeyError):
            registry.reverse("alias-1", reviewer="r", at=now)

    def test_an_alias_cycle_is_detected_rather_than_looping(self, now):
        registry = AliasRegistry(
            [
                self.decision(now, decision_id="a", primary_fingerprint="x", alias_fingerprint="y"),
                self.decision(now, decision_id="b", primary_fingerprint="y", alias_fingerprint="x"),
            ]
        )
        with pytest.raises(ValueError, match="alias cycle"):
            registry.resolve(ORG, "x")

    def test_a_chain_records_the_path_it_collapsed(self, now):
        """A reviewer must be able to see what was merged into what."""
        registry = AliasRegistry(
            [
                self.decision(now, decision_id="a", primary_fingerprint="b", alias_fingerprint="c"),
                self.decision(now, decision_id="b", primary_fingerprint="a", alias_fingerprint="b"),
            ]
        )
        primary, path = registry.resolve(ORG, "c")
        assert primary == "a"
        assert path == ("c", "b")


def test_a_contradicting_observation_is_marked_as_such(now):
    """C01 relies on this flag to invalidate a pending closure intent."""
    observation = Observation(
        observation_id="obs-8",
        organization=ORG,
        target_id=TARGET,
        fingerprint=web(),
        job_id="job-2",
        observed_at=now,
        contradicts_fix=True,
    )
    assert observation.contradicts_fix
