"""L01 + U10 -- the admission validator for untrusted adapter output.

This is the system's primary trust boundary. Spec Section 8: "Treat scanner
output as untrusted data. Validate types, sizes, enumerations and tenant/job
bindings; reject path traversal and unsafe object references."

L01's acceptance evidence is the shape of this file: "Malformed, oversized,
unknown-version and cross-tenant output rejected **without unsafe
processing**." The last clause is the hard part and drives the ordering tests
below -- a validator that parses a 500 MB document before noticing it is too
large has already lost.
"""

from __future__ import annotations

import json

import pytest
from conftest import ORG, OTHER_ORG, PROFILE, TARGET

from seal.core import reasons as R
from seal.core.admission import (
    SUPPORTED_SCHEMA_VERSIONS,
    AdapterLimits,
    ExpectedBinding,
    admit,
    max_bracket_depth,
    reference_is_safe,
)

SCHEMA = "adapter-result-1"


@pytest.fixture
def binding() -> ExpectedBinding:
    """What the orchestrator dispatched. The result must match it exactly."""
    return ExpectedBinding(
        organization=ORG,
        target_id=TARGET,
        job_id="job-1",
        authorization_revision=1,
        profile_digest=PROFILE,
    )


@pytest.fixture
def limits() -> AdapterLimits:
    return AdapterLimits()


def observation(**overrides) -> dict:
    base = {
        "observation_id": "obs-1",
        "family": "web",
        "identity": {
            "alert_class": "zap.40012",
            "route_template": "/app/users/{id}",
            "method_class": "safe",
            "parameter": "q",
        },
        "severity": 8.0,
        "confidence": "High",
        "evidence_refs": ["evidence/job-1/obs-1.json"],
    }
    base.update(overrides)
    return base


def payload(**overrides) -> dict:
    base = {
        "schema_version": SCHEMA,
        "organization": ORG,
        "target_id": TARGET,
        "job_id": "job-1",
        "authorization_revision": 1,
        "profile_digest": PROFILE,
        "status": "complete",
        "truncated": False,
        "sanitized": True,
        "observations": [observation()],
    }
    base.update(overrides)
    return base


def raw(data: dict) -> bytes:
    return json.dumps(data).encode("utf-8")


class TestHappyPath:
    def test_a_well_formed_result_is_admitted(self, binding, limits):
        result = admit(raw(payload()), binding, limits)
        assert result.decision.allowed, result.decision.reasons
        assert len(result.observations) == 1
        assert result.observations[0]["observation_id"] == "obs-1"

    def test_nothing_is_returned_when_admission_is_denied(self, binding, limits):
        """A rejected result must not leak partially-validated data through."""
        result = admit(raw(payload(organization=OTHER_ORG)), binding, limits)
        assert not result.decision.allowed
        assert result.observations == ()

    def test_an_empty_observation_list_is_admitted(self, binding, limits):
        """A clean scan legitimately returns nothing. That is not an error."""
        result = admit(raw(payload(observations=[])), binding, limits)
        assert result.decision.allowed, result.decision.reasons
        assert result.observations == ()


class TestBoundedParsing:
    """Oversized and hostile input must be refused before it is parsed."""

    def test_an_oversized_payload_is_refused(self, binding, limits):
        huge = raw(payload()) + b" " * (limits.max_payload_bytes + 1)
        result = admit(huge, binding, limits)
        assert R.PAYLOAD_TOO_LARGE in result.decision.reasons

    def test_an_oversized_payload_is_refused_without_parsing_it(self, binding, limits):
        """The size check must precede the parse.

        Built as valid JSON that would parse fine, so the only way this can be
        rejected is on length. A validator that parsed first would admit it.
        """
        oversized_but_valid = raw(
            payload(observations=[observation(observation_id=f"obs-{i}") for i in range(50_000)])
        )
        assert len(oversized_but_valid) > limits.max_payload_bytes
        result = admit(oversized_but_valid, binding, limits)
        assert R.PAYLOAD_TOO_LARGE in result.decision.reasons
        # Not reported as a count problem: the size gate fired first.
        assert R.TOO_MANY_OBSERVATIONS not in result.decision.reasons

    def test_deeply_nested_input_is_refused_before_parsing(self, binding, limits):
        """A nesting bomb must not reach json.loads and exhaust the stack."""
        bomb = b"[" * 2000 + b"]" * 2000
        result = admit(bomb, binding, limits)
        assert R.NESTING_TOO_DEEP in result.decision.reasons

    def test_malformed_json_is_refused_without_raising(self, binding, limits):
        result = admit(b'{"schema_version": "adapter-result-1", broken', binding, limits)
        assert not result.decision.allowed
        assert R.MALFORMED_PAYLOAD in result.decision.reasons

    def test_invalid_utf8_is_refused_without_raising(self, binding, limits):
        result = admit(b"\xff\xfe\x00 not utf-8", binding, limits)
        assert not result.decision.allowed
        assert R.MALFORMED_PAYLOAD in result.decision.reasons

    def test_a_json_scalar_is_not_a_result(self, binding, limits):
        for scalar in (b"42", b'"a string"', b"true", b"null"):
            result = admit(scalar, binding, limits)
            assert R.MALFORMED_PAYLOAD in result.decision.reasons

    def test_a_top_level_list_is_not_a_result(self, binding, limits):
        result = admit(b"[]", binding, limits)
        assert R.MALFORMED_PAYLOAD in result.decision.reasons

    def test_an_empty_payload_is_refused(self, binding, limits):
        result = admit(b"", binding, limits)
        assert not result.decision.allowed

    def test_bracket_depth_counts_nesting(self):
        assert max_bracket_depth(b"{}") == 1
        assert max_bracket_depth(b'{"a": {"b": 1}}') == 2
        assert max_bracket_depth(b"[[[]]]") == 3
        assert max_bracket_depth(b"{}{}{}") == 1

    def test_bracket_depth_ignores_brackets_inside_strings(self):
        """Otherwise a legitimate value containing braces reads as nesting."""
        assert max_bracket_depth(b'{"route": "/app/{id}/{sub}"}') == 1

    def test_bracket_depth_handles_escaped_quotes_in_strings(self):
        assert max_bracket_depth(rb'{"q": "say \"[[[\" loudly"}') == 1


class TestSchemaVersion:
    def test_an_unknown_schema_version_is_refused(self, binding, limits):
        result = admit(raw(payload(schema_version="adapter-result-99")), binding, limits)
        assert R.SCHEMA_VERSION_UNSUPPORTED in result.decision.reasons

    def test_a_missing_schema_version_is_refused(self, binding, limits):
        body = payload()
        del body["schema_version"]
        result = admit(raw(body), binding, limits)
        assert R.SCHEMA_VERSION_UNSUPPORTED in result.decision.reasons

    def test_a_non_string_schema_version_is_refused(self, binding, limits):
        result = admit(raw(payload(schema_version=1)), binding, limits)
        assert R.SCHEMA_VERSION_UNSUPPORTED in result.decision.reasons

    def test_the_supported_set_is_explicit_and_small(self):
        """U10 pins the transformation version; an open-ended set defeats that."""
        assert SUPPORTED_SCHEMA_VERSIONS == frozenset({SCHEMA})

    def test_the_version_is_checked_before_field_validation(self, binding, limits):
        """An unknown version means the field layout is unknown too.

        Validating fields against assumptions drawn from a version we do not
        recognise is exactly the "unsafe processing" L01 forbids.
        """
        result = admit(
            raw({"schema_version": "adapter-result-99", "observations": "not even a list"}),
            binding,
            limits,
        )
        assert R.SCHEMA_VERSION_UNSUPPORTED in result.decision.reasons
        assert R.FIELD_TYPE_INVALID not in result.decision.reasons


class TestTenantAndJobBinding:
    def test_a_cross_tenant_result_is_refused(self, binding, limits):
        """L01: cross-tenant output rejected. A worker cannot relabel its org."""
        result = admit(raw(payload(organization=OTHER_ORG)), binding, limits)
        assert R.BINDING_MISMATCH in result.decision.reasons

    def test_a_result_for_another_target_is_refused(self, binding, limits):
        result = admit(raw(payload(target_id="target-other")), binding, limits)
        assert R.BINDING_MISMATCH in result.decision.reasons

    def test_a_result_for_another_job_is_refused(self, binding, limits):
        result = admit(raw(payload(job_id="job-99")), binding, limits)
        assert R.BINDING_MISMATCH in result.decision.reasons

    def test_a_result_claiming_a_different_authorization_revision_is_refused(self, binding, limits):
        result = admit(raw(payload(authorization_revision=2)), binding, limits)
        assert R.BINDING_MISMATCH in result.decision.reasons

    def test_a_result_claiming_a_different_profile_is_refused(self, binding, limits):
        result = admit(raw(payload(profile_digest="other-profile")), binding, limits)
        assert R.BINDING_MISMATCH in result.decision.reasons

    @pytest.mark.parametrize(
        "field",
        ["organization", "target_id", "job_id", "authorization_revision", "profile_digest"],
    )
    def test_every_binding_field_must_be_present(self, binding, limits, field):
        body = payload()
        del body[field]
        result = admit(raw(body), binding, limits)
        assert not result.decision.allowed
        assert R.BINDING_MISMATCH in result.decision.reasons


class TestFieldValidation:
    def test_observations_must_be_a_list(self, binding, limits):
        result = admit(raw(payload(observations={"not": "a list"})), binding, limits)
        assert R.FIELD_TYPE_INVALID in result.decision.reasons

    def test_an_observation_must_be_an_object(self, binding, limits):
        result = admit(raw(payload(observations=["a string"])), binding, limits)
        assert R.FIELD_TYPE_INVALID in result.decision.reasons

    def test_too_many_observations_are_refused(self, binding, limits):
        many = [observation(observation_id=f"obs-{i}") for i in range(limits.max_observations + 1)]
        # Raise the size ceiling so the count gate is what fires.
        generous = AdapterLimits(max_payload_bytes=50_000_000)
        result = admit(raw(payload(observations=many)), binding, generous)
        assert R.TOO_MANY_OBSERVATIONS in result.decision.reasons

    def test_an_overlong_string_field_is_refused(self, binding, limits):
        long_id = "o" * (limits.max_string_length + 1)
        result = admit(
            raw(payload(observations=[observation(observation_id=long_id)])), binding, limits
        )
        assert R.FIELD_TOO_LONG in result.decision.reasons

    def test_a_non_boolean_truncated_flag_is_refused(self, binding, limits):
        """'truncated': 'false' is a string, and a truthy one at that."""
        result = admit(raw(payload(truncated="false")), binding, limits)
        assert R.FIELD_TYPE_INVALID in result.decision.reasons

    def test_a_non_boolean_sanitized_flag_is_refused(self, binding, limits):
        result = admit(raw(payload(sanitized=1)), binding, limits)
        assert R.FIELD_TYPE_INVALID in result.decision.reasons

    @pytest.mark.parametrize("missing", ["observation_id", "family", "identity", "confidence"])
    def test_a_required_observation_field_must_be_present(self, binding, limits, missing):
        obs = observation()
        del obs[missing]
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert not result.decision.allowed
        assert R.MISSING_REQUIRED_FIELD in result.decision.reasons

    def test_an_unexpected_observation_field_is_refused(self, binding, limits):
        """An allowlist, not a denylist. An unknown field means an unknown
        contract, which U10 requires rejecting rather than ignoring."""
        result = admit(
            raw(payload(observations=[observation(exploit_command="rm -rf /")])),
            binding,
            limits,
        )
        assert R.UNEXPECTED_FIELD in result.decision.reasons

    def test_an_unexpected_top_level_field_is_refused(self, binding, limits):
        result = admit(raw(payload(run_this="curl evil.invalid")), binding, limits)
        assert R.UNEXPECTED_FIELD in result.decision.reasons


class TestEnumerations:
    @pytest.mark.parametrize("family", ["web", "source", "dependency"])
    def test_known_families_are_accepted(self, binding, limits, family):
        identities = {
            "web": observation()["identity"],
            "source": {
                "rule": "semgrep.sqli",
                "repository": "lab/app",
                "structural_context": "UserRepo.find",
            },
            "dependency": {
                "ecosystem": "pypi",
                "package": "requests",
                "vulnerability": "CVE-2026-0001",
            },
        }
        obs = observation(family=family, identity=identities[family])
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert result.decision.allowed, result.decision.reasons

    def test_an_unknown_family_is_refused(self, binding, limits):
        result = admit(raw(payload(observations=[observation(family="network")])), binding, limits)
        assert R.ENUM_VALUE_UNKNOWN in result.decision.reasons

    def test_an_unknown_confidence_is_refused(self, binding, limits):
        result = admit(
            raw(payload(observations=[observation(confidence="Definitely")])), binding, limits
        )
        assert R.ENUM_VALUE_UNKNOWN in result.decision.reasons

    def test_an_unknown_status_is_refused(self, binding, limits):
        result = admit(raw(payload(status="totally_fine")), binding, limits)
        assert R.ENUM_VALUE_UNKNOWN in result.decision.reasons

    def test_identity_keys_must_match_the_declared_family(self, binding, limits):
        """A web family carrying dependency identity fields is incoherent."""
        obs = observation(
            family="web",
            identity={"ecosystem": "pypi", "package": "requests", "vulnerability": "CVE-1"},
        )
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert not result.decision.allowed

    def test_severity_outside_the_cvss_range_is_refused(self, binding, limits):
        for bad in (-1.0, 10.1, 999):
            result = admit(raw(payload(observations=[observation(severity=bad)])), binding, limits)
            assert R.FIELD_VALUE_OUT_OF_RANGE in result.decision.reasons

    def test_a_non_numeric_severity_is_refused(self, binding, limits):
        result = admit(raw(payload(observations=[observation(severity="high")])), binding, limits)
        assert R.FIELD_TYPE_INVALID in result.decision.reasons

    def test_a_boolean_is_not_a_severity(self, binding, limits):
        """bool is an int subclass in Python, so this needs an explicit guard."""
        result = admit(raw(payload(observations=[observation(severity=True)])), binding, limits)
        assert R.FIELD_TYPE_INVALID in result.decision.reasons


class TestUnsafeReferences:
    @pytest.mark.parametrize(
        "unsafe",
        [
            "../../etc/passwd",
            "/etc/passwd",
            "evidence/../../../secrets",
            "C:\\Windows\\System32\\config",
            "evidence\\..\\secrets",
            "file:///etc/passwd",
            "http://evil.invalid/exfil",
            "//evil.invalid/share",
            "evidence/\x00truncated",
            "~/.ssh/id_rsa",
            "",
        ],
    )
    def test_unsafe_evidence_references_are_rejected(self, unsafe):
        assert not reference_is_safe(unsafe)

    @pytest.mark.parametrize(
        "safe",
        [
            "evidence/job-1/obs-1.json",
            "evidence/job-1/response-headers.txt",
            "obs-1.json",
            "a/b/c/d.bin",
        ],
    )
    def test_ordinary_references_are_accepted(self, safe):
        assert reference_is_safe(safe)

    def test_a_traversing_reference_denies_the_whole_result(self, binding, limits):
        obs = observation(evidence_refs=["../../etc/passwd"])
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert R.PATH_TRAVERSAL_REJECTED in result.decision.reasons
        assert result.observations == ()

    def test_an_absolute_reference_denies_the_result(self, binding, limits):
        obs = observation(evidence_refs=["/etc/shadow"])
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert R.PATH_TRAVERSAL_REJECTED in result.decision.reasons

    def test_a_url_reference_is_refused(self, binding, limits):
        """An evidence reference is a key in our own store, never a URL to fetch."""
        obs = observation(evidence_refs=["https://evil.invalid/payload"])
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert R.PATH_TRAVERSAL_REJECTED in result.decision.reasons

    def test_too_many_evidence_references_are_refused(self, binding, limits):
        obs = observation(
            evidence_refs=[f"evidence/e{i}.json" for i in range(limits.max_evidence_refs + 1)]
        )
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert R.TOO_MANY_EVIDENCE_REFS in result.decision.reasons

    def test_evidence_refs_must_be_a_list_of_strings(self, binding, limits):
        obs = observation(evidence_refs=[{"nested": "object"}])
        result = admit(raw(payload(observations=[obs])), binding, limits)
        assert R.FIELD_TYPE_INVALID in result.decision.reasons


class TestNoUnsafeProcessing:
    """The result is data. It can never become an instruction."""

    def test_a_content_field_cannot_carry_an_executable_instruction(self, binding, limits):
        """Spec Section 8: "A content field cannot invoke a tool or alter policy."

        The allowlist is what guarantees this: a field the contract does not
        name is refused, so there is no channel for a command to arrive at all.
        """
        for hostile in ("command", "shell", "exec", "flags", "policy_override"):
            result = admit(
                raw(payload(observations=[observation(**{hostile: "whatever"})])),
                binding,
                limits,
            )
            assert R.UNEXPECTED_FIELD in result.decision.reasons

    def test_admitted_observations_are_plain_data(self, binding, limits):
        """What comes back must be inert dicts and primitives, nothing callable."""
        result = admit(raw(payload()), binding, limits)
        assert result.decision.allowed
        obs = result.observations[0]
        assert isinstance(obs, dict)
        for value in obs.values():
            assert isinstance(value, str | int | float | bool | dict | list | type(None))
            assert not callable(value)

    def test_the_validator_never_raises_on_hostile_input(self, binding, limits):
        """Every rejection is a Decision, not an exception the caller must catch.

        An exception escaping here would become a 500 at the API boundary and,
        worse, could leave a half-admitted result behind.
        """
        hostile = [
            b"",
            b"\x00\x00\x00",
            b"{",
            b"[" * 5000,
            b'{"schema_version": null}',
            b'{"observations": [[[[[[[[[[]]]]]]]]]]}',
            b"\xff" * 100,
            json.dumps({"schema_version": SCHEMA, "observations": [None]}).encode(),
            json.dumps({"a": {"b": {"c": {"d": {"e": {}}}}}}).encode(),
        ]
        for case in hostile:
            result = admit(case, binding, limits)
            assert not result.decision.allowed
            assert result.observations == ()

    def test_every_denial_names_at_least_one_reason(self, binding, limits):
        for case in (b"", b"{}", b"[]", raw(payload(organization=OTHER_ORG))):
            result = admit(case, binding, limits)
            assert not result.decision.allowed
            assert result.decision.reasons


class TestLimitsAreExplicit:
    def test_the_defaults_are_the_documented_ceilings(self):
        """Spec Section 4 caps a response at 1 MiB; the envelope allows headroom
        for the manifest and observation metadata around it."""
        limits = AdapterLimits()
        assert limits.max_payload_bytes == 8 * 1024 * 1024
        assert limits.max_observations == 10_000
        assert limits.max_string_length == 4096
        assert limits.max_nesting_depth == 32
        assert limits.max_evidence_refs == 32

    def test_limits_are_overridable_per_profile(self, binding):
        """A reviewed profile may tighten a ceiling; it may not remove one."""
        strict = AdapterLimits(max_observations=1)
        two = [observation(observation_id="a"), observation(observation_id="b")]
        result = admit(raw(payload(observations=two)), binding, strict)
        assert R.TOO_MANY_OBSERVATIONS in result.decision.reasons
