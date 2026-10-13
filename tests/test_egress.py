"""U02 -- scope enforcement at the network boundary.

Acceptance evidence: "DNS, redirect and stop tests". Spec Section 10 adds
DNS rebinding, redirect escape and compromised-worker egress as required
adversarial scenarios.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from seal.core import reasons as R
from seal.core.egress import (
    ProposedRequest,
    evaluate_destination,
    has_ambiguous_encoding,
)

LAB_ADDRESS = "10.10.0.5"
PUBLIC_ADDRESS = "203.0.113.10"
METADATA_ADDRESS = "169.254.169.254"


def request(**changes) -> ProposedRequest:
    base = {
        "scheme": "https",
        "host": "lab.internal.invalid",
        "port": 443,
        "path": "/app",
        "method": "GET",
    }
    base.update(changes)
    return ProposedRequest(**base)


def decide(target, proposed, *, addresses=(LAB_ADDRESS,), pinned=LAB_ADDRESS):
    return evaluate_destination(
        target, proposed, resolved_addresses=addresses, pinned_address=pinned
    )


class TestExactTargetIdentity:
    def test_registered_origin_and_path_is_allowed(self, registered_target):
        assert decide(registered_target, request()).allowed

    def test_approved_subpath_is_allowed(self, registered_target):
        assert decide(registered_target, request(path="/api/v1/users")).allowed

    def test_unapproved_path_is_denied(self, registered_target):
        decision = decide(registered_target, request(path="/internal"))
        assert R.PATH_NOT_IN_SCOPE in decision.reasons

    def test_excluded_path_is_denied_even_though_the_prefix_is_approved(self, registered_target):
        decision = decide(registered_target, request(path="/app/admin/settings"))
        assert R.PATH_EXCLUDED in decision.reasons

    def test_path_matching_is_segment_aware(self, registered_target):
        """An approved /app must not approve /appendix."""
        decision = decide(registered_target, request(path="/appendix"))
        assert R.PATH_NOT_IN_SCOPE in decision.reasons

    def test_different_host_is_denied(self, registered_target):
        decision = decide(registered_target, request(host="evil.invalid"))
        assert R.HOST_NOT_REGISTERED in decision.reasons

    def test_different_port_is_denied(self, registered_target):
        """Scheme, host, port and path are all part of the identity."""
        decision = decide(registered_target, request(port=8443))
        assert R.PORT_NOT_REGISTERED in decision.reasons

    def test_scheme_downgrade_is_denied(self, registered_target):
        decision = decide(registered_target, request(scheme="http"))
        assert R.SCHEME_NOT_SUPPORTED in decision.reasons

    @pytest.mark.parametrize("scheme", ["file", "gopher", "ftp", "javascript"])
    def test_unsupported_schemes_are_denied(self, registered_target, scheme):
        decision = decide(registered_target, request(scheme=scheme))
        assert R.SCHEME_NOT_SUPPORTED in decision.reasons


class TestForbiddenDestinations:
    def test_cloud_metadata_address_is_denied(self, registered_target):
        decision = decide(
            registered_target,
            request(),
            addresses=(METADATA_ADDRESS,),
            pinned=METADATA_ADDRESS,
        )
        assert R.FORBIDDEN_DESTINATION in decision.reasons

    def test_metadata_address_cannot_be_registered_as_a_lab_address(self, registered_target):
        """Registration must not open a path to a cloud metadata service."""
        permissive = replace(registered_target, lab_addresses=frozenset({METADATA_ADDRESS}))
        decision = decide(
            permissive, request(), addresses=(METADATA_ADDRESS,), pinned=METADATA_ADDRESS
        )
        assert R.FORBIDDEN_DESTINATION in decision.reasons

    def test_loopback_is_denied(self, registered_target):
        decision = decide(
            registered_target, request(), addresses=("127.0.0.1",), pinned="127.0.0.1"
        )
        assert R.FORBIDDEN_DESTINATION in decision.reasons

    def test_unregistered_private_address_is_denied(self, registered_target):
        """Private addressing alone is never authorization (spec Section 4)."""
        decision = decide(
            registered_target, request(), addresses=("192.168.1.10",), pinned="192.168.1.10"
        )
        assert R.FORBIDDEN_DESTINATION in decision.reasons

    def test_registered_lab_address_is_allowed(self, registered_target):
        assert decide(registered_target, request()).allowed

    def test_ipv6_link_local_is_denied(self, registered_target):
        decision = decide(registered_target, request(), addresses=("fe80::1",), pinned="fe80::1")
        assert R.FORBIDDEN_DESTINATION in decision.reasons


class TestDnsRebinding:
    def test_every_resolved_address_is_evaluated_not_only_the_pinned_one(self, registered_target):
        """A host resolving to one approved and one forbidden address is denied."""
        decision = decide(
            registered_target,
            request(),
            addresses=(LAB_ADDRESS, METADATA_ADDRESS),
            pinned=LAB_ADDRESS,
        )
        assert not decision.allowed
        assert R.FORBIDDEN_DESTINATION in decision.reasons
        assert METADATA_ADDRESS in decision.detail["forbidden_addresses"]

    def test_binding_an_address_outside_the_resolved_set_is_denied(self, registered_target):
        """The rebind window: check one address, connect to another."""
        decision = decide(
            registered_target, request(), addresses=(LAB_ADDRESS,), pinned=METADATA_ADDRESS
        )
        assert R.DESTINATION_NOT_PINNED in decision.reasons

    def test_no_pinned_address_is_denied(self, registered_target):
        decision = decide(registered_target, request(), pinned=None)
        assert R.DESTINATION_NOT_PINNED in decision.reasons

    def test_empty_resolution_is_denied(self, registered_target):
        decision = decide(registered_target, request(), addresses=(), pinned=None)
        assert R.UNRESOLVED_DESTINATION in decision.reasons

    def test_unparseable_address_is_denied(self, registered_target):
        decision = decide(
            registered_target, request(), addresses=("not-an-address",), pinned="not-an-address"
        )
        assert R.UNRESOLVED_DESTINATION in decision.reasons


class TestRedirects:
    def test_a_redirect_is_not_followed_automatically(self, registered_target):
        """Even a redirect to an in-scope path needs a fresh scope decision."""
        decision = decide(registered_target, request(path="/api/v1", from_redirect=True))
        assert not decision.allowed
        assert R.REDIRECT_REQUIRES_FRESH_DECISION in decision.reasons

    def test_a_revalidated_in_scope_redirect_is_allowed(self, registered_target):
        decision = decide(
            registered_target,
            request(path="/api/v1", from_redirect=True, redirect_revalidated=True),
        )
        assert decision.allowed, decision.reasons

    def test_a_revalidated_out_of_scope_redirect_is_still_denied(self, registered_target):
        """Redirect escape: revalidation is a check, not a bypass."""
        decision = decide(
            registered_target,
            request(host="attacker.invalid", from_redirect=True, redirect_revalidated=True),
        )
        assert R.HOST_NOT_REGISTERED in decision.reasons

    def test_redirect_to_metadata_is_denied_twice_over(self, registered_target):
        decision = decide(
            registered_target,
            request(from_redirect=True),
            addresses=(METADATA_ADDRESS,),
            pinned=METADATA_ADDRESS,
        )
        assert R.FORBIDDEN_DESTINATION in decision.reasons
        assert R.REDIRECT_REQUIRES_FRESH_DECISION in decision.reasons


class TestAmbiguousEncoding:
    @pytest.mark.parametrize(
        "path",
        [
            "/app/%2e%2e/internal",  # encoded dot segments
            "/app/%252e%252e/internal",  # double encoded
            "/app%2fadmin",  # encoded separator
            "/app/../internal",  # plain traversal
            "/app\\admin",  # backslash
            "/app/%zz",  # invalid escape
            "/app/%2",  # truncated escape
        ],
    )
    def test_ambiguous_paths_are_rejected(self, path):
        assert has_ambiguous_encoding(path)

    @pytest.mark.parametrize("path", ["/app", "/api/v1/users", "/app/a-b_c.json", "/app/%20x"])
    def test_unambiguous_paths_are_accepted(self, path):
        assert not has_ambiguous_encoding(path)

    def test_an_ambiguous_path_is_denied_at_the_boundary(self, registered_target):
        decision = decide(registered_target, request(path="/app/%2e%2e/internal"))
        assert R.AMBIGUOUS_ENCODING in decision.reasons


def test_the_decision_records_what_it_decided_about(registered_target):
    """Control health counts denials by code, so detail must identify the target."""
    decision = decide(registered_target, request(path="/internal"))
    assert decision.detail["target_id"] == registered_target.target_id
    assert decision.detail["origin"] == "https://lab.internal.invalid:443"
    assert decision.detail["path"] == "/internal"
