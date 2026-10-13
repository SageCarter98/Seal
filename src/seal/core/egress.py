"""U02 -- scope enforcement at the network boundary.

Spec Section 4: "Treat the target as an exact registered identity, including
scheme, host, port and approved paths." The decision lives here, outside the
scanner, so a compromised worker cannot bypass it.

What this module deliberately does NOT do: resolve DNS, open sockets, or follow
anything. Address resolution is an *input* (``resolved_addresses``) supplied by
the boundary that actually performed it. Keeping the decision pure is what lets
the DNS-rebinding and redirect-escape scenarios in spec Section 10 be tested as
fixtures -- a rebind is just two different address lists for the same host.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

from . import reasons as R
from .decision import Decision, evaluate

#: Spec Section 4 allows only ordinary web schemes; anything else is rejected
#: rather than interpreted.
SUPPORTED_SCHEMES = frozenset({"http", "https"})

#: Destinations denied regardless of registration. The cloud instance-metadata
#: addresses are the specific "control-plane, metadata and other forbidden
#: destinations" spec Section 4 names.
FORBIDDEN_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, incl. 169.254.169.254 metadata
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("ff00::/8"),
)


class Disposition(str, Enum):
    """What the boundary should do with a proposed request."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class RegisteredTarget:
    """The exact identity a job is authorized against.

    ``lab_addresses`` carries the point spec Section 4 is emphatic about: "An
    owned private laboratory address requires explicit registration and an
    isolated route; private addressing alone is never authorization." So a
    private address is denied unless it appears here by registration.
    """

    target_id: str
    organization: str
    scheme: str
    host: str
    port: int
    approved_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...] = ()
    lab_addresses: frozenset[str] = frozenset()

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass(frozen=True)
class ProposedRequest:
    """A request the boundary is being asked to permit, before it is made."""

    scheme: str
    host: str
    port: int
    path: str
    method: str = "GET"
    #: True only when this came from a redirect the target offered. Spec
    #: Section 4: "Do not follow redirects automatically. A proposed redirect
    #: must pass a fresh scope decision or stop."
    from_redirect: bool = False
    #: Set by the caller when a fresh scope decision has been taken for this
    #: redirect hop. A redirect with this False is denied even if in scope,
    #: so "allowed destination" can never be mistaken for "follow it".
    redirect_revalidated: bool = False


def has_ambiguous_encoding(path: str) -> bool:
    """True when a path's encoding could be read more than one way.

    Spec Section 4 requires rejecting ambiguous URL encodings. Double-encoded
    percent sequences, encoded path separators and encoded dot segments all let
    the same bytes mean different paths to Seal and to the target, which is
    exactly how a scope check gets bypassed.
    """
    lowered = path.lower()
    suspicious = (
        "%25",  # encoded percent: double encoding
        "%2f",  # encoded slash
        "%5c",  # encoded backslash
        "%2e",  # encoded dot
        "..",
        "\\",
    )
    if any(token in lowered for token in suspicious):
        return True
    # A stray percent that is not a complete escape is undecidable.
    index = lowered.find("%")
    while index != -1:
        escape = lowered[index : index + 3]
        if len(escape) < 3 or any(c not in "0123456789abcdef" for c in escape[1:]):
            return True
        index = lowered.find("%", index + 1)
    return False


def _path_matches(path: str, pattern: str) -> bool:
    """Prefix match on whole path segments.

    Segment-aware so an approved ``/api`` does not silently approve
    ``/apifoo``. There is no wildcard language here on purpose: spec Section 5
    forbids guessing that unrelated paths are equivalent, and a glob syntax is
    how that guessing creeps in.
    """
    if pattern == path:
        return True
    prefix = pattern if pattern.endswith("/") else pattern + "/"
    return path.startswith(prefix)


def evaluate_destination(
    target: RegisteredTarget,
    request: ProposedRequest,
    *,
    resolved_addresses: tuple[str, ...],
    pinned_address: str | None,
) -> Decision:
    """Decide whether one outbound request may be made.

    ``resolved_addresses`` is every address the host resolved to at execution
    time -- spec Section 4 requires evaluating all returned IPv4/IPv6 addresses,
    not just the one that will be connected to, so a host that resolves to one
    approved and one forbidden address is denied outright.

    ``pinned_address`` is the address the connection will actually be bound to.
    It must be one of the resolved set; binding something unresolved is how a
    rebind slips through between the check and the connect.
    """
    addresses = [_parse(address) for address in resolved_addresses]
    forbidden = [
        str(address)
        for address in addresses
        if address is not None and _is_forbidden(address, target)
    ]
    unparseable = any(address is None for address in addresses)

    checks: list[tuple[bool, str]] = [
        (request.scheme in SUPPORTED_SCHEMES, R.SCHEME_NOT_SUPPORTED),
        # Preserve host/TLS validation when binding an address (spec Section 4):
        # the scheme and host must still be the registered ones.
        (request.scheme == target.scheme, R.SCHEME_NOT_SUPPORTED),
        (bool(request.host) and request.host == target.host, R.HOST_NOT_REGISTERED),
        (request.port == target.port, R.PORT_NOT_REGISTERED),
        (not has_ambiguous_encoding(request.path), R.AMBIGUOUS_ENCODING),
        (
            any(_path_matches(request.path, approved) for approved in target.approved_paths),
            R.PATH_NOT_IN_SCOPE,
        ),
        (
            not any(_path_matches(request.path, excluded) for excluded in target.excluded_paths),
            R.PATH_EXCLUDED,
        ),
        (bool(resolved_addresses) and not unparseable, R.UNRESOLVED_DESTINATION),
        (not forbidden, R.FORBIDDEN_DESTINATION),
        (
            pinned_address is not None and pinned_address in resolved_addresses,
            R.DESTINATION_NOT_PINNED,
        ),
        (
            not request.from_redirect or request.redirect_revalidated,
            R.REDIRECT_REQUIRES_FRESH_DECISION,
        ),
    ]

    return evaluate(
        checks,
        target_id=target.target_id,
        origin=target.origin,
        path=request.path,
        pinned_address=pinned_address,
        forbidden_addresses=tuple(forbidden),
    )


def _parse(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


def _is_forbidden(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, target: RegisteredTarget
) -> bool:
    """Forbidden unless explicitly registered as an isolated lab address.

    Note the ordering: ``FORBIDDEN_NETWORKS`` is checked first and registration
    cannot override it. Registering 169.254.169.254 as a "lab address" must not
    open a path to a cloud metadata service.
    """
    if any(address in network for network in FORBIDDEN_NETWORKS):
        return True
    if address.is_private:
        return str(address) not in target.lab_addresses
    return False
