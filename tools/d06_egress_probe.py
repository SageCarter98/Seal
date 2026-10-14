"""D06 probe -- what must an egress enforcement mechanism be able to observe?

`docs/decisions/D06_egress_boundary.md` section 3 turns on a constraint that is
measurable today: ``egress.evaluate_destination`` requires a path, a redirect state,
the resolved addresses and a pinned address for every request. A mechanism that sees
only ``host:port`` -- a TLS-tunnelling forward proxy, or a network-layer egress
allowlist -- cannot supply those, and because the decision is deny-by-default it does
not merely decide less safely: it denies everything.

This runs the real decision with the information each candidate mechanism can actually
observe, and prints what happens. Like its D04 counterpart it asserts nothing and
emits no pass/fail: it establishes what the decision needs, not that any mechanism
works, which needs a running platform nobody has authorised.

    python tools/d06_egress_probe.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from seal.core.egress import ProposedRequest, RegisteredTarget, evaluate_destination

TARGET = RegisteredTarget(
    target_id="tgt-1",
    organization="org-1",
    scheme="https",
    host="lab.internal",
    port=443,
    approved_paths=("/app",),
    excluded_paths=("/app/admin",),
    lab_addresses=frozenset({"10.1.2.3"}),
)

SCENARIOS = {
    "broker performs the request (full URL visible)": dict(
        scheme="https", host="lab.internal", port=443, path="/app/search"
    ),
    "CONNECT tunnel proxy (host:port only, path unknown)": dict(
        scheme="https", host="lab.internal", port=443, path=""
    ),
    "CONNECT tunnel, path guessed as root": dict(
        scheme="https", host="lab.internal", port=443, path="/"
    ),
    "network-layer allowlist only (host known, path unknown)": dict(
        scheme="https", host="lab.internal", port=443, path=""
    ),
    "broker, request to an excluded path": dict(
        scheme="https", host="lab.internal", port=443, path="/app/admin/users"
    ),
    "broker, redirect not revalidated": dict(
        scheme="https", host="lab.internal", port=443, path="/app/next", from_redirect=True
    ),
    "broker, redirect revalidated": dict(
        scheme="https",
        host="lab.internal",
        port=443,
        path="/app/next",
        from_redirect=True,
        redirect_revalidated=True,
    ),
}

print("=" * 78)
print("Can the modelled egress decision be made with what each mechanism sees?")
print("=" * 78)
for label, kwargs in SCENARIOS.items():
    request = ProposedRequest(**kwargs)
    decision = evaluate_destination(
        TARGET, request, resolved_addresses=("10.1.2.3",), pinned_address="10.1.2.3"
    )
    verdict = "PERMIT" if decision.allowed else "DENY  " + str(decision.reasons)
    print(f"  {label:54} -> {verdict}")

print()
print("DNS rebinding, with the full URL available:")
for label, resolved, pinned in [
    ("pinned address still in the resolved set", ("10.1.2.3",), "10.1.2.3"),
    ("host now resolves elsewhere (rebind)", ("203.0.113.9",), "10.1.2.3"),
    ("no address pinned at all", ("10.1.2.3",), None),
]:
    request = ProposedRequest(scheme="https", host="lab.internal", port=443, path="/app/search")
    decision = evaluate_destination(
        TARGET, request, resolved_addresses=resolved, pinned_address=pinned
    )
    verdict = "PERMIT" if decision.allowed else "DENY  " + str(decision.reasons)
    print(f"  {label:54} -> {verdict}")
