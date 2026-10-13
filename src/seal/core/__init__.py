"""The Seal decision core: pure contracts, no I/O.

Every module here is a function of its arguments. Nothing opens a socket,
touches a database, reads a clock or spawns a process -- ``now`` is always a
parameter. That constraint is what makes the adversarial scenarios in spec
Section 10 expressible as fixtures: a DNS rebind is two address lists, a late
anchor receipt is a receipt with a later timestamp, and a crash between receipt
verification and commit is simply not calling ``finalize``.

Requirement map:

===========  ==========================================================
Requirement  Module
===========  ==========================================================
U01          ``authorization`` -- scope, revocation, execution grants
U02          ``egress`` -- destination and redirect decisions
U03          ``coverage`` -- manifests and honest coverage states
U04, C01     ``closure`` -- proof review and stale-intent finalization
U05          ``identity``, ``lifecycle`` -- fingerprints, states, exceptions
U06          ``priority`` -- the SSVC-style tree and overrides
U07, U08     ``audit`` -- hash chain, anchor outbox, evidence custody
U10, L01     ``admission`` -- bounded validation of untrusted adapter output
U11          ``incident`` -- halt, hold, routing, undetermined legal duty
U12          ``recovery`` -- idempotency, leases, retry rechecks, checkpoints
U13, C03     ``metrics`` -- exposure measures with visible denominators
C02          ``integrity`` -- admission state, generation, stop budgets
===========  ==========================================================

U09 (tenant isolation) remains partially represented: the organization boundary
is carried through every contract and hashed into every identity, but its
enforcement point is PostgreSQL RLS, which does not exist yet and which this
package does not claim. U14 is not represented at all -- binding a release
claim to an authority is a human gate decision, not code.
"""

from . import (
    admission,
    audit,
    authorization,
    closure,
    coverage,
    decision,
    egress,
    identity,
    incident,
    integrity,
    lifecycle,
    metrics,
    priority,
    reasons,
    recovery,
)

__all__ = [
    "admission",
    "audit",
    "authorization",
    "closure",
    "coverage",
    "decision",
    "egress",
    "identity",
    "incident",
    "integrity",
    "lifecycle",
    "metrics",
    "priority",
    "reasons",
    "recovery",
]
