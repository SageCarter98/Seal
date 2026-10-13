"""U05 -- finding identity, versioned fingerprints and reviewed aliases.

Baseline Section 6.10, carried into spec Section 5: web identities use alert
class, normalized route, method class and parameter within organization/target;
source identities use rule and structural context within repository; dependency
identities use ecosystem, package and vulnerability within a logical artifact.

Two rules shape this module:

* Nothing is guessed. Spec Section 5: "use a reviewed route template; do not
  guess that unrelated numeric paths are equivalent." ``fingerprint`` therefore
  takes an already-normalized route template and refuses to invent one.
* Volatile detail is observation evidence, never identity. Line numbers and
  build digests change without the weakness changing, so they are excluded from
  the fingerprint and kept on the observation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ._canonical import digest

#: Fingerprint rule version. Spec Section 5 requires versioned fingerprints so
#: a rule change becomes a reviewed migration with both identities retained,
#: rather than a silent re-identification of every open finding.
FINGERPRINT_VERSION = 1


class Family(str, Enum):
    WEB = "web"
    SOURCE = "source"
    DEPENDENCY = "dependency"


#: The exact identity fields per family. Required to be present and non-empty --
#: a partial identity would collide with every other partial identity.
IDENTITY_FIELDS: dict[Family, tuple[str, ...]] = {
    Family.WEB: ("alert_class", "route_template", "method_class", "parameter"),
    Family.SOURCE: ("rule", "repository", "structural_context"),
    Family.DEPENDENCY: ("ecosystem", "package", "vulnerability"),
}

#: Fields that must never enter a fingerprint even if a caller supplies them.
#: These are the "volatile line/layer/build details" the plan keeps as
#: observation evidence only.
VOLATILE_FIELDS = frozenset(
    {"line", "line_number", "column", "layer", "build_digest", "build", "commit", "timestamp"}
)


def fingerprint(*, organization: str, target_id: str, family: Family, **identity: str) -> str:
    """Compute a versioned fingerprint inside the organization/target boundary.

    The organization and target are part of the hashed content, not just a
    lookup key, so the same weakness in two tenants can never produce the same
    fingerprint. U09 requires the tenant boundary enforced on every path; this
    is that enforcement at the identity layer.
    """
    if not organization or not target_id:
        raise ValueError("organization and target_id are part of the identity boundary")

    expected = IDENTITY_FIELDS[family]
    supplied = set(identity)

    volatile = supplied & VOLATILE_FIELDS
    if volatile:
        raise ValueError(
            f"volatile fields are observation evidence, not identity: {sorted(volatile)}"
        )
    if supplied != set(expected):
        missing = sorted(set(expected) - supplied)
        unexpected = sorted(supplied - set(expected))
        raise ValueError(
            f"exact identity required for {family.value}; missing={missing} unexpected={unexpected}"
        )
    if any(not isinstance(value, str) or not value.strip() for value in identity.values()):
        raise ValueError("identity fields must be non-empty strings")

    return digest(
        {
            "version": FINGERPRINT_VERSION,
            "organization": organization,
            "target_id": target_id,
            "family": family.value,
            "identity": {key: identity[key] for key in expected},
        }
    )


@dataclass(frozen=True)
class Observation:
    """One sighting of a weakness. Immutable, and never deleted.

    Observations accumulate against a finding: U05 makes a repeat sighting an
    observation event that preserves the current work state, and C03 requires an
    original observation preserved even when a finding is corrected to a false
    positive. So nothing in the lifecycle removes one of these.
    """

    observation_id: str
    organization: str
    target_id: str
    fingerprint: str
    job_id: str
    observed_at: datetime
    #: The volatile detail excluded from the fingerprint lives here instead.
    evidence: dict[str, object] = field(default_factory=dict)
    #: True when this sighting contradicts a claimed fix -- the weakness is
    #: still present. C01 uses this to invalidate a pending closure intent.
    contradicts_fix: bool = False


@dataclass(frozen=True)
class AliasDecision:
    """A reviewed decision that two fingerprints identify the same weakness.

    Spec Section 5: "Alias, merge and split decisions require review, preserve
    original observations and support reversal." Hence the named reviewer, the
    reason, and ``reversed_at`` rather than deletion -- a reversal is a new
    state on the same record, so the history of the merge survives it.
    """

    decision_id: str
    organization: str
    primary_fingerprint: str
    alias_fingerprint: str
    reviewer: str
    reason: str
    decided_at: datetime
    fingerprint_version: int = FINGERPRINT_VERSION
    reversed_at: datetime | None = None
    reversed_by: str = ""

    @property
    def active(self) -> bool:
        return self.reversed_at is None


class AliasRegistry:
    """Resolves a fingerprint to its reviewed primary identity.

    Deliberately not transitive beyond one documented step: chained aliases are
    how two genuinely distinct findings get silently merged through an
    intermediate. ``resolve`` walks the chain but refuses a cycle and records
    the path, so a reviewer can see what was collapsed into what.
    """

    def __init__(self, decisions: list[AliasDecision] | None = None) -> None:
        self._decisions: list[AliasDecision] = list(decisions or [])

    def add(self, decision: AliasDecision) -> None:
        if decision.primary_fingerprint == decision.alias_fingerprint:
            raise ValueError("a fingerprint cannot alias itself")
        if not decision.reviewer:
            raise ValueError("an alias decision requires a named reviewer")
        self._decisions.append(decision)

    def reverse(self, decision_id: str, *, reviewer: str, at: datetime) -> AliasDecision:
        """Reverse an alias without losing the original decision."""
        from dataclasses import replace

        for index, decision in enumerate(self._decisions):
            if decision.decision_id == decision_id and decision.active:
                reversed_decision = replace(decision, reversed_at=at, reversed_by=reviewer)
                self._decisions[index] = reversed_decision
                return reversed_decision
        raise KeyError(f"no active alias decision {decision_id}")

    def resolve(self, organization: str, candidate: str) -> tuple[str, tuple[str, ...]]:
        """Return the primary fingerprint and the alias path taken to reach it."""
        active = {
            d.alias_fingerprint: d.primary_fingerprint
            for d in self._decisions
            if d.active and d.organization == organization
        }
        path: list[str] = []
        current = candidate
        while current in active:
            if current in path:
                raise ValueError(f"alias cycle through {current}")
            path.append(current)
            current = active[current]
        return current, tuple(path)

    def distinct(self, organization: str, left: str, right: str) -> bool:
        """True when two fingerprints are not the same reviewed identity.

        L04's acceptance evidence is "zero seeded distinct findings silently
        merged", so this is the predicate that assertion tests against.
        """
        return self.resolve(organization, left)[0] != self.resolve(organization, right)[0]
