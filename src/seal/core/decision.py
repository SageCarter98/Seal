"""The one shape every contract in the core returns.

Each contract answers a yes/no question and must say *why* when the answer is
no. Baseline Section 9 requires the denied condition to be explainable before
submission, and spec Section 5 requires an inconclusive verification to state
what evidence is missing -- so a bare ``False`` is never an acceptable result.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Decision:
    """An allow/deny outcome carrying its reason codes.

    ``reasons`` is populated on denial and is ordered by the sequence the checks
    were evaluated in, so the first entry is the earliest failing contract.
    An allowed decision may still carry reasons as positive justification (the
    priority tree and closure both do this).
    """

    allowed: bool
    reasons: tuple[str, ...] = ()
    detail: dict[str, object] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.allowed

    @property
    def reason(self) -> str | None:
        """The first reason code, or None when there are none."""
        return self.reasons[0] if self.reasons else None

    def with_detail(self, **extra: object) -> Decision:
        return Decision(self.allowed, self.reasons, {**self.detail, **extra})


def deny(*reasons: str, **detail: object) -> Decision:
    if not reasons:
        raise ValueError("a denial must name at least one reason")
    return Decision(False, tuple(reasons), dict(detail))


def allow(*reasons: str, **detail: object) -> Decision:
    return Decision(True, tuple(reasons), dict(detail))


def evaluate(checks: list[tuple[bool, str]], **detail: object) -> Decision:
    """Collect every failing check rather than stopping at the first.

    Returning all failures matters for the user workflow: the scope screen has
    to explain every denied condition before submission (U13), not make the
    assessor resubmit once per problem.
    """
    failures = tuple(reason for passed, reason in checks if not passed)
    return Decision(not failures, failures, dict(detail))
