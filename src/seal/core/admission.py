"""L01 + U10 -- admission of untrusted adapter output.

This is the system's primary trust boundary. A worker container runs a scanner
and hands back a document; everything on the other side of this module is
trusted core. Spec Section 8: "Treat scanner output as untrusted data. Validate
types, sizes, enumerations and tenant/job bindings; reject path traversal and
unsafe object references."

Three properties shape the implementation:

**Reject before processing.** L01 requires malformed, oversized, unknown-version
and cross-tenant output "rejected without unsafe processing". So the gates run
cheapest-and-most-hostile first: byte length, then nesting depth scanned over
the raw bytes, then decode and parse, then schema version, and only then fields.
A nesting bomb never reaches ``json.loads``, and a 12 MB document is refused
without being parsed at all.

**Allowlist, never denylist.** Every accepted field is named. An unrecognised
field is a rejection, not something to ignore -- that is what makes spec
Section 8's "A content field cannot invoke a tool or alter policy" structurally
true, because there is no channel for an unexpected instruction to arrive on.

**Never raise.** Every rejection is a ``Decision``. An exception escaping this
module would surface as a 500 at the API boundary and could leave a
half-admitted result behind.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import reasons as R
from .decision import Decision, deny, evaluate
from .identity import IDENTITY_FIELDS, Family
from .priority import Confidence

#: The adapter result schema versions this build understands. Deliberately
#: closed: U10 pins the transformation version, and accepting an unrecognised
#: version would mean guessing at a field layout.
SUPPORTED_SCHEMA_VERSIONS = frozenset({"adapter-result-1"})

#: Coverage statuses an adapter may report. These mirror ``coverage.CoverageStatus``
#: in wire form; the mapping is deliberate and reviewed, not a string cast.
VALID_STATUSES = frozenset({"complete", "partial", "failed", "stopped", "not_assessed"})

VALID_FAMILIES = frozenset(f.value for f in Family)
VALID_CONFIDENCE = frozenset(c.value for c in Confidence)

#: The complete accepted top-level field set.
RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "organization",
        "target_id",
        "job_id",
        "authorization_revision",
        "profile_digest",
        "status",
        "truncated",
        "sanitized",
        "observations",
    }
)

#: The complete accepted observation field set.
OBSERVATION_FIELDS = frozenset(
    {"observation_id", "family", "identity", "severity", "confidence", "evidence_refs"}
)

#: Observation fields that must be present. ``severity`` and ``evidence_refs``
#: are optional because an adapter may legitimately report neither.
REQUIRED_OBSERVATION_FIELDS = ("observation_id", "family", "identity", "confidence")

#: Characters permitted in an evidence reference. Anything else is refused
#: rather than escaped -- a reference is a key in our own store, so there is no
#: legitimate reason for it to contain anything exotic.
_SAFE_REFERENCE_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./"
)

_QUOTE = 0x22
_BACKSLASH = 0x5C
_OPENERS = (0x7B, 0x5B)  # { [
_CLOSERS = (0x7D, 0x5D)  # } ]


@dataclass(frozen=True)
class AdapterLimits:
    """Bounds applied before and during validation.

    A reviewed profile may tighten any of these. None may be removed, which is
    why they are separate named fields rather than an optional dict.
    """

    #: Envelope ceiling. Spec Section 4 caps a single response body at 1 MiB;
    #: this allows headroom for the manifest and observation metadata around it.
    max_payload_bytes: int = 8 * 1024 * 1024
    max_observations: int = 10_000
    max_string_length: int = 4096
    max_nesting_depth: int = 32
    max_evidence_refs: int = 32


@dataclass(frozen=True)
class ExpectedBinding:
    """What the orchestrator dispatched, as the trusted core recorded it.

    U09 forbids taking tenant context from the payload. The result must *match*
    this, and a mismatch is a rejection -- the result never gets to say which
    organization it belongs to.
    """

    organization: str
    target_id: str
    job_id: str
    authorization_revision: int
    profile_digest: str


@dataclass(frozen=True)
class AdmissionResult:
    """The decision, plus the observations only when admission succeeded.

    ``observations`` is empty on any denial. A partially-validated result must
    not leak through, so there is no path that returns some of them.
    """

    decision: Decision
    observations: tuple[dict[str, Any], ...] = ()
    detail: dict[str, object] = field(default_factory=dict)


def max_bracket_depth(raw: bytes) -> int:
    """Greatest object/array nesting depth, scanned over raw bytes.

    Done before parsing, and by scanning rather than recursing, so a nesting
    bomb cannot exhaust the stack on the way to being rejected. String contents
    are skipped (with escape handling) so a route template like
    ``/app/{id}/{sub}`` does not read as nesting.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False

    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == _BACKSLASH:
                escaped = True
            elif byte == _QUOTE:
                in_string = False
            continue
        if byte == _QUOTE:
            in_string = True
        elif byte in _OPENERS:
            depth += 1
            deepest = max(deepest, depth)
        elif byte in _CLOSERS:
            depth -= 1

    return deepest


def reference_is_safe(reference: Any) -> bool:
    """Whether an evidence reference is a safe key in our own evidence store.

    Not a path on any filesystem and never a URL to fetch. Rejects traversal,
    absolute paths, drive letters, scheme-bearing strings, protocol-relative
    prefixes, home expansion and embedded null bytes.
    """
    if not isinstance(reference, str) or not reference:
        return False
    if any(character not in _SAFE_REFERENCE_CHARACTERS for character in reference):
        return False
    if reference.startswith(("/", "~", "//")):
        return False
    segments = reference.split("/")
    return not any(segment in ("", ".", "..") for segment in segments)


def _is_bool(value: Any) -> bool:
    return type(value) is bool


def _is_number(value: Any) -> bool:
    # bool is an int subclass, so an explicit exclusion is required or
    # ``severity: true`` would validate as 1.0.
    return type(value) in (int, float)


def admit(
    raw: bytes | str,
    expected: ExpectedBinding,
    limits: AdapterLimits | None = None,
) -> AdmissionResult:
    """Validate one adapter result against its expected binding.

    Returns ``AdmissionResult``. Never raises, whatever the input.
    """
    limits = limits or AdapterLimits()

    try:
        payload_bytes = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    except (UnicodeEncodeError, TypeError, ValueError):
        return AdmissionResult(deny(R.MALFORMED_PAYLOAD))

    # -- Gate 1: size, before anything looks inside -------------------------
    if len(payload_bytes) > limits.max_payload_bytes:
        return AdmissionResult(
            deny(
                R.PAYLOAD_TOO_LARGE,
                size=len(payload_bytes),
                ceiling=limits.max_payload_bytes,
            )
        )

    # -- Gate 2: nesting depth, still without parsing -----------------------
    depth = max_bracket_depth(payload_bytes)
    if depth > limits.max_nesting_depth:
        return AdmissionResult(
            deny(R.NESTING_TOO_DEEP, depth=depth, ceiling=limits.max_nesting_depth)
        )

    # -- Gate 3: decode and parse -------------------------------------------
    try:
        document = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return AdmissionResult(deny(R.MALFORMED_PAYLOAD))

    if not isinstance(document, dict):
        return AdmissionResult(
            deny(R.MALFORMED_PAYLOAD, note="an adapter result must be a JSON object")
        )

    # -- Gate 4: schema version ---------------------------------------------
    # Returns immediately on failure: an unrecognised version means the field
    # layout is unknown, so validating fields against assumptions drawn from it
    # would be the "unsafe processing" L01 forbids.
    version = document.get("schema_version")
    if not isinstance(version, str) or version not in SUPPORTED_SCHEMA_VERSIONS:
        return AdmissionResult(
            deny(
                R.SCHEMA_VERSION_UNSUPPORTED,
                supplied=version if isinstance(version, str) else None,
                supported=sorted(SUPPORTED_SCHEMA_VERSIONS),
            )
        )

    # -- Gate 5: field allowlist and binding --------------------------------
    failures: list[tuple[bool, str]] = []

    unexpected = sorted(set(document) - RESULT_FIELDS)
    failures.append((not unexpected, R.UNEXPECTED_FIELD))

    failures.append(
        (
            document.get("organization") == expected.organization
            and document.get("target_id") == expected.target_id
            and document.get("job_id") == expected.job_id
            and document.get("authorization_revision") == expected.authorization_revision
            and document.get("profile_digest") == expected.profile_digest,
            R.BINDING_MISMATCH,
        )
    )

    status = document.get("status")
    failures.append((isinstance(status, str) and status in VALID_STATUSES, R.ENUM_VALUE_UNKNOWN))
    failures.append(
        (
            _is_bool(document.get("truncated")) and _is_bool(document.get("sanitized")),
            R.FIELD_TYPE_INVALID,
        )
    )

    observations = document.get("observations")
    if not isinstance(observations, list):
        failures.append((False, R.FIELD_TYPE_INVALID))
        return AdmissionResult(
            evaluate(failures, unexpected_fields=tuple(unexpected)),
        )

    # Count before validating each one, so an enormous list is refused rather
    # than walked.
    if len(observations) > limits.max_observations:
        failures.append((False, R.TOO_MANY_OBSERVATIONS))
        return AdmissionResult(
            evaluate(failures, count=len(observations), ceiling=limits.max_observations)
        )

    for entry in observations:
        failures.extend(_validate_observation(entry, limits))

    decision = evaluate(
        failures,
        job_id=expected.job_id,
        observation_count=len(observations),
        unexpected_fields=tuple(unexpected),
    )
    if not decision.allowed:
        return AdmissionResult(decision)

    return AdmissionResult(decision, observations=tuple(observations))


def _validate_observation(entry: Any, limits: AdapterLimits) -> list[tuple[bool, str]]:
    """Validate one observation. Returns the checks, never raises."""
    if not isinstance(entry, dict):
        return [(False, R.FIELD_TYPE_INVALID)]

    checks: list[tuple[bool, str]] = []

    unexpected = set(entry) - OBSERVATION_FIELDS
    checks.append((not unexpected, R.UNEXPECTED_FIELD))

    missing = [name for name in REQUIRED_OBSERVATION_FIELDS if name not in entry]
    checks.append((not missing, R.MISSING_REQUIRED_FIELD))
    if missing:
        # Without the required fields there is nothing coherent left to check.
        return checks

    identifier = entry.get("observation_id")
    checks.append((isinstance(identifier, str) and bool(identifier), R.FIELD_TYPE_INVALID))
    checks.append(
        (
            not isinstance(identifier, str) or len(identifier) <= limits.max_string_length,
            R.FIELD_TOO_LONG,
        )
    )

    family = entry.get("family")
    family_known = isinstance(family, str) and family in VALID_FAMILIES
    confidence = entry.get("confidence")
    confidence_known = isinstance(confidence, str) and confidence in VALID_CONFIDENCE
    checks.append((family_known and confidence_known, R.ENUM_VALUE_UNKNOWN))

    identity = entry.get("identity")
    checks.append((isinstance(identity, dict), R.FIELD_TYPE_INVALID))
    if isinstance(identity, dict) and family_known:
        # The identity's keys must be exactly those its declared family uses --
        # a web observation carrying dependency fields is incoherent, and
        # guessing which the adapter meant is not this module's job.
        wanted = set(IDENTITY_FIELDS[Family(family)])
        checks.append((set(identity) == wanted, R.FIELD_TYPE_INVALID))
        for value in identity.values():
            checks.append((isinstance(value, str) and bool(value), R.FIELD_TYPE_INVALID))
            checks.append(
                (
                    not isinstance(value, str) or len(value) <= limits.max_string_length,
                    R.FIELD_TOO_LONG,
                )
            )

    if "severity" in entry:
        severity = entry["severity"]
        checks.append((_is_number(severity), R.FIELD_TYPE_INVALID))
        if _is_number(severity):
            checks.append((0 <= severity <= 10, R.FIELD_VALUE_OUT_OF_RANGE))

    if "evidence_refs" in entry:
        references = entry["evidence_refs"]
        checks.append((isinstance(references, list), R.FIELD_TYPE_INVALID))
        if isinstance(references, list):
            checks.append((len(references) <= limits.max_evidence_refs, R.TOO_MANY_EVIDENCE_REFS))
            for reference in references:
                if not isinstance(reference, str):
                    checks.append((False, R.FIELD_TYPE_INVALID))
                    continue
                checks.append((reference_is_safe(reference), R.PATH_TRAVERSAL_REJECTED))

    return checks
