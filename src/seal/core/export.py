"""W04 + U08 -- the export surface: guarded cells, escaped display, no raw content.

W04 delivers a "role-based dashboard, evidence views, management summary and
tenant-filtered JSON/CSV export", and its acceptance evidence names what must
hold: "server enforces scope; CSV formula injection mitigated; downloads
sanitized; deferred capabilities absent". Spec Section 8 states the same two
output rules in one sentence -- "Escape display content and guard CSV formula
cells" -- and U08 adds that quarantined secrets must appear "never ... in logs,
exports or fixtures".

What a pure core can own here is the *serialization decision*: which rows a
viewer may receive, which fields may leave the system, and how a value that
came from untrusted adapter output is rendered so that a spreadsheet or a
browser cannot execute it. What it cannot own is the HTTP response, the signed
download URL or the session the role came from -- those are W04's platform half
and remain absent.

Two properties shape this module:

**Every cell is quoted, and a formula-looking cell is prefixed.** Uniform
RFC 4180 quoting removes the "did this field need quoting?" judgment from the
hot path; the ``'`` prefix is what actually stops a spreadsheet evaluating the
cell, because a quoted ``"=cmd|..."`` is still a formula to Excel.

**Nothing partial is ever emitted.** Like ``admission``, a denial returns no
document at all. A half-filtered export is the cross-tenant leak U09's negative
tests look for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import reasons as R
from ._canonical import require_aware
from .audit import EvidenceRecord
from .decision import Decision, deny, evaluate
from .lifecycle import Cohort, Finding
from .metrics import DenominatorAdjustment, ExposureReport, exposure_report

#: Formats this build can produce. Closed on purpose: the surface is the
#: contract, and "JSON/CSV" is what baseline Section 6.9 approved for the MVP.
SUPPORTED_FORMATS = frozenset({"json", "csv"})

#: Formats and sinks the baseline explicitly defers (Section 6.9: "Automated
#: ticket creation, CI/CD enforcement checks and generated DOCX/PDF reports are
#: post-MVP capabilities"). Named so a request for one is refused as *deferred*
#: rather than as a typo -- and so the absence is reviewable rather than
#: incidental.
DEFERRED_FORMATS = frozenset({"docx", "pdf", "xlsx", "ticket", "ci_check"})

#: Leading characters that make a spreadsheet treat a cell as a formula. The
#: first four are the usual set; ``|`` carries the DDE payload that follows an
#: ``=``; tab, carriage return and newline are included because a leading one
#: is stripped by the spreadsheet before it decides, which would hand the
#: following character the first position.
FORMULA_TRIGGERS = ("=", "+", "-", "@", "|", "\t", "\r", "\n")

#: The guard. A single quote in the first position makes a spreadsheet treat the
#: rest of the cell as text, and is stripped on display.
_GUARD = "'"

_LEADING_WHITESPACE = " \t\r\n\v\f"

#: Display escapes, applied in this order. ``&`` must be first or every entity
#: emitted after it would be broken by the pass that follows.
_DISPLAY_ESCAPES = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&quot;"),
    ("'", "&#x27;"),
    ("`", "&#x60;"),
)


def escape_display(value: str) -> str:
    """Escape a value for display in markup.

    Spec Section 8: "Escape display content". Applied to every string that came
    from adapter output before it reaches a template, so that "A content field
    cannot invoke a tool or alter policy" stays true of the rendered page too.
    """
    text = value
    for character, entity in _DISPLAY_ESCAPES:
        text = text.replace(character, entity)
    return text


def starts_a_formula(text: str) -> bool:
    """Whether a spreadsheet would read this text as a formula.

    Checked twice: against the raw first character, and against the first
    character a spreadsheet would see after it strips leading whitespace. One
    check alone leaves the other as a bypass.
    """
    if not text:
        return False
    if text[0] in FORMULA_TRIGGERS:
        return True
    stripped = text.lstrip(_LEADING_WHITESPACE)
    return bool(stripped) and stripped[0] in FORMULA_TRIGGERS


def csv_cell(value: Any) -> str:
    """Render one scalar as a guarded, quoted RFC 4180 field.

    Accepts ``None``, ``bool``, ``int``, ``float`` and ``str``. Anything else is
    a programming error rather than untrusted input -- a row reaches here only
    after ``export_findings`` has type-checked it -- so it raises.

    The formula guard applies to *text*. A typed number is not text an adapter
    chose to render, so ``-3.5`` keeps its sign instead of becoming ``'-3.5``.
    """
    if value is None:
        text = ""
    elif isinstance(value, bool):
        # Checked before int: bool is an int subclass, and "True"/"False" are
        # Python spellings rather than interchange ones.
        text = "true" if value else "false"
    elif isinstance(value, int | float):
        text = str(value)
    elif isinstance(value, str):
        text = _GUARD + value if starts_a_formula(value) else value
    else:
        raise TypeError(f"a CSV cell must be a scalar, not {type(value).__name__}")

    return '"' + text.replace('"', '""') + '"'


def csv_document(header: tuple[str, ...], rows: tuple[tuple[Any, ...], ...]) -> str:
    """Assemble a CSV document: every cell guarded, CRLF line endings.

    A row whose width differs from the header's is refused rather than padded or
    truncated. Silently padding would shift a value into the wrong column, and
    an export whose columns do not mean what the header says is worse than no
    export.
    """
    lines = [",".join(csv_cell(name) for name in header)]
    for index, row in enumerate(rows):
        if len(row) != len(header):
            raise ValueError(f"row {index} has width {len(row)}, header width is {len(header)}")
        lines.append(",".join(csv_cell(cell) for cell in row))
    return "\r\n".join(lines) + "\r\n"


def json_document(payload: Any) -> str:
    """Serialize a payload as a canonical JSON document.

    Sorted keys and fixed separators so the same data exports byte-identically
    twice -- a reviewer comparing two downloads should see a diff only where the
    data differs. ``ensure_ascii`` escapes every non-ASCII character, which also
    removes U+2028/U+2029, line terminators in JavaScript but not in JSON.
    ``allow_nan=False`` refuses non-finite floats rather than emitting the
    ``NaN`` literal, which is not valid JSON.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


# -- The export surface ------------------------------------------------------

#: Roles that may export at all. W04's dashboard is role-based; the export is
#: the same data in file form, so it carries the same role gate.
EXPORT_ROLES = frozenset({"assessor", "reviewer", "security_lead", "manager", "remediation_owner"})

#: Roles that may also receive the person fields below. U08 requires
#: minimization, so a name leaves the system only for a role whose work needs
#: it -- an assignment report for a manager, not a bulk download for anyone who
#: can open the dashboard.
PERSON_FIELD_ROLES = frozenset({"reviewer", "security_lead", "manager"})

_PERSON_FIELD_ORDER = ("assessor", "remediation_owner")

#: Fields naming a person. Held separately so their absence from a default
#: export is structural rather than something a caller has to remember.
PERSON_FIELDS = frozenset(_PERSON_FIELD_ORDER)

#: The finding export allowlist, in column order. Everything a reviewer needs
#: to reconcile an export against the system; nothing that could carry a
#: response body. ``fingerprint`` is a digest *of* the observation, never the
#: observation.
EXPORTED_FINDING_FIELDS = (
    "finding_id",
    "target_id",
    "rule",
    "state",
    "severity_score",
    "disposition",
    "fingerprint",
    "fixed_revision",
    "fixed_at",
    "reopened_count",
    "version",
)

#: The evidence view allowlist. Custody facts only: what was collected, whether
#: it was sanitized, which holds it carries, whether it has been disposed of and
#: how many times it has been accessed. The content has no column at all, and
#: the access log becomes a count rather than a list of people.
EXPORTED_EVIDENCE_FIELDS = (
    "evidence_id",
    "revision",
    "content_digest",
    "collected_at",
    "sanitized",
    "legal_hold",
    "incident_hold",
    "disposed_at",
    "access_count",
)

#: The management summary's columns. A count row leaves numerator and
#: denominator empty on purpose: a count is not a ratio, and filling those cells
#: with the closure rate's denominator would invite a reader to divide.
EXPOSURE_SUMMARY_FIELDS = (
    "measure",
    "value",
    "numerator",
    "denominator",
    "window_start",
    "window_end",
    "note",
)

MEDIA_TYPES = {"csv": "text/csv; charset=utf-8", "json": "application/json"}

#: Control characters permitted inside a cell. Tab, CR and LF are legal in a
#: quoted RFC 4180 field; every other C0 character, and DEL, is refused.
_PERMITTED_CONTROLS = ("\t", "\r", "\n")


@dataclass(frozen=True)
class ExportLimits:
    """Bounds on one export. A reviewed profile may tighten any of them."""

    #: A ceiling, not a page size. An export over it is refused rather than
    #: truncated -- a silently short download is evidence that reads as
    #: complete and is not.
    max_rows: int = 50_000
    max_cell_length: int = 4096


@dataclass(frozen=True)
class ExportRequest:
    """Who is asking, for what, in which format.

    ``organization`` is the authenticated membership the platform derived.
    ``requested_organization`` is whatever a query string or body carried: U09
    forbids trusting it, so it can only ever *match* -- it never selects. Empty
    means the request named no tenant at all, which is fine.
    """

    organization: str
    actor: str
    role: str
    format: str
    requested_at: datetime
    member_organizations: frozenset[str] = frozenset()
    requested_organization: str = ""
    include_person_fields: bool = False


@dataclass(frozen=True)
class ExportResult:
    """The decision, and the document only when it was allowed.

    ``document`` is empty on any denial. There is no path that returns the rows
    that passed -- a half-filtered export is exactly the cross-tenant leak U09's
    negative tests look for.
    """

    decision: Decision
    document: str = ""
    row_count: int = 0
    media_type: str = ""
    detail: dict[str, object] = field(default_factory=dict)


def exported_finding_fields(*, include_person_fields: bool = False) -> tuple[str, ...]:
    """The finding column order for one export."""
    if include_person_fields:
        return EXPORTED_FINDING_FIELDS + _PERSON_FIELD_ORDER
    return EXPORTED_FINDING_FIELDS


def cell_is_safe(value: Any) -> bool:
    """Whether a value may be rendered into a cell at all.

    Refuses rather than strips. Stripping would change the value a reviewer
    compares against the finding in the system, which makes the export useless
    as evidence; refusing says plainly that the value was never fit to export.
    """
    if not isinstance(value, str):
        return True
    return not any(
        (ord(character) < 0x20 and character not in _PERMITTED_CONTROLS) or ord(character) == 0x7F
        for character in value
    )


def finding_row(finding: Finding, *, include_person_fields: bool = False) -> dict[str, Any]:
    """One finding as an allowlisted export row."""
    row: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "target_id": finding.target_id,
        "rule": finding.rule,
        "state": finding.state.value,
        "severity_score": finding.severity_score,
        "disposition": finding.disposition.value if finding.disposition else None,
        "fingerprint": finding.fingerprint,
        "fixed_revision": finding.fixed_revision,
        "fixed_at": finding.fixed_at.isoformat() if finding.fixed_at else None,
        "reopened_count": finding.reopened_count,
        "version": finding.version,
    }
    if include_person_fields:
        row["assessor"] = finding.assessor
        row["remediation_owner"] = finding.remediation_owner
    return row


def evidence_row(record: EvidenceRecord) -> dict[str, Any]:
    """One evidence record as a custody row -- metadata, never content."""
    return {
        "evidence_id": record.evidence_id,
        "revision": record.revision,
        "content_digest": record.content_digest,
        "collected_at": record.collected_at.isoformat(),
        "sanitized": record.sanitized,
        "legal_hold": record.legal_hold,
        "incident_hold": record.incident_hold,
        "disposed_at": record.disposed_at.isoformat() if record.disposed_at else None,
        "access_count": len(record.access_log),
    }


def may_export(request: ExportRequest, *, limits: ExportLimits | None = None) -> Decision:
    """Whether this actor may receive this export at all.

    The format check returns immediately and separately from the rest: a caller
    who asked for PDF needs to hear that the capability is *deferred*, not that
    their role or tenant was wrong.
    """
    if request.format not in SUPPORTED_FORMATS:
        reason = (
            R.EXPORT_CAPABILITY_DEFERRED
            if request.format in DEFERRED_FORMATS
            else R.EXPORT_FORMAT_NOT_SUPPORTED
        )
        return deny(
            reason,
            requested_format=request.format,
            supported=sorted(SUPPORTED_FORMATS),
        )

    checks = [
        (request.role in EXPORT_ROLES, R.ROLE_NOT_PERMITTED),
        (
            bool(request.organization) and request.organization in request.member_organizations,
            R.MEMBERSHIP_REQUIRED,
        ),
        (
            not request.requested_organization
            or request.requested_organization == request.organization,
            R.TENANT_MISMATCH,
        ),
        (
            not request.include_person_fields or request.role in PERSON_FIELD_ROLES,
            R.PERSON_FIELDS_NOT_PERMITTED,
        ),
        (not require_aware(requested_at=request.requested_at), R.UTC_AWARE_TIME_REQUIRED),
    ]
    return evaluate(checks, actor=request.actor, role=request.role, format=request.format)


def _cell_checks(row: dict[str, Any], limits: ExportLimits) -> list[tuple[bool, str]]:
    """Type, length and content checks for one row's cells."""
    checks: list[tuple[bool, str]] = []
    for value in row.values():
        checks.append(
            (value is None or isinstance(value, bool | int | float | str), R.FIELD_TYPE_INVALID)
        )
        if isinstance(value, str):
            checks.append((len(value) <= limits.max_cell_length, R.FIELD_TOO_LONG))
            checks.append((cell_is_safe(value), R.CELL_CONTENT_UNSAFE))
    return checks


def _render(
    fields: tuple[str, ...],
    rows: tuple[dict[str, Any], ...],
    request: ExportRequest,
    *,
    extra: dict[str, Any] | None = None,
) -> str:
    """Assemble the document in the requested format."""
    if request.format == "csv":
        return csv_document(fields, tuple(tuple(row.get(name) for name in fields) for row in rows))

    payload: dict[str, Any] = {
        "organization": request.organization,
        "generated_at": request.requested_at.isoformat(),
        "fields": list(fields),
        "rows": [dict(row) for row in rows],
        "row_count": len(rows),
    }
    payload.update(extra or {})
    return json_document(payload)


def _emit(
    fields: tuple[str, ...],
    rows: tuple[dict[str, Any], ...],
    request: ExportRequest,
    limits: ExportLimits,
    scope_checks: list[tuple[bool, str]],
    *,
    extra: dict[str, Any] | None = None,
) -> ExportResult:
    """Shared tail: count, validate, then render -- or deny with no document."""
    if len(rows) > limits.max_rows:
        return ExportResult(
            deny(R.EXPORT_ROW_LIMIT_EXCEEDED, count=len(rows), ceiling=limits.max_rows)
        )

    checks = list(scope_checks)
    for row in rows:
        checks.extend(_cell_checks(row, limits))

    decision = evaluate(checks, actor=request.actor, row_count=len(rows))
    if not decision.allowed:
        return ExportResult(decision)

    return ExportResult(
        decision,
        document=_render(fields, rows, request, extra=extra),
        row_count=len(rows),
        media_type=MEDIA_TYPES[request.format],
    )


def export_findings(
    findings: tuple[Finding, ...],
    request: ExportRequest,
    *,
    limits: ExportLimits | None = None,
) -> ExportResult:
    """Export findings for one tenant, in the requested format.

    A finding belonging to another organization refuses the *whole* export
    rather than being dropped from it. Silently filtering would hide the real
    fault -- a query that reached across tenants -- behind a download that looks
    complete, and W04's acceptance evidence is that the server enforces scope,
    not that it tidies up afterwards.
    """
    limits = limits or ExportLimits()
    gate = may_export(request, limits=limits)
    if not gate.allowed:
        return ExportResult(gate)

    foreign = tuple(
        finding.finding_id for finding in findings if finding.organization != request.organization
    )
    fields = exported_finding_fields(include_person_fields=request.include_person_fields)
    rows = tuple(
        finding_row(finding, include_person_fields=request.include_person_fields)
        for finding in findings
    )
    return _emit(fields, rows, request, limits, [(not foreign, R.TENANT_MISMATCH)])


def export_evidence(
    records: tuple[EvidenceRecord, ...],
    request: ExportRequest,
    *,
    limits: ExportLimits | None = None,
) -> ExportResult:
    """Export the evidence custody view. U08's rules decide what may leave.

    Two refusals matter here. Unsanitized evidence has not been through
    minimization, so even its metadata row may name a path or parameter that
    the sanitization pass exists to remove. Quarantined secret material is
    refused outright: spec Section 7 puts it beyond logs, exports and fixtures,
    and a row pointing at it is still a pointer into the quarantine.
    """
    limits = limits or ExportLimits()
    gate = may_export(request, limits=limits)
    if not gate.allowed:
        return ExportResult(gate)

    scope_checks = [
        (
            all(record.organization == request.organization for record in records),
            R.TENANT_MISMATCH,
        ),
        (all(record.sanitized for record in records), R.EVIDENCE_NOT_SANITIZED),
        (not any(record.secret_quarantined for record in records), R.EVIDENCE_NOT_EXPORTABLE),
    ]
    rows = tuple(evidence_row(record) for record in records)
    return _emit(EXPORTED_EVIDENCE_FIELDS, rows, request, limits, scope_checks)


def _summary_row(name: str, value: Any, window: tuple[str, str], note: str = "") -> dict[str, Any]:
    """One count row of the management summary."""
    return {
        "measure": name,
        "value": value,
        "numerator": None,
        "denominator": None,
        "window_start": window[0],
        "window_end": window[1],
        "note": note,
    }


def _summary_rows(report: ExposureReport) -> tuple[dict[str, Any], ...]:
    """The management summary: the one ratio, then the counts beside it."""
    rate = report.verified_closure_rate
    window = (rate.window_start.isoformat(), rate.window_end.isoformat())
    rows: list[dict[str, Any]] = [
        {
            "measure": rate.name,
            "value": rate.display,
            "numerator": rate.numerator,
            "denominator": rate.denominator,
            "window_start": window[0],
            "window_end": window[1],
            "note": rate.note,
        },
        _summary_row(
            "unresolved_exposure",
            report.unresolved_exposure,
            window,
            "includes accepted and suppressed findings (C03)",
        ),
        _summary_row(
            "awaiting_anchor", report.awaiting_anchor, window, "not counted as closed (C01)"
        ),
        _summary_row("reopened", report.reopened, window),
        _summary_row("initial_denominator", report.initial_denominator, window),
        _summary_row("denominator_adjustments", len(report.adjustments), window),
    ]
    rows.extend(
        _summary_row(f"disposition[{name}]", count, window, "a disposition is not a verified fix")
        for name, count in sorted(report.disposition_counts.items())
    )
    return tuple(rows)


def export_exposure(
    cohort: Cohort,
    request: ExportRequest,
    *,
    adjustments: tuple[DenominatorAdjustment, ...] = (),
    filtered: dict[str, object] | None = None,
    limits: ExportLimits | None = None,
) -> ExportResult:
    """Export the management summary for a declared cohort.

    Takes the cohort rather than a finished report so the tenant check has
    something to check: an ``ExposureReport`` carries a cohort id but not an
    organization, and an export that cannot name its tenant cannot enforce it.

    A filtered view may travel alongside the totals but never instead of them.
    C03: "never present a filtered view as the overall closure rate" -- so one
    arriving without its label, or without the unchanged overall report beside
    it, is refused rather than exported as though it were the whole picture.
    """
    limits = limits or ExportLimits()
    gate = may_export(request, limits=limits)
    if not gate.allowed:
        return ExportResult(gate)

    scope_checks = [(cohort.organization == request.organization, R.TENANT_MISMATCH)]
    if filtered is not None:
        scope_checks.append(
            (bool(filtered.get("label")) and "overall" in filtered, R.FILTERED_VIEW_NOT_LABELED)
        )

    report = exposure_report(cohort, adjustments=adjustments)
    rows = _summary_rows(report)
    extra: dict[str, Any] = {"exposure": report.as_display(), "cohort": cohort.cohort_id}
    if filtered is not None:
        extra["filtered_view"] = filtered
        rate = report.verified_closure_rate
        rows = (
            *rows,
            _summary_row(
                f"filtered_view[{filtered.get('label', '')}]",
                filtered.get("filtered_count"),
                (rate.window_start.isoformat(), rate.window_end.isoformat()),
                "a filtered view is never the overall closure rate (C03)",
            ),
        )

    return _emit(EXPOSURE_SUMMARY_FIELDS, rows, request, limits, scope_checks, extra=extra)
