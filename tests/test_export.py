"""W04 + U08 -- the export surface: guarded cells, tenant scope, no raw content.

W04's acceptance evidence names four properties this module can answer for in a
pure core: "server enforces scope; CSV formula injection mitigated; downloads
sanitized; deferred capabilities absent". The fifth ("role scenarios work by
keyboard") is a rendered-interface property and has no decision to model.

Spec Section 8 supplies the escaping requirement -- "Escape display content and
guard CSV formula cells" -- and Section 7 supplies U08's: secrets are "never
exposed in logs, exports or fixtures".

What is absent from the module under test is as much the point as what is in it:
there is no DOCX writer, no PDF renderer and no ticket client, because the
baseline defers all three. ``TestDeferredCapabilitiesAbsent`` asserts that at
the source level, not just that a request for one is refused.
"""

from __future__ import annotations

import ast
import json
import pathlib
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from conftest import ORG, OTHER_ORG, TARGET

from seal.core import reasons as R
from seal.core._canonical import digest
from seal.core.audit import EvidenceRecord
from seal.core.export import (
    DEFERRED_FORMATS,
    EXPORT_ROLES,
    EXPORTED_EVIDENCE_FIELDS,
    EXPORTED_FINDING_FIELDS,
    FORMULA_TRIGGERS,
    PERSON_FIELD_ROLES,
    PERSON_FIELDS,
    SUPPORTED_FORMATS,
    ExportLimits,
    ExportRequest,
    csv_cell,
    csv_document,
    escape_display,
    evidence_row,
    export_evidence,
    export_exposure,
    export_findings,
    finding_row,
    json_document,
    may_export,
)
from seal.core.lifecycle import Cohort, Disposition, Finding, State
from seal.core.metrics import filtered_view

EXPORT_SOURCE = (
    pathlib.Path(__file__).resolve().parents[1] / "src" / "seal" / "core" / "export.py"
).read_text(encoding="utf-8")


@pytest.fixture
def export_request(now) -> ExportRequest:
    """A manager exporting CSV for the tenant they are a member of.

    ``organization`` is the authenticated membership, not a parameter the
    caller chose; ``requested_organization`` is what a query string carried and
    is left empty here so each test can set it deliberately.
    """
    return ExportRequest(
        organization=ORG,
        actor="manager.adwoa",
        role="manager",
        format="csv",
        requested_at=now,
        member_organizations=frozenset({ORG}),
    )


@pytest.fixture
def finding(now) -> Finding:
    return Finding(
        finding_id="F-2001",
        organization=ORG,
        target_id=TARGET,
        fingerprint=digest({"fp": "web-xss-login-q"}),
        rule="zap.40012",
        profile_digest=digest({"profile": "passive-web-v1"}),
        state=State.ASSIGNED,
        version=3,
        assessor="assessor.ama",
        remediation_owner="dev.yaw",
        severity_score=7.5,
        observation_watermark="obs-7",
    )


@pytest.fixture
def evidence(now) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id="EV-1",
        organization=ORG,
        revision=2,
        content_digest=digest({"evidence": "request-response-pair"}),
        collected_at=now - timedelta(hours=3),
        sanitized=True,
    )


@pytest.fixture
def cohort(now, finding) -> Cohort:
    """Three confirmed findings: one closed, one accepted, one still open.

    Denominator 3, numerator 1, unresolved exposure 2 -- the C03 shape in
    miniature, so the export tests assert against values the metrics module
    already has its own tests for.
    """
    return Cohort(
        cohort_id="cohort-2026-10",
        organization=ORG,
        declared_at=now - timedelta(days=30),
        period_start=now - timedelta(days=30),
        period_end=now,
        scope="lab web targets",
        findings=[
            replace(finding, finding_id="F-closed", state=State.CLOSED),
            replace(
                finding,
                finding_id="F-accepted",
                state=State.CONFIRMED,
                disposition=Disposition.RISK_ACCEPTED,
            ),
            replace(finding, finding_id="F-open", state=State.CONFIRMED),
        ],
    )


class TestCsvFormulaGuard:
    """ "CSV formula injection mitigated" -- W04 acceptance evidence."""

    def test_a_plain_value_is_quoted_and_otherwise_unchanged(self):
        assert csv_cell("login form") == '"login form"'

    def test_every_trigger_character_is_neutralized_by_a_prefix(self):
        for trigger in FORMULA_TRIGGERS:
            guarded = csv_cell(f"{trigger}cmd")
            assert guarded.startswith("\"'"), f"{trigger!r} left unguarded: {guarded}"

    def test_the_classic_dde_payload_cannot_start_a_formula(self):
        assert csv_cell("=cmd|' /C calc'!A0") == "\"'=cmd|' /C calc'!A0\""

    def test_leading_whitespace_does_not_smuggle_a_trigger_past_the_guard(self):
        # Spreadsheets ignore leading whitespace when deciding whether a cell is
        # a formula, so the guard must look at the first non-space character.
        assert csv_cell("   =1+1").startswith("\"'")
        assert csv_cell("\t=1+1").startswith("\"'")

    def test_a_quote_inside_a_cell_is_doubled_rather_than_closing_the_field(self):
        assert csv_cell('say "hi"') == '"say ""hi"""'

    def test_a_separator_or_newline_cannot_break_out_of_its_cell(self):
        assert csv_cell("a,b") == '"a,b"'
        assert csv_cell("a\r\nb") == '"a\r\nb"'

    def test_a_typed_number_keeps_its_sign_and_is_not_prefixed(self):
        # The guard applies to *text* that looks like a formula. A numeric field
        # is not text an adapter chose, so prefixing it would corrupt the value.
        assert csv_cell(-3.5) == '"-3.5"'
        assert csv_cell(7) == '"7"'

    def test_booleans_and_none_have_one_documented_spelling_each(self):
        assert csv_cell(True) == '"true"'
        assert csv_cell(False) == '"false"'
        assert csv_cell(None) == '""'

    def test_a_guarded_cell_never_begins_with_a_trigger_character(self):
        for value in ("=1", "+1", "-1", "@SUM(A1)", " \t-2", "|cmd"):
            body = csv_cell(value)[1:]
            assert body[0] not in FORMULA_TRIGGERS


class TestCsvDocument:
    """ "Downloads sanitized" -- a whole document, not just one cell."""

    def test_rows_are_crlf_terminated_per_rfc_4180(self):
        document = csv_document(("finding_id",), (("F-1",),))
        assert document == '"finding_id"\r\n"F-1"\r\n'

    def test_a_header_only_document_is_still_valid(self):
        assert csv_document(("a", "b"), ()) == '"a","b"\r\n'

    def test_every_row_must_have_the_header_s_width(self):
        try:
            csv_document(("a", "b"), (("only-one",),))
        except ValueError as error:
            assert "width" in str(error)
        else:  # pragma: no cover - the assertion above is the contract
            raise AssertionError("a short row must be refused, not padded")

    def test_a_hostile_cell_is_guarded_in_the_assembled_document(self):
        document = csv_document(("rule",), (('=HYPERLINK("http://x")',),))
        assert "\"'=HYPERLINK" in document
        assert document.count("\r\n") == 2


class TestDisplayEscaping:
    """ "Escape display content" -- spec Section 8."""

    def test_the_five_markup_characters_are_escaped(self):
        assert escape_display("<script>") == "&lt;script&gt;"
        assert escape_display('a"b') == "a&quot;b"
        assert escape_display("a'b") == "a&#x27;b"

    def test_an_ampersand_is_escaped_first_so_entities_are_not_double_broken(self):
        assert escape_display("&lt;") == "&amp;lt;"

    def test_a_backtick_is_escaped_because_it_opens_an_attribute_in_old_engines(self):
        assert escape_display("a`b") == "a&#x60;b"

    def test_escaping_is_idempotent_in_the_sense_that_it_never_emits_raw_markup(self):
        twice = escape_display(escape_display("<img src=x onerror=alert(1)>"))
        assert "<" not in twice and ">" not in twice


class TestJsonDocument:
    """The JSON half of "JSON/CSV export", with no ambiguity left in it."""

    def test_keys_are_sorted_so_two_runs_of_the_same_data_are_byte_identical(self):
        assert json_document({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_non_ascii_is_escaped_so_no_transport_can_reinterpret_it(self):
        # U+2028 is a line terminator in JavaScript but not in JSON, so a raw
        # one in an export could be read as a line break the document does not
        # contain. Escaping every non-ASCII character removes the whole class
        # of question.
        document = json_document({"note": "start" + chr(0x2028) + "end"})
        assert document.isascii()
        assert "\\u2028" in document

    def test_a_non_finite_number_is_refused_rather_than_emitted_as_nan(self):
        try:
            json_document({"score": float("inf")})
        except ValueError:
            pass
        else:  # pragma: no cover - the assertion above is the contract
            raise AssertionError("Infinity is not valid JSON and must be refused")

    def test_the_document_round_trips(self):
        payload = {"findings": [{"finding_id": "F-1", "severity": 7.5}]}
        assert json.loads(json_document(payload)) == payload


class TestDeferredCapabilitiesAbsent:
    """ "Deferred capabilities absent" -- W04 acceptance evidence.

    Baseline Section 6.9 defers generated DOCX/PDF reports and automated ticket
    creation. A refusal at the request boundary is necessary but not sufficient:
    the renderers must not exist at all, or a later caller could reach past the
    refusal straight to them.
    """

    def test_the_module_imports_no_office_report_or_ticket_library(self):
        tree = ast.parse(EXPORT_SOURCE, filename="export.py")
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
        deferred_libraries = {
            "docx",
            "openpyxl",
            "reportlab",
            "pdfkit",
            "weasyprint",
            "fpdf",
            "jira",
            "xlsxwriter",
        }
        assert not roots & deferred_libraries

    def test_the_module_defines_no_function_that_renders_a_deferred_format(self):
        tree = ast.parse(EXPORT_SOURCE, filename="export.py")
        names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        offenders = [
            name
            for name in names
            if any(word in name.lower() for word in ("docx", "pdf", "xlsx", "ticket", "report_to"))
        ]
        assert not offenders, f"deferred capability implemented: {offenders}"

    def test_no_deferred_format_is_also_advertised_as_supported(self):
        assert DEFERRED_FORMATS and not DEFERRED_FORMATS & SUPPORTED_FORMATS

    def test_a_request_for_a_deferred_format_is_refused_as_deferred(self, export_request):
        # The refusal has to say *deferred*, not "unsupported": a caller who
        # asked for PDF needs to know the capability is gated, not misspelled.
        decision = may_export(replace(export_request, format="pdf"))
        assert not decision
        assert decision.reason == R.EXPORT_CAPABILITY_DEFERRED

    def test_an_unrecognised_format_is_refused_as_unsupported(self, export_request):
        decision = may_export(replace(export_request, format="yaml"))
        assert not decision
        assert decision.reason == R.EXPORT_FORMAT_NOT_SUPPORTED


class TestServerEnforcesScope:
    """ "Server enforces scope" -- W04 acceptance evidence.

    U09: "Derive organization from authenticated membership; do not trust body
    or URL fields alone." So the request carries both the authenticated
    organization and the membership it came from, and a tenant named in the
    request parameters only ever has to *match* -- it can never select.
    """

    def test_a_healthy_request_is_permitted(self, export_request):
        assert may_export(export_request)

    def test_a_role_outside_the_export_roles_is_refused(self, export_request):
        decision = may_export(replace(export_request, role="intern"))
        assert not decision
        assert R.ROLE_NOT_PERMITTED in decision.reasons

    def test_an_organization_the_actor_is_not_a_member_of_is_refused(self, export_request):
        decision = may_export(replace(export_request, organization=OTHER_ORG))
        assert not decision
        assert R.MEMBERSHIP_REQUIRED in decision.reasons

    def test_a_tenant_named_in_the_request_can_match_but_never_select(self, export_request):
        assert may_export(replace(export_request, requested_organization=ORG))
        decision = may_export(replace(export_request, requested_organization=OTHER_ORG))
        assert not decision
        assert R.TENANT_MISMATCH in decision.reasons

    def test_a_naive_timestamp_is_refused_like_everywhere_else_in_the_core(self, export_request):
        decision = may_export(replace(export_request, requested_at=datetime(2026, 10, 13, 12)))
        assert not decision
        assert R.UTC_AWARE_TIME_REQUIRED in decision.reasons

    def test_person_fields_need_a_role_that_may_see_them(self, export_request):
        assert "remediation_owner" not in PERSON_FIELD_ROLES
        decision = may_export(
            replace(export_request, role="remediation_owner", include_person_fields=True)
        )
        assert not decision
        assert R.PERSON_FIELDS_NOT_PERMITTED in decision.reasons

    def test_every_person_field_role_is_itself_an_export_role(self):
        """Guards the guard: a role that may see names must be able to export."""
        assert PERSON_FIELD_ROLES <= EXPORT_ROLES


class TestTenantFilteredRows:
    """A foreign row refuses the export rather than being quietly dropped."""

    def test_rows_in_the_actor_s_own_tenant_export(self, export_request, finding):
        result = export_findings((finding,), export_request)
        assert result.decision
        assert result.row_count == 1
        assert finding.finding_id in result.document

    def test_one_foreign_row_refuses_the_whole_export(self, export_request, finding):
        foreign = replace(finding, finding_id="F-OTHER", organization=OTHER_ORG)
        result = export_findings((finding, foreign), export_request)
        assert not result.decision
        assert R.TENANT_MISMATCH in result.decision.reasons

    def test_a_denied_export_emits_no_document_and_no_partial_rows(self, export_request, finding):
        foreign = replace(finding, finding_id="F-OTHER", organization=OTHER_ORG)
        result = export_findings((finding, foreign), export_request)
        assert result.document == ""
        assert result.row_count == 0
        assert finding.finding_id not in result.document

    def test_more_rows_than_the_limit_is_refused_rather_than_truncated(
        self, export_request, finding
    ):
        findings = tuple(replace(finding, finding_id=f"F-{index}") for index in range(4))
        result = export_findings(findings, export_request, limits=ExportLimits(max_rows=3))
        assert not result.decision
        assert R.EXPORT_ROW_LIMIT_EXCEEDED in result.decision.reasons

    def test_a_request_denied_at_the_boundary_never_reaches_the_rows(self, export_request, finding):
        result = export_findings((finding,), replace(export_request, format="pdf"))
        assert not result.decision
        assert result.document == ""


class TestEvidenceMinimization:
    """U08 -- "prefer structured allowlisted metadata over raw response bodies"."""

    def test_a_finding_row_carries_exactly_the_allowlisted_fields(self, finding):
        assert tuple(finding_row(finding)) == EXPORTED_FINDING_FIELDS

    def test_no_exported_field_could_hold_raw_response_content(self, finding):
        row = finding_row(finding, include_person_fields=True)
        for name in row:
            assert not any(
                word in name for word in ("content", "body", "response", "raw", "payload")
            ), name
        # The fingerprint is the one derived value that leaves, and it is a
        # digest -- not the observation it was computed from.
        assert len(row["fingerprint"]) == 64

    def test_person_fields_are_absent_unless_asked_for(self, finding):
        row = finding_row(finding)
        assert not set(row) & PERSON_FIELDS
        named = finding_row(finding, include_person_fields=True)
        assert PERSON_FIELDS <= set(named)

    def test_an_export_by_a_permitted_role_can_carry_the_assignment(self, export_request, finding):
        result = export_findings((finding,), replace(export_request, include_person_fields=True))
        assert result.decision
        assert finding.remediation_owner in result.document


class TestFindingsDocuments:
    """The two documents W04 approves, assembled over real findings."""

    def test_the_csv_header_is_the_field_allowlist_in_order(self, export_request, finding):
        result = export_findings((finding,), export_request)
        header = result.document.split("\r\n")[0]
        assert header == ",".join(f'"{name}"' for name in EXPORTED_FINDING_FIELDS)

    def test_a_hostile_value_from_adapter_output_is_guarded_in_the_document(
        self, export_request, finding
    ):
        hostile = replace(finding, rule="=cmd|' /C calc'!A0")
        result = export_findings((hostile,), export_request)
        assert result.decision
        assert "\"'=cmd" in result.document

    def test_the_json_document_names_its_tenant_and_its_fields(self, export_request, finding):
        result = export_findings((finding,), replace(export_request, format="json"))
        payload = json.loads(result.document)
        assert payload["organization"] == ORG
        assert payload["fields"] == list(EXPORTED_FINDING_FIELDS)
        assert payload["rows"][0]["finding_id"] == finding.finding_id
        assert payload["generated_at"] == export_request.requested_at.isoformat()

    def test_each_format_declares_the_media_type_it_would_be_served_as(
        self, export_request, finding
    ):
        assert export_findings((finding,), export_request).media_type.startswith("text/csv")
        json_result = export_findings((finding,), replace(export_request, format="json"))
        assert json_result.media_type == "application/json"

    def test_a_value_longer_than_the_cell_ceiling_is_refused(self, export_request, finding):
        long_rule = replace(finding, rule="r" * 40)
        result = export_findings(
            (long_rule,), export_request, limits=ExportLimits(max_cell_length=10)
        )
        assert not result.decision
        assert R.FIELD_TOO_LONG in result.decision.reasons

    def test_a_control_character_is_refused_rather_than_stripped(self, export_request, finding):
        # Stripping would change the value a reviewer compares against the
        # finding; refusing says the value was never fit to export.
        nul = replace(finding, rule="zap" + chr(0) + "40012")
        result = export_findings((nul,), export_request)
        assert not result.decision
        assert R.CELL_CONTENT_UNSAFE in result.decision.reasons


class TestEvidenceViews:
    """U08 -- the evidence view exports custody, never content."""

    def test_an_evidence_row_carries_exactly_the_allowlisted_fields(self, evidence):
        assert tuple(evidence_row(evidence)) == EXPORTED_EVIDENCE_FIELDS

    def test_the_row_carries_the_digest_and_the_holds(self, evidence):
        row = evidence_row(replace(evidence, legal_hold=True))
        assert row["content_digest"] == evidence.content_digest
        assert row["legal_hold"] is True

    def test_the_access_history_becomes_a_count_not_a_list_of_people(self, evidence, now):
        row = evidence_row(replace(evidence, access_log=[("reviewer.kofi", now)]))
        assert row["access_count"] == 1
        assert "reviewer.kofi" not in json_document(row)

    def test_unsanitized_evidence_is_not_exportable(self, export_request, evidence):
        result = export_evidence((replace(evidence, sanitized=False),), export_request)
        assert not result.decision
        assert R.EVIDENCE_NOT_SANITIZED in result.decision.reasons

    def test_quarantined_secret_material_is_never_exportable(self, export_request, evidence):
        # Spec Section 7: quarantined secrets are exposed "never ... in logs,
        # exports or fixtures" -- including their metadata row here.
        result = export_evidence((replace(evidence, secret_quarantined=True),), export_request)
        assert not result.decision
        assert R.EVIDENCE_NOT_EXPORTABLE in result.decision.reasons

    def test_a_foreign_tenant_s_evidence_refuses_the_export(self, export_request, evidence):
        result = export_evidence((replace(evidence, organization=OTHER_ORG),), export_request)
        assert not result.decision
        assert R.TENANT_MISMATCH in result.decision.reasons

    def test_sanitized_evidence_exports(self, export_request, evidence):
        result = export_evidence((evidence,), export_request)
        assert result.decision
        assert result.row_count == 1


class TestExposureSummary:
    """C03 in export form: totals stay visible, a filtered view stays labelled."""

    def test_the_summary_carries_the_denominator_and_the_adjustment_log(
        self, export_request, cohort
    ):
        result = export_exposure(cohort, replace(export_request, format="json"))
        assert result.decision
        payload = json.loads(result.document)
        summary = payload["exposure"]
        assert summary["verified_closure_rate"]["denominator"] == 3
        assert summary["initial_denominator"] == 3
        assert summary["denominator_adjustments"] == []

    def test_a_zero_denominator_exports_as_not_available(self, export_request, cohort):
        empty = replace(cohort, findings=[])
        result = export_exposure(empty, replace(export_request, format="json"))
        payload = json.loads(result.document)
        assert payload["exposure"]["verified_closure_rate"]["value"] == "Not available"

    def test_a_filtered_view_must_carry_its_label_and_the_overall_totals(
        self, export_request, cohort
    ):
        view = filtered_view(
            cohort, include=frozenset({Disposition.RISK_ACCEPTED}), label="accepted only"
        )
        result = export_exposure(cohort, replace(export_request, format="json"), filtered=view)
        assert result.decision
        payload = json.loads(result.document)
        assert payload["filtered_view"]["label"] == "accepted only"
        assert payload["filtered_view"]["overall"]["unresolved_exposure"] == 2

    def test_an_unlabelled_filtered_view_is_refused(self, export_request, cohort):
        result = export_exposure(
            cohort,
            replace(export_request, format="json"),
            filtered={"filtered_count": 1, "overall": {}},
        )
        assert not result.decision
        assert R.FILTERED_VIEW_NOT_LABELED in result.decision.reasons

    def test_a_filtered_view_without_the_overall_totals_is_refused(self, export_request, cohort):
        result = export_exposure(
            cohort,
            replace(export_request, format="json"),
            filtered={"label": "accepted only", "filtered_count": 1},
        )
        assert not result.decision
        assert R.FILTERED_VIEW_NOT_LABELED in result.decision.reasons

    def test_a_foreign_cohort_refuses_the_summary(self, export_request, cohort):
        result = export_exposure(
            replace(cohort, organization=OTHER_ORG), replace(export_request, format="json")
        )
        assert not result.decision
        assert R.TENANT_MISMATCH in result.decision.reasons

    def test_the_csv_summary_is_one_row_per_measure(self, export_request, cohort):
        result = export_exposure(cohort, export_request)
        assert result.decision
        lines = result.document.rstrip("\r\n").split("\r\n")
        assert lines[0].startswith('"measure"')
        assert len(lines) >= 2
