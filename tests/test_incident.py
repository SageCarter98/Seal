"""U11 -- the incident path for an active compromise found inside approved scope.

Spec Section 8: "An active-compromise signal halts assessment and persists the
stop state, detection time, limited evidence, custody and hold. Route to the
named coordinator and target-owner contacts in the authorization. Record
acknowledgement, containment decision and legal/CERT reporting decision. **Do
not autonomously contact external parties without explicit delegated
authority.**"

Two rules here are about what Seal must *refuse* to do, and they get the most
tests:

* **No autonomous external contact.** A CERT or regulator notification may be
  prepared, never sent, unless delegated authority is recorded.
* **No invented legal duty.** Spec Section 8 carries the twenty-four-hour
  reporting clock forward as "a baseline legal-review requirement" and states
  plainly: "This proposal makes no new determination of Ghanaian law. Counsel
  must confirm applicable duties and deadlines. Pending guidance must be
  visibly owned and escalated, never silently treated as approval."

So an undetermined duty is reported as undetermined and escalated. It is never
reported as "no duty", and the clock is never presented as a deadline Seal
established.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from conftest import ORG, TARGET

from seal.core import reasons as R
from seal.core.coverage import CoverageStatus
from seal.core.incident import (
    REPORTING_CLOCK_CONSIDERATION,
    ContainmentDecision,
    DutyStatus,
    ExternalParty,
    Incident,
    IncidentSignal,
    acknowledge,
    declare,
    may_contact_external,
    notification_plan,
    record_containment,
    record_reporting_decision,
    reporting_clock,
)


@pytest.fixture
def authorization_contacts() -> tuple[str, ...]:
    """Emergency contacts as recorded on the authorization (U01)."""
    return ("owner@lab.invalid", "ops@lab.invalid")


@pytest.fixture
def incident(now, authorization_contacts) -> Incident:
    declared, _ = declare(
        signal=IncidentSignal.ACTIVE_COMPROMISE,
        incident_id="INC-1",
        organization=ORG,
        target_id=TARGET,
        job_id="job-1",
        coordinator="incident.coordinator.abena",
        target_owner_contacts=authorization_contacts,
        evidence_refs=("evidence/job-1/obs-1.json",),
        detected_at=now,
    )
    return declared


class TestDeclaration:
    def test_an_active_compromise_signal_halts_assessment(self, now, authorization_contacts):
        declared, actions = declare(
            signal=IncidentSignal.ACTIVE_COMPROMISE,
            incident_id="INC-1",
            organization=ORG,
            target_id=TARGET,
            job_id="job-1",
            coordinator="incident.coordinator.abena",
            target_owner_contacts=authorization_contacts,
            evidence_refs=(),
            detected_at=now,
        )
        assert declared.halted is True
        assert "halt_assessment" in actions

    def test_declaration_persists_the_detection_time(self, incident, now):
        assert incident.detected_at == now

    def test_declaration_places_evidence_under_incident_hold(self, incident):
        """Spec Section 8: persists "limited evidence, custody and hold"."""
        assert incident.incident_hold is True
        assert incident.evidence_refs == ("evidence/job-1/obs-1.json",)

    def test_the_hold_blocks_evidence_disposal(self, incident, now):
        """Cross-checks the U08 custody rule rather than asserting it twice."""
        from seal.core._canonical import digest
        from seal.core.audit import EvidenceRecord

        record = EvidenceRecord(
            evidence_id="ev-1",
            organization=ORG,
            revision=1,
            content_digest=digest({"e": 1}),
            collected_at=now,
            sanitized=True,
            incident_hold=incident.incident_hold,
        )
        assert R.HOLD_PREVENTS_DISPOSAL in record.may_dispose(now=now).reasons

    def test_affected_coverage_is_never_complete(self, incident):
        """An assessment halted mid-flight did not complete."""
        assert incident.coverage_status is not CoverageStatus.COMPLETE
        assert incident.coverage_status is CoverageStatus.STOPPED

    def test_a_declaration_requires_a_named_coordinator(self, now):
        """Spec Section 8 routes to "the named coordinator". Not an alias."""
        with pytest.raises(ValueError, match="named coordinator"):
            declare(
                signal=IncidentSignal.ACTIVE_COMPROMISE,
                incident_id="INC-2",
                organization=ORG,
                target_id=TARGET,
                job_id="job-1",
                coordinator="",
                target_owner_contacts=("owner@lab.invalid",),
                evidence_refs=(),
                detected_at=now,
            )

    def test_a_declaration_requires_an_aware_detection_time(self, authorization_contacts):
        from datetime import datetime

        with pytest.raises(ValueError, match="timezone-aware"):
            declare(
                signal=IncidentSignal.ACTIVE_COMPROMISE,
                incident_id="INC-3",
                organization=ORG,
                target_id=TARGET,
                job_id="job-1",
                coordinator="incident.coordinator.abena",
                target_owner_contacts=authorization_contacts,
                evidence_refs=(),
                detected_at=datetime(2026, 10, 12),
            )

    def test_a_lower_signal_still_records_but_need_not_halt(self, now, authorization_contacts):
        """Not every signal is an active compromise. Only that one forces a halt."""
        declared, actions = declare(
            signal=IncidentSignal.SUSPECTED_SECRET_EXPOSURE,
            incident_id="INC-4",
            organization=ORG,
            target_id=TARGET,
            job_id="job-1",
            coordinator="incident.coordinator.abena",
            target_owner_contacts=authorization_contacts,
            evidence_refs=(),
            detected_at=now,
        )
        assert declared.incident_hold is True
        assert "halt_assessment" not in actions


class TestNotificationRouting:
    def test_internal_routing_uses_the_recorded_contacts_only(self, incident):
        """Contacts come from the authorization. Nothing is invented or guessed."""
        plan = notification_plan(incident)
        assert plan.internal == (
            "incident.coordinator.abena",
            "owner@lab.invalid",
            "ops@lab.invalid",
        )

    def test_no_external_party_is_ever_in_the_send_list_by_default(self, incident):
        """The headline rule: no autonomous external contact."""
        plan = notification_plan(incident)
        assert plan.external_authorized == ()
        assert plan.external_prepared != ()

    def test_external_parties_are_prepared_not_sent(self, incident):
        plan = notification_plan(incident)
        for party in plan.external_prepared:
            assert isinstance(party, ExternalParty)
        assert ExternalParty.CERT in plan.external_prepared
        assert ExternalParty.REGULATOR in plan.external_prepared

    def test_recorded_delegated_authority_moves_a_party_to_authorized(self, incident):
        delegated = replace(
            incident,
            delegated_external_authority={
                ExternalParty.CERT: "legal.counsel.nii",
            },
        )
        plan = notification_plan(delegated)
        assert ExternalParty.CERT in plan.external_authorized
        # The regulator was not delegated, so it stays prepared only.
        assert ExternalParty.REGULATOR not in plan.external_authorized
        assert ExternalParty.REGULATOR in plan.external_prepared

    def test_the_plan_never_claims_anything_was_sent(self, incident):
        plan = notification_plan(incident)
        assert not hasattr(plan, "sent")
        assert "prepared" in plan.as_display()
        assert plan.as_display()["sent"] == []


class TestExternalContactAuthority:
    def test_contacting_an_external_party_without_delegation_is_refused(self, incident):
        for party in ExternalParty:
            decision = may_contact_external(incident, party)
            assert not decision.allowed
            assert R.EXTERNAL_CONTACT_NOT_DELEGATED in decision.reasons

    def test_contacting_a_delegated_party_is_permitted_and_names_the_authority(self, incident):
        delegated = replace(
            incident,
            delegated_external_authority={ExternalParty.CERT: "legal.counsel.nii"},
        )
        decision = may_contact_external(delegated, ExternalParty.CERT)
        assert decision.allowed
        assert decision.detail["authority"] == "legal.counsel.nii"

    def test_delegation_for_one_party_does_not_authorize_another(self, incident):
        delegated = replace(
            incident,
            delegated_external_authority={ExternalParty.CERT: "legal.counsel.nii"},
        )
        decision = may_contact_external(delegated, ExternalParty.REGULATOR)
        assert R.EXTERNAL_CONTACT_NOT_DELEGATED in decision.reasons

    def test_an_empty_authority_name_is_not_a_delegation(self, incident):
        """A blank field is not an authority. It is a missing one."""
        delegated = replace(incident, delegated_external_authority={ExternalParty.CERT: ""})
        decision = may_contact_external(delegated, ExternalParty.CERT)
        assert R.EXTERNAL_CONTACT_NOT_DELEGATED in decision.reasons

    def test_the_target_owner_is_not_an_external_party(self, incident):
        """The authorization's own emergency contacts are the agreed route,
        which is why they sit in the internal list and need no delegation."""
        assert "owner@lab.invalid" in notification_plan(incident).internal
        assert "owner@lab.invalid" not in [p.value for p in ExternalParty]


class TestReportingClock:
    def test_the_duty_starts_undetermined_not_absent(self, incident, now):
        """Never silently treated as approval, and never as "no duty"."""
        clock = reporting_clock(incident, now=now)
        assert clock.duty == DutyStatus.UNDETERMINED
        assert clock.duty is not DutyStatus.NO_DUTY

    def test_an_undetermined_duty_must_be_escalated(self, incident, now):
        clock = reporting_clock(incident, now=now)
        assert clock.requires_escalation is True
        assert clock.owner_required is True

    def test_the_clock_is_a_consideration_not_a_deadline_seal_established(self, incident, now):
        clock = reporting_clock(incident, now=now)
        assert clock.consideration == REPORTING_CLOCK_CONSIDERATION
        assert REPORTING_CLOCK_CONSIDERATION == timedelta(hours=24)
        display = clock.as_display()
        assert "pending counsel" in display["basis"].lower()
        assert display["deadline_established_by_seal"] is False

    def test_elapsed_time_is_reported_against_the_consideration(self, incident, now):
        clock = reporting_clock(incident, now=now + timedelta(hours=25))
        assert clock.elapsed > REPORTING_CLOCK_CONSIDERATION
        assert clock.consideration_exceeded is True

    def test_exceeding_the_consideration_does_not_assert_a_breach(self, incident, now):
        """Seal cannot say a legal deadline was missed when no duty is determined."""
        clock = reporting_clock(incident, now=now + timedelta(hours=48))
        display = clock.as_display()
        assert display["duty"] == DutyStatus.UNDETERMINED.value
        assert display["breach_asserted"] is False
        assert clock.requires_escalation is True

    def test_a_counsel_determination_of_a_duty_is_recorded_with_its_author(self, incident, now):
        determined = replace(
            incident,
            reporting_duty=DutyStatus.DUTY_CONFIRMED,
            reporting_duty_determined_by="legal.counsel.nii",
        )
        clock = reporting_clock(determined, now=now)
        assert clock.duty is DutyStatus.DUTY_CONFIRMED
        assert clock.as_display()["determined_by"] == "legal.counsel.nii"
        assert clock.requires_escalation is False

    def test_a_duty_status_without_a_named_determiner_is_not_trusted(self, incident, now):
        """A status nobody signed stays undetermined in effect."""
        unsigned = replace(
            incident,
            reporting_duty=DutyStatus.NO_DUTY,
            reporting_duty_determined_by="",
        )
        clock = reporting_clock(unsigned, now=now)
        assert clock.duty is DutyStatus.UNDETERMINED
        assert clock.requires_escalation is True

    def test_a_counsel_determination_of_no_duty_is_honoured_when_signed(self, incident, now):
        signed = replace(
            incident,
            reporting_duty=DutyStatus.NO_DUTY,
            reporting_duty_determined_by="legal.counsel.nii",
        )
        clock = reporting_clock(signed, now=now)
        assert clock.duty is DutyStatus.NO_DUTY
        assert clock.requires_escalation is False


class TestLifecycleRecords:
    def test_acknowledgement_records_who_and_when(self, incident, now):
        acknowledged, decision = acknowledge(
            incident, by="incident.coordinator.abena", at=now + timedelta(minutes=5)
        )
        assert decision.allowed
        assert acknowledged.acknowledged_by == "incident.coordinator.abena"
        assert acknowledged.acknowledged_at == now + timedelta(minutes=5)

    def test_acknowledgement_requires_a_name(self, incident, now):
        _, decision = acknowledge(incident, by="", at=now)
        assert R.DISPOSITION_REVIEWER_REQUIRED in decision.reasons

    def test_acknowledging_twice_is_refused(self, incident, now):
        once, _ = acknowledge(incident, by="coordinator", at=now)
        _, decision = acknowledge(once, by="someone.else", at=now)
        assert R.ALREADY_FINALIZED in decision.reasons

    @pytest.mark.parametrize("choice", list(ContainmentDecision))
    def test_every_containment_decision_is_recordable_with_a_reason(self, incident, now, choice):
        contained, decision = record_containment(
            incident,
            choice,
            decided_by="incident.coordinator.abena",
            reason="scoped to the lab segment",
            at=now,
        )
        assert decision.allowed
        assert contained.containment == choice
        assert contained.containment_decided_by == "incident.coordinator.abena"

    def test_containment_requires_a_decider_and_a_reason(self, incident, now):
        for by, reason in (("", "r"), ("someone", "")):
            _, decision = record_containment(
                incident,
                ContainmentDecision.ISOLATE,
                decided_by=by,
                reason=reason,
                at=now,
            )
            assert not decision.allowed

    def test_a_reporting_decision_records_the_party_and_the_authority(self, incident, now):
        delegated = replace(
            incident,
            delegated_external_authority={ExternalParty.CERT: "legal.counsel.nii"},
        )
        reported, decision = record_reporting_decision(
            delegated,
            party=ExternalParty.CERT,
            report=True,
            decided_by="legal.counsel.nii",
            at=now,
        )
        assert decision.allowed
        assert reported.reporting_decisions[ExternalParty.CERT] is True

    def test_a_reporting_decision_to_notify_without_delegation_is_refused(self, incident, now):
        """Deciding to report is not the same as being allowed to do the reporting."""
        _, decision = record_reporting_decision(
            incident,
            party=ExternalParty.CERT,
            report=True,
            decided_by="incident.coordinator.abena",
            at=now,
        )
        assert R.EXTERNAL_CONTACT_NOT_DELEGATED in decision.reasons

    def test_deciding_not_to_report_needs_no_delegation(self, incident, now):
        """Choosing to hold is always available; only contacting is gated."""
        held, decision = record_reporting_decision(
            incident,
            party=ExternalParty.CERT,
            report=False,
            decided_by="legal.counsel.nii",
            at=now,
        )
        assert decision.allowed
        assert held.reporting_decisions[ExternalParty.CERT] is False


def test_an_incident_never_exposes_raw_evidence_content(incident):
    """U08: evidence is referenced, never inlined into the incident record."""
    for value in incident.evidence_refs:
        assert isinstance(value, str)
        assert value.startswith("evidence/")
    assert not hasattr(incident, "evidence_body")
    assert not hasattr(incident, "raw_response")
