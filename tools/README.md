# tools/

Evidence-preparation scripts. **Nothing here is part of `seal.core`**, nothing here is
imported by it, and the purity boundary that `tests/test_boundary.py` enforces applies
to `src/seal/core` only — these scripts may read files, because reading fixtures off
disk is their whole job.

They are also not tests. `pytest` does not collect them and CI does not run them,
deliberately: each one reports measurements for a person to judge, and a script that
turned a judgement into a green tick would be the exact failure the decision pack's
own section 14 warns about.

## `d04_identity_probe.py`

Asks whether a scanner's own output can fill the identity tuple `identity.py`
requires, and whether that identity survives the edits L04 cares about. It is the
versioned form of the probe behind section 5 of
[`../docs/decisions/D04_scanner_adapter_selection.md`](../docs/decisions/D04_scanner_adapter_selection.md),
and the vehicle for discharging that pack's section 11 step 6.

```
python tools/d04_identity_probe.py
python tools/d04_identity_probe.py --fixtures path/to/real/output
```

**The fixtures in `fixtures/d04/` are simulated.** They are hand-written to the
documented JSON shapes of `trivy fs --scanners vuln --format json` and
`semgrep --json`; no scanner has been installed or run in this repository, and the
repository cannot run one (see [`../docs/BOUNDARY.md`](../docs/BOUNDARY.md)). The
harness says so on every run, because the numbers it prints are a design signal and
not L04 acceptance evidence.

To discharge step 6 once a scanner is authorised: drop the real JSON into a fixtures
directory, record its provenance as `real` in that directory's `MANIFEST.json` along
with the tool and database or rule versions, and run the harness against it. The
mutation sets are keyed on fields real output carries, so nothing in the harness needs
to change. Record the versions in
[`../docs/decisions/D04_pinning_record.md`](../docs/decisions/D04_pinning_record.md)
at the same time.

`MANIFEST.json` is mandatory and its `provenance` must be `simulated` or `real`. The
harness refuses to run without it — an unlabelled fixture is how a hand-written number
ends up quoted as a measurement.

## `d06_egress_probe.py`

Asks what information an egress enforcement mechanism must be able to observe, by
running the real `egress.py` decision with only what each candidate mechanism sees per
request. It is the evidence behind section 3 of
[`../docs/decisions/D06_egress_boundary.md`](../docs/decisions/D06_egress_boundary.md).

```
python tools/d06_egress_probe.py
```

Needs no fixtures: the inputs are constructed in the file, because the question is
about the decision's required inputs rather than about any tool's output. It asserts
nothing and emits no pass/fail, for the same reason as the D04 probe — it establishes
what the decision needs, not that a mechanism works, which needs a running platform
nobody has authorised.

## `d07_anchor_probe.py`

Asks what an external audit sink must be able to return, by running the real
`audit.py`, `integrity.py` and `closure.py` decisions against the receipt each
candidate sink could actually produce. It is the evidence behind sections 3 and 4 of
[`../docs/decisions/D07_audit_sink_key_custody.md`](../docs/decisions/D07_audit_sink_key_custody.md).

```
python tools/d07_anchor_probe.py
```

Needs no fixtures, for the same reason as the D06 probe, and asserts nothing. Its
section 4 prints the fields `AnchorReceipt` actually carries rather than describing
them, because the point being made is an absence — there is no key identity among
them — and an absence stated by a document is easier to doubt than one printed by the
type itself.

**It cannot demonstrate anchoring.** `AnchorReceipt.verified` is a trusted input the
decision core deliberately does not establish, and D07's own wording excludes "any
claim of external trust from a local mock". The probe establishes what a receipt must
contain for the decision to proceed; whether a real sink can produce one is §12 of
that pack, and needs a sink nobody has selected.

## `d08_evidence_probe.py`

Asks what the decision core already decides about personal data and where it has no
opinion, by running the real `EvidenceRecord.may_dispose` and `export.may_export`. It
is the evidence behind sections 3 and 4 of
[`../docs/decisions/D08_privacy_evidence_handling.md`](../docs/decisions/D08_privacy_evidence_handling.md).

```
python tools/d08_evidence_probe.py
```

Needs no fixtures and asserts nothing. Its two findings are absences rather than
failures, which is why they are printed rather than described: `may_dispose` permits
disposal one second after collection, because it has no concept of elapsed time and
the retention floors in baseline §11.1 have no enforcement point; and not one of the
eight baseline §5 role identifiers is recognised by `may_export`, which enforces a
different five.

**It is not a privacy assessment and cannot become one.** `sanitized` is a recorded
flag the core cannot verify, no real personal data exists in this repository to
inventory, and the determinations D08 needs are a named privacy reviewer's, with six
of them waiting on counsel.

## `d10_priority_probe.py`

Asks whether the candidate priority policy is operating as a proposal or as a default,
by running the real `priority.py` over every branch of the baseline Appendix D.6 tree,
every weak-signal case, and the Attend floor under override. It is the evidence behind
sections 2 to 6 of
[`../docs/decisions/D10_operations_policy.md`](../docs/decisions/D10_operations_policy.md).

```
python tools/d10_priority_probe.py
```

Needs no fixtures and asserts nothing. Its section 4 prints the six elements D10's
evidence line requires and which of them the core can express, reading the live module
rather than this description — one is expressed, four are partial and one is absent.
Its section 5 prints the three override controls that the pack first measured as gaps
and that `apply_override` now checks: a move to Triage is below the Attend floor and
needs the same approved exception as a move to Track, an override whose
`policy_version` is not the active one lapses, and an override whose recorded old
outcome is not the recomputed one does not apply.

**Each of the three encodes a policy answer the security lead may still change.** The
enforcement was added at the owner's instruction on 2026-10-18, after the pack measured
the gaps; §5 and §11 of that pack record which answer is encoded and which question
remains open, and `POLICY_VERSION` must bump if D10 answers any of them differently.

**The thresholds it prints are a proposal, not a policy.** `POLICY_VERSION` says
`seal-priority-proposal-v1` and baseline U06 says the candidate tree, threshold,
freshness limit and acknowledgement targets "remain pending D10 approval, not silent
operating defaults". If the string ever reads `approved` without §12 of that pack being
signed, the probe is the place that will show it.
