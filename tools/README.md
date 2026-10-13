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
