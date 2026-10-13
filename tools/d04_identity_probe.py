"""D04 step 6 harness -- can a tool's own output fill Seal's identity contract?

`docs/decisions/D04_scanner_adapter_selection.md` section 5 reports identity findings
that decide a large part of the Trivy-versus-Semgrep question. Those findings were
produced by a throwaway script, which is not good enough for something a decision
rests on, so this is that probe under version control. Section 11 step 6 of the pack
is the outstanding half: replacing the simulated fixtures with real tool output.

What it does, in order:

1. Loads each fixture named in ``fixtures/d04/MANIFEST.json``, which records whether
   that file is simulated or came from a real scanner run.
2. Maps it onto the ``adapter-result-1`` schema and puts it through the real
   ``admission.admit`` -- does the trust boundary accept this tool's shape at all?
3. Fills the family's identity tuple from the tool's own fields and asks two questions
   L04 cares about: are distinct findings kept distinct, and does one finding keep its
   identity across edits that do not change it?

Nothing here asserts a pass. It prints what it found and states plainly whether the
inputs were real, because a percentage computed from hand-written fixtures is a design
signal and not acceptance evidence. The harness deliberately has no pass/fail exit
code for that reason -- L04's thresholds are judged on a seeded benchmark with real
runs, by a person.

Run it from the repository root:

    python tools/d04_identity_probe.py
    python tools/d04_identity_probe.py --fixtures path/to/real/output
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from seal.core.admission import ExpectedBinding, admit  # noqa: E402
from seal.core.identity import Family, fingerprint  # noqa: E402

DEFAULT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "d04"

#: A binding the orchestrator would have recorded. Admission compares the result
#: against this rather than trusting the payload's own tenant claims (U09).
BINDING = ExpectedBinding(
    organization="org-1",
    target_id="tgt-1",
    job_id="job-1",
    authorization_revision=7,
    profile_digest="sha256:profile",
)


def envelope(observations: list[dict[str, Any]]) -> str:
    """Wrap observations in a result envelope that matches ``BINDING``."""
    return json.dumps(
        {
            "schema_version": "adapter-result-1",
            "organization": BINDING.organization,
            "target_id": BINDING.target_id,
            "job_id": BINDING.job_id,
            "authorization_revision": BINDING.authorization_revision,
            "profile_digest": BINDING.profile_digest,
            "status": "complete",
            "truncated": False,
            "sanitized": True,
            "observations": observations,
        }
    )


# --------------------------------------------------------------------------- trivy


def trivy_findings(output: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Every (vulnerability, enclosing result) pair in a Trivy document."""
    pairs = []
    for result in output.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            pairs.append((vulnerability, result))
    return pairs


def trivy_identity(finding: tuple[dict[str, Any], dict[str, Any]]) -> dict[str, str]:
    """The dependency identity tuple, taken entirely from Trivy's own fields.

    ``Type`` is the ecosystem (``npm``, ``pip``, ``gomod`` ...), ``PkgName`` the
    package and ``VulnerabilityID`` the advisory. Nothing is derived or guessed,
    which is the finding section 5.2 of the pack turns on.
    """
    vulnerability, result = finding
    return {
        "ecosystem": str(result.get("Type", "")),
        "package": str(vulnerability.get("PkgName", "")),
        "vulnerability": str(vulnerability.get("VulnerabilityID", "")),
    }


#: Changes that occur between two scans of the *same* real finding. Identity must
#: survive all of them, or a fix cannot be proved against the finding it fixed (W03).
TRIVY_MUTATIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "installed version changes": lambda v: {**v, "InstalledVersion": "0.0.0-mutated"},
    "a fix becomes available": lambda v: {**v, "FixedVersion": "99.99.99"},
    "severity re-rated": lambda v: {**v, "Severity": "CRITICAL"},
    "CVSS rescored": lambda v: {**v, "CVSS": {"nvd": {"V3Score": 9.9}}},
    "image layer digest changes": lambda v: {**v, "Layer": {"Digest": "sha256:mutated"}},
    "package path moves": lambda v: {**v, "PkgPath": "mutated/path/package.json"},
    "advisory DB refreshed": lambda v: {**v, "DataSource": {"ID": "ghsa", "Name": "mutated"}},
}


# ------------------------------------------------------------------------- semgrep

#: The candidate derivations for ``structural_context``, which Semgrep's JSON does
#: not supply. Each is tested rather than argued about.
SEMGREP_CONTEXTS: dict[str, Callable[[dict[str, Any]], str]] = {
    "path": lambda r: str(r.get("path", "")),
    "path:line": lambda r: "{}:{}".format(r.get("path", ""), (r.get("start") or {}).get("line")),
    "semgrep fingerprint": lambda r: str((r.get("extra") or {}).get("fingerprint", "")),
}

SEMGREP_MUTATIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "blank line added above": lambda r: {
        **r,
        "start": {**(r.get("start") or {}), "line": ((r.get("start") or {}).get("line") or 0) + 1},
    },
    "unrelated edit earlier in file": lambda r: {
        **r,
        "start": {**(r.get("start") or {}), "line": ((r.get("start") or {}).get("line") or 0) + 40},
    },
    "local variable renamed": lambda r: {
        **r,
        "extra": {**(r.get("extra") or {}), "fingerprint": "mutated-rename"},
    },
    "file reformatted": lambda r: {
        **r,
        "start": {**(r.get("start") or {}), "col": ((r.get("start") or {}).get("col") or 0) + 4},
    },
    "semgrep upgraded, fingerprint scheme changes": lambda r: {
        **r,
        "extra": {**(r.get("extra") or {}), "fingerprint": "mutated-scheme"},
    },
    "file moved to another directory": lambda r: {**r, "path": "moved/" + str(r.get("path", ""))},
}


def semgrep_identity(result: dict[str, Any], context: str) -> dict[str, str]:
    """A source identity tuple, with ``structural_context`` from one candidate."""
    return {
        "rule": str(result.get("check_id", "")),
        "repository": "repo-1",
        "structural_context": SEMGREP_CONTEXTS[context](result),
    }


# -------------------------------------------------------------------------- report


def load_manifest(fixtures: Path) -> dict[str, dict[str, Any]]:
    manifest_path = fixtures / "MANIFEST.json"
    if not manifest_path.is_file():
        raise SystemExit(
            f"no MANIFEST.json in {fixtures}. Every fixture must declare its provenance "
            "('simulated' or 'real'), because a number from a hand-written fixture is "
            "not acceptance evidence and must never be reported as if it were."
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, entry in manifest.items():
        if entry.get("provenance") not in ("simulated", "real"):
            raise SystemExit(f"fixture {name}: provenance must be 'simulated' or 'real'")
    return manifest


def fp(family: Family, identity: dict[str, str]) -> str:
    return fingerprint(
        organization=BINDING.organization,
        target_id=BINDING.target_id,
        family=family,
        **identity,
    )


def check_admission(family: str, identity: dict[str, str]) -> str:
    observation = {
        "observation_id": "probe-1",
        "family": family,
        "identity": identity,
        "confidence": "High",
        "evidence_refs": ["ev/probe/1"],
    }
    decision = admit(envelope([observation]), BINDING).decision
    return "ADMITTED" if decision.allowed else f"DENIED {decision.reasons}"


def report_trivy(output: dict[str, Any]) -> None:
    findings = trivy_findings(output)
    print(f"  findings in fixture: {len(findings)}")
    if not findings:
        print("  nothing to probe")
        return

    identities = [trivy_identity(f) for f in findings]
    missing = [i for i in identities if not all(i.values())]
    print(
        f"  identity fields present in tool output: {len(identities) - len(missing)}"
        f"/{len(identities)} findings complete"
    )
    for identity in missing:
        print(f"    INCOMPLETE: {identity}")

    print(f"  admission: {check_admission('dependency', identities[0])}")

    distinct_findings = len({tuple(sorted(i.items())) for i in identities})
    print(
        f"  distinct identities for {len(identities)} findings: {distinct_findings}"
        f"{'  *** COLLISION' if distinct_findings < len(identities) else ''}"
    )

    vulnerability, result = findings[0]
    base = fp(Family.DEPENDENCY, trivy_identity(findings[0]))
    kept = 0
    for label, mutate in TRIVY_MUTATIONS.items():
        same = fp(Family.DEPENDENCY, trivy_identity((mutate(vulnerability), result))) == base
        kept += same
        print(f"    {'KEPT ' if same else 'LOST '} {label}")
    print(f"  mutations retaining identity: {kept}/{len(TRIVY_MUTATIONS)}")


def report_semgrep(output: dict[str, Any]) -> None:
    results = output.get("results") or []
    print(f"  findings in fixture: {len(results)}")
    if not results:
        print("  nothing to probe")
        return

    print("  NOTE: Semgrep's output supplies no structural_context field. Each candidate")
    print("        derivation below is Seal's invention, which is the point of the test.")
    print(f"  admission: {check_admission('source', semgrep_identity(results[0], 'path'))}")

    for context in SEMGREP_CONTEXTS:
        identities = [semgrep_identity(r, context) for r in results]
        if any(not all(i.values()) for i in identities):
            print(f"    [{context}] INCOMPLETE identity -- candidate unusable on this fixture")
            continue

        distinct = len({tuple(sorted(i.items())) for i in identities})
        base = fp(Family.SOURCE, identities[0])
        kept, lost = 0, []
        for label, mutate in SEMGREP_MUTATIONS.items():
            if fp(Family.SOURCE, semgrep_identity(mutate(results[0]), context)) == base:
                kept += 1
            else:
                lost.append(label)
        merged = f"  *** MERGES ({distinct} of {len(results)})"
        collision = "" if distinct == len(results) else merged
        print(f"    [{context}] mutations retained {kept}/{len(SEMGREP_MUTATIONS)}{collision}")
        for label in lost:
            print(f"        LOST: {label}")


REPORTERS = {"trivy": report_trivy, "semgrep": report_semgrep}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=DEFAULT_FIXTURES,
        help="directory holding tool output plus a MANIFEST.json declaring provenance",
    )
    arguments = parser.parse_args()

    manifest = load_manifest(arguments.fixtures)
    simulated = [name for name, entry in manifest.items() if entry["provenance"] == "simulated"]

    print("=" * 78)
    print("D04 identity probe -- decision pack section 5, section 11 step 6")
    print("=" * 78)
    if simulated:
        print("PROVENANCE: SIMULATED fixtures present:", ", ".join(sorted(simulated)))
        print("These numbers are a DESIGN SIGNAL, not L04 acceptance evidence. L04's >=95%")
        print("is judged on the seeded benchmark with real tool runs (step 6 outstanding).")
    else:
        print("PROVENANCE: all fixtures declared 'real'. Record the tool and database or")
        print("rule versions in docs/decisions/D04_pinning_record.md alongside this run.")

    for name in sorted(manifest):
        entry = manifest[name]
        path = arguments.fixtures / name
        print()
        print("-" * 78)
        print(f"{name}  [tool={entry['tool']}  provenance={entry['provenance']}]")
        if entry.get("note"):
            print(f"  note: {entry['note']}")
        print("-" * 78)
        if not path.is_file():
            print("  MISSING FILE")
            continue
        reporter = REPORTERS.get(entry["tool"])
        if reporter is None:
            print(f"  no reporter for tool '{entry['tool']}'")
            continue
        reporter(json.loads(path.read_text(encoding="utf-8")))

    print()
    print("No pass/fail is emitted. L04's thresholds are judged by a person, on real runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
