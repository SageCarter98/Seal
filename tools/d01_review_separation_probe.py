"""D01 probe -- what separation of duties does this repository actually evidence?

`docs/decisions/D01_appointments_and_separation.md` turns on facts about people, and
people are not in `seal.core`. D01's required evidence is "names, separation checks,
appointment scope and review period", and the only part of that a script can measure is
the separation check: who authored each change, who approved it, who merged it, how long
the review had, and whether the platform required any of it.

So this probe reads GitHub rather than the decision core. It prints one row per pull
request and then the aggregate separation counts, the branch-protection state and the
collaborator permissions. Like its D04, D06, D07, D08 and D10 counterparts it asserts
nothing and emits no pass/fail: separation of duties is a judgement about whether the
right people hold the right roles, which is the Project Authority's call.

**Three ways this probe is unlike the others.** It is not offline -- it shells out to
`gh`, so it needs the CLI installed and authenticated and it will not run in CI. It is
not deterministic -- its subject is live GitHub state, so the same command tomorrow may
print different rows. And it reports on the people reviewing this repository, so its
output names accounts; `docs/decisions/D01_appointments_and_separation.md` records which
person operates which account, because an account is not a person.

    python tools/d01_review_separation_probe.py
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime

REPO = "SageCarter98/Seal"

PR_FIELDS = (
    "number,title,state,author,createdAt,mergedAt,mergedBy,reviews,additions,deletions"
)


def gh(*args: str) -> tuple[int, str, str]:
    """Run a gh command, returning (returncode, stdout, stderr) and never raising."""
    try:
        done = subprocess.run(
            ["gh", *args], capture_output=True, text=True, timeout=120, check=False
        )
    except FileNotFoundError:
        return 127, "", "gh not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", "gh timed out"
    return done.returncode, done.stdout.strip(), done.stderr.strip()


def parse(stamp: str | None) -> datetime | None:
    if not stamp:
        return None
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def interval(start: datetime | None, end: datetime | None) -> str:
    if start is None or end is None:
        return "--"
    seconds = int((end - start).total_seconds())
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    if seconds < 90:
        return f"{sign}{seconds}s"
    if seconds < 5400:
        return f"{sign}{seconds // 60}m"
    return f"{sign}{seconds / 3600:.1f}h"


print("=" * 78)
print("0. What this probe could reach")
print("=" * 78)

code, out, err = gh("auth", "status")
if code != 0:
    print(f"   gh unavailable: {err or out}")
    print("   Nothing below can be measured. Install and authenticate the GitHub CLI,")
    print("   then re-run. This probe prints no substitute for evidence it cannot read.")
    raise SystemExit(0)
print(f"   gh auth status: ok ({REPO})")

code, out, err = gh("pr", "list", "--repo", REPO, "--state", "all", "--limit", "100",
                    "--json", PR_FIELDS)
if code != 0:
    print(f"   could not list pull requests: {err or out}")
    raise SystemExit(0)
prs = sorted(json.loads(out), key=lambda p: p["number"])
print(f"   pull requests read: {len(prs)}")
print()

print("=" * 78)
print("1. Every pull request: who wrote it, who approved it, who merged it")
print("=" * 78)
print("   Appendix E.3 D01 requires a separation check. These are its inputs.")
print()
print(f"  {'PR':>4}  {'author':14} {'approved by':14} {'merged by':14} "
      f"{'open>appr':>9} {'appr>merge':>10}  size")
print("  " + "-" * 74)

author_ne_approver = approver_ne_merger = merged_unapproved = 0
merged = 0

for pr in prs:
    author = (pr.get("author") or {}).get("login", "?")
    approvals = [r for r in pr.get("reviews") or [] if r.get("state") == "APPROVED"]
    first = min((parse(r.get("submittedAt")) for r in approvals), default=None)
    approver = approvals[0]["author"]["login"] if approvals else "(none)"
    merger = (pr.get("mergedBy") or {}).get("login", "(unmerged)")
    created, merged_at = parse(pr.get("createdAt")), parse(pr.get("mergedAt"))
    size = f"+{pr.get('additions', 0)}/-{pr.get('deletions', 0)}"
    print(f"  {pr['number']:>4}  {author:14} {approver:14} {merger:14} "
          f"{interval(created, first):>9} {interval(first, merged_at):>10}  {size}")

    if merged_at is None:
        continue
    merged += 1
    if not approvals:
        merged_unapproved += 1
        continue
    if author not in {r["author"]["login"] for r in approvals}:
        author_ne_approver += 1
    if merger not in {r["author"]["login"] for r in approvals}:
        approver_ne_merger += 1

print()
print(f"  Of {merged} merged pull requests:")
print(f"    author was not among the approvers   -> {author_ne_approver}/{merged}")
print(f"    merger was not among the approvers   -> {approver_ne_merger}/{merged}")
print(f"    merged with no approving review      -> {merged_unapproved}/{merged}")
print()
print("  The first count is the control that matters: nobody approved their own")
print("  change. The second is a different control, and a reviewer merging what")
print("  they just approved is ordinary practice rather than a finding. The")
print("  'appr>merge' column is the one to read sceptically -- it measures the gap")
print("  between the approval click and the merge click, not the time spent")
print("  reading, and a short gap neither proves nor disproves a real review.")
print()

print("=" * 78)
print("2. What the platform requires, as opposed to what practice does")
print("=" * 78)

code, out, err = gh("api", f"repos/{REPO}/branches/main/protection")
message = err or out
if code == 0:
    rules = json.loads(out)
    checks = rules.get("required_status_checks") or {}
    reviews = rules.get("required_pull_request_reviews") or {}

    def flag(section: str) -> bool:
        return bool((rules.get(section) or {}).get("enabled"))

    print("   main is PROTECTED. What it now requires:")
    print(f"     approving reviews         -> {reviews.get('required_approving_review_count', 0)}")
    print(f"     stale reviews dismissed   -> {reviews.get('dismiss_stale_reviews')}")
    print(f"     conversations resolved    -> {flag('required_conversation_resolution')}")
    print(f"     branch up to date         -> {checks.get('strict')}")
    for context in checks.get("contexts", []):
        print(f"     required check            -> {context}")
    print(f"     force pushes allowed      -> {flag('allow_force_pushes')}")
    print(f"     branch deletion allowed   -> {flag('allow_deletions')}")
    print(f"     rules bind administrators -> {flag('enforce_admins')}")
    print()
    print("   The last line is the one that decides whether any of the others mean")
    print("   anything here. Every change in section 1 was authored by the account")
    print("   that owns the repository, and an owner not bound by the rules can merge")
    print("   past all of them. It stays reversible either way: an administrator can")
    print("   lift protection, which is a recorded settings change rather than a quiet")
    print("   unreviewed merge, and that difference is the control.")
elif "Upgrade to GitHub Pro" in message:
    print("   Branch protection is UNAVAILABLE. gh reported:")
    print(f"     {message[:300]}")
    print()
    print("   Read that carefully: it is not 'protection is switched off'. Branch")
    print("   protection cannot be enabled for a private repository on this plan, so")
    print("   no setting in this repository can require the review section 1 shows")
    print("   happening. Enforcement would need GitHub Pro, a public repository, or")
    print("   an organisation-owned one -- a cost, a disclosure and an ownership")
    print("   decision respectively, none of them a checkbox.")
else:
    print("   Branch protection is AVAILABLE and NOT CONFIGURED. gh reported:")
    print(f"     {message[:300]}")
    print()
    print("   This is the state to read most carefully, because it looks like the one")
    print("   above in any summary and means the opposite. 404 says the setting exists")
    print("   and nothing is set; 403 said it could not exist. Until something is")
    print("   configured, main still accepts a direct push and an unreviewed merge --")
    print("   so the practice in section 1 is still the only control, with nothing")
    print("   now standing in the way of enforcing it. Tracker item #117 is closable")
    print("   by configuration in this state and not closed by reaching it.")
print()

print("=" * 78)
print("3. Who can act on the repository at all")
print("=" * 78)
code, out, err = gh("api", f"repos/{REPO}/collaborators")
if code != 0:
    print(f"   could not read collaborators: {err or out}")
else:
    for person in json.loads(out):
        held = sorted(k for k, v in (person.get("permissions") or {}).items() if v)
        print(f"   {person['login']:16} {', '.join(held)}")
    print()
    print("   This is a personal repository, so a collaborator's ceiling is write.")
    print("   Write is enough to review, approve and merge; it cannot change settings,")
    print("   secrets or collaborators. An account is not a person -- D01's pack")
    print("   records which person operates each of these.")
print()

print("=" * 78)
print("  Nothing above appoints anyone. A reviewer who has approved fourteen pull")
print("  requests is evidence of a practice, not an appointment with a stated scope")
print("  and review period, which is what Appendix E.3 D01 requires before Phase 0")
print("  exit. The gap between the two is the whole subject of D01's pack.")
print("=" * 78)
