#!/usr/bin/env python3
"""File non-blocking cyber-review findings as tracked security-debt issues.

Runs AFTER gate.py has passed (the step is skipped on a blocked run), so the
findings it files reflect the state of the PR that is actually merge-eligible —
intermediate pushes that still have blocking findings never spam the tracker.

For every finding whose severity did NOT block the merge (under PRE_GA that is
high/medium/low/info), open a GitHub issue labelled `security-debt` +
`severity:<sev>` on the "Pre-release security hardening" milestone, unless an
open `security-debt` issue with the same title already exists.

Usage: file_findings.py <findings.json>
Env:   GH_TOKEN, REPO (owner/name), PR_NUMBER, PRE_GA
"""
import json
import os
import subprocess
import sys

MILESTONE = "Pre-release security hardening"
FILED_SEVERITIES = {"high", "medium", "low"}  # criticals block instead; info is noise


def gh(*args: str) -> str:
    return subprocess.run(
        ["gh", *args], check=True, capture_output=True, text=True
    ).stdout


def issue_title(f: dict) -> str:
    sev = str(f.get("severity", "?")).upper()
    return f"[cyber-review][{sev}] {f.get('title', '(untitled)')}"


def main() -> int:
    path = sys.argv[1]
    repo = os.environ["REPO"]
    pr = os.environ.get("PR_NUMBER", "?")

    try:
        with open(path, encoding="utf-8") as fh:
            findings = json.load(fh)["findings"]
    except (OSError, ValueError, KeyError) as exc:
        print(f"no parseable findings file ({exc}); nothing to file")
        return 0

    to_file = [f for f in findings if str(f.get("severity", "")).lower() in FILED_SEVERITIES]
    if not to_file:
        print("no non-blocking high/medium/low findings; nothing to file")
        return 0

    existing = {
        i["title"]
        for i in json.loads(
            gh("issue", "list", "--repo", repo, "--label", "security-debt",
               "--state", "open", "--limit", "200", "--json", "title")
        )
    }

    for f in to_file:
        title = issue_title(f)
        if title in existing:
            print(f"skip (already tracked): {title}")
            continue
        loc = f.get("file", "?")
        if f.get("line"):
            loc += f":{f['line']}"
        body = "\n".join([
            f"Auto-filed from the cyber-review gate on PR #{pr} (non-blocking under the pre-GA posture, ADR 0002).",
            "",
            f"**Location:** `{loc}`",
            f"**Severity:** {f.get('severity', '?')} · **Confidence:** {f.get('confidence', '?')} · **Category:** {f.get('category', '?')}",
            "",
            f"**Scenario:** {f.get('scenario', '—')}",
            "",
            f"**Recommendation:** {f.get('recommendation', '—')}",
        ])
        sev_label = f"severity:{str(f.get('severity', 'low')).lower()}"
        try:
            url = gh("issue", "create", "--repo", repo, "--title", title,
                     "--body", body, "--label", "security,security-debt," + sev_label,
                     "--milestone", MILESTONE).strip()
            print(f"filed: {title} -> {url}")
        except subprocess.CalledProcessError as exc:
            # Filing is best-effort bookkeeping; never fail the (already green) run.
            print(f"WARN could not file '{title}': {exc.stderr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
