#!/usr/bin/env python3
"""Deterministic pass/fail gate for the multi-agent cybersecurity review.

The LLM review is non-deterministic, so the *model* never decides merge-ability.
It only emits a structured findings file; THIS script applies a fixed policy.

Policy ("passing" = exit 0):
  A finding BLOCKS merge iff  severity in {critical, high}
                         AND  confidence in {high, medium}.
  Everything else (low/medium severity, or low-confidence high/critical) is
  advisory and never blocks.

Break-glass:
  If the PR carries the `security-override` label, the gate is advisory for that
  PR (exit 0) but still prints what it *would* have blocked. Use it deliberately;
  it must be paired with an ADR (see docs/decisions/).

Fail-closed:
  A missing/malformed findings file exits non-zero (a review that produced no
  parseable output must not silently pass). The override label still bypasses.

Usage: gate.py <findings.json>
Env:   HAS_OVERRIDE = "true" when the PR has the security-override label.
"""
import json
import os
import sys

BLOCKING_SEVERITY = {"critical", "high"}
BLOCKING_CONFIDENCE = {"high", "medium"}


def _summary(lines: list[str]) -> None:
    print("\n".join(lines))
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError:
            pass


def _is_blocking(f: dict) -> bool:
    return (
        str(f.get("severity", "")).lower() in BLOCKING_SEVERITY
        and str(f.get("confidence", "")).lower() in BLOCKING_CONFIDENCE
    )


def main() -> int:
    override = os.environ.get("HAS_OVERRIDE", "").lower() == "true"

    if len(sys.argv) != 2:
        _summary(["## 🛡️ Cyber-review gate", "", "❌ internal error: no findings path given"])
        return 0 if override else 1

    path = sys.argv[1]
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        findings = data["findings"] if isinstance(data, dict) else data
        assert isinstance(findings, list)
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        _summary([
            "## 🛡️ Cyber-review gate",
            "",
            f"❌ **Fail-closed:** could not read a valid findings file (`{path}`): {exc}",
            "The review did not produce parseable output. Re-run the job; if it keeps",
            "failing, apply the `security-override` label with an ADR to merge.",
        ])
        return 0 if override else 1

    blocking = [f for f in findings if _is_blocking(f)]
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    lines = [
        "## 🛡️ Cyber-review gate",
        "",
        "| severity | count |",
        "| --- | --- |",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    if blocking:
        lines.append(f"**{len(blocking)} blocking finding(s)** (severity∈{{critical,high}} ∧ confidence∈{{high,medium}}):")
        lines.append("")
        for f in blocking:
            loc = f.get("file", "?")
            if f.get("line"):
                loc += f":{f['line']}"
            lines.append(f"- **[{str(f.get('severity','?')).upper()}]** {f.get('title','(untitled)')} — `{loc}`")
        lines.append("")
        if override:
            lines.append("⚠️ `security-override` label present → gate is **advisory**; merge allowed. Ensure an ADR records this.")
            _summary(lines)
            return 0
        lines.append("❌ **Blocked.** Fix these or apply `security-override` (with an ADR) to merge.")
        _summary(lines)
        return 1

    lines.append("✅ No blocking findings. (Advisory findings, if any, are posted as review comments.)")
    _summary(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
