# Cybersecurity Review Gate

A required CI check that runs a security-first LLM review of each PR to `main`
and blocks merge on high-confidence Critical/High findings.

## What "passing" means

Merge is gated by two tiers of check. **All required checks must be green** for
auto-merge to fire.

### Tier 1 — deterministic (the reliable gates)
Run by `CI Pipeline` (`.github/workflows/ci.yml`) and `CodeQL Analysis`:
- `cargo fmt --check`, `cargo clippy -- -D warnings`
- `cargo test`
- `cargo audit`, `cargo deny check`, Semgrep
- `cargo build --release`
- CodeQL static analysis

These are deterministic and are the backbone of "green".

> **Note:** `Build, Test & Security Checks` is temporarily **not** a required check
> because `cargo audit` is red on `main` (9 dependency advisories, see #89).
> `Static Analysis (CodeQL)` and `Cyber-review gate` are required today; add the
> build/test context back once #89 is fixed.

### Tier 2 — LLM cyber-review (this workflow)
`.github/workflows/cyber-review.yml` runs a multi-dimension review (security,
static, tests, architecture, simplification) and **ingests CodeRabbit's findings
as an additional input**. The model writes structured findings to
`.github/cyber-review/findings.json`; it does **not** decide merge-ability.

`.github/cyber-review/gate.py` applies a fixed policy:

> **Block** iff a finding has `severity ∈ {critical, high}` **and**
> `confidence ∈ {high, medium}`. Everything else is advisory.

Rationale: the LLM is non-deterministic, so only *high-confidence, high-severity*
findings gate. Medium/Low and low-confidence findings are posted as comments and
never block, keeping the gate from flaking on borderline calls.

## Break-glass override

Apply the **`security-override`** label to a PR to make the gate advisory for that
PR (it still reports what it *would* have blocked). Every use must be paired with
an ADR under `docs/decisions/` recording who/why. Intended for false positives and
genuine emergencies only.

## Fail-closed

A missing/malformed findings file fails the gate (a review that produced no
parseable output must not silently pass). Re-run the job; if infra is flaky, use
the override label with an ADR.

## Enabling / configuration

- Requires an org/repo secret **`ANTHROPIC_API_KEY`**. Until it is set, the job
  passes as *not configured* (never wedges merges) and auto-activates once added.
- Cost/latency control: the CI review runs the five dimensions in a single agent
  pass (not five subagents per push). The full 5-subagent fan-out is the local /
  on-demand `cybersecurity-code-review` flow.
- To narrow when it runs, restrict the `on.pull_request.types` (e.g. drop
  `synchronize`, or gate on a `ready-for-review` label).
