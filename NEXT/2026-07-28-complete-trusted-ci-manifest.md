# Complete the trusted CI definition manifest

- Add every repository-owned shell, PowerShell, and Python script directly executed by the required CI workflow.
- Cover the Windows protoc helpers, Cargo cache contract, release contracts, and cyber-review contract tests introduced before PR #139 merged.
- Add a regression assertion that fails whenever `ci.yml` references an executable repository script missing from the manifest.
- Track the trusted-surface omission and fix in issue #147.
