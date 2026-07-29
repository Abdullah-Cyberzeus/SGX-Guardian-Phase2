# Record live CI gate measurements

- Record the first base-owned `CI Required` publication: 8s after CI Pipeline
  completion and 9s after Coverage on final PR #131 head.
- Record the old-gate race observed on PR #127, where monolithic CI failed
  7m33s after the merge workflow completed.
- Keep redesigned cyber-review and model durations marked unmeasured until the
  workflow reaches `main` and a non-fast-lane PR exercises it.
