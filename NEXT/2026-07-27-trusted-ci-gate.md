# Trust the required CI gate

- Move the `CI Required` decision out of pull-request-controlled code into a default-branch `pull_request_target` workflow that never executes PR content.
- Publish the required status only after the exact head SHA's `CI Pipeline` run contains one successful copy of every required job; workflow/config changes cannot skip heavy validation.
- Remove the redundant PR-local summary checkout and centralize changed-path rules shared by the build classifier and trusted gate.
