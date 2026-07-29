# Make Windows loopback tests independent of excluded ports

- Bind DID mock registry servers to OS-assigned loopback ports instead of the fixed production port.
- Add a test-only, in-process registry port guard that resets automatically and leaves production port 50062 unchanged.
- Cover Windows hosts that reserve port 50062 in an excluded TCP range and otherwise fail before exercising the tested behavior.
- Track the compatibility failure and fix in issue #146.
