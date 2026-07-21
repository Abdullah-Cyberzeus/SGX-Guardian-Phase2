# Enforce workspace-wide Clippy checks

- Resolve the outstanding `sgx-pa-cli` warnings without broad lint exemptions.
- Run Clippy against every workspace member and target with the locked dependency graph and deny all warnings.
