# Contribution Guidelines for Secure Calling

This repository includes the secure calling subsystem for SGX Guardian.
Contributions should follow the existing state machine, policy enforcement, and audit logging conventions.

## Extending the calling system

- Add new signaling types in `src/call/signaling.rs`.
- Extend call state behavior in `src/call/state.rs` and update state transition tests accordingly.
- Hook new policy decisions into `SessionManager::update_session_state` in `src/call/session.rs`.

## Testing requirements

- New behavior must include unit tests for invalid inputs and state transitions.
- End-to-end scenarios should be added under `tests/` using the existing `SessionManager` and `NebulaSignaling` abstractions.
- Performance benchmarks should be added as integration tests in `tests/bench_call_*.rs`.

## Documentation

- Add operational or security docs under `docs/` when introducing new call features.
- Keep the implementation plan in `calling_plan/IMPLEMENTATION_PLAN.md` up to date with phase completion notes.
