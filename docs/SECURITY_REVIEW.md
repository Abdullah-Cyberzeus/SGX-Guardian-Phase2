# Security Review for Secure Calling

## Threat model summary

- Signaling is sent over the Nebula overlay network.
- Call offers and answers are cryptographically signed with the local node identity key.
- The receiver enforces local policy before transitioning a call to `Accepted`.
- The protocol assumes the Nebula overlay is the only permitted signaling plane.

## Key security properties

- Integrity: offers and answers include a signed payload.
- Authorization: call acceptance requires a policy check before the call enters the connected state.
- State machine safety: invalid transitions are rejected by `CallState::validate_transition`.
- Offline resilience: call signaling parsing and offline state handling do not depend on cloud services.

## Verified constraints

- `CallOffer::new` validates required fields and rejects empty media lists.
- `CallAnswer::accept` rejects empty accepted media.
- `SessionManager::update_session_state` runs policy enforcement before accepting a call.
- `CallState::EndCall` is terminal and no further state transitions are allowed.

## Operational implications

- Do not expose the Nebula signaling port (`50063`) to untrusted networks.
- Use audit logs to detect abnormal state transitions or repeated policy denials.
- Ensure the local key generation path is robust: corrupt key files are quarantined and regenerated.
