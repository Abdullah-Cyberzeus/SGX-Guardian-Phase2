# CRL Gossip API Field Reference

This note lists the exact fields returned by the two CRL gossip APIs, and highlights which fields are not currently surfaced in the frontend.

## 1. `GET /api/v1/crl/gossip/status`

Backend handler:
- `src/api/handlers/crl.rs`
- function: `gossip_status`

Backend response type:
- `GossipStatusResponse`

Exact top-level fields returned by backend:

```json
{
  "enabled": true,
  "port": 50063,
  "interval_secs": 60,
  "threshold_pct": 80,
  "self_did": "did:guardian:...",
  "circle_id": "guardian-circle-alpha",
  "other_members": 2,
  "threshold_count": 2,
  "sequence": 11,
  "merkle_root": "e8043ed9dfaee47ecdda776e4dfef30af5f78070e505bb6aa8a8aaec502e2a71",
  "entries": 4,
  "propagated": 4,
  "rounds_initiated": 12,
  "rounds_served": 9,
  "entries_merged": 3,
  "last_round": {
    "direction": "initiated",
    "peer_did": "did:guardian:...",
    "peer_node": "nodeB",
    "merged": 1,
    "sent": 0,
    "merkle_root": "e8043ed9dfaee47ecdda776e4dfef30af5f78070e505bb6aa8a8aaec502e2a71",
    "at": "2026-08-04T06:24:41.739600629+00:00"
  }
}
```

### Meaning of each field

- `enabled`: gossip engine on/off
- `port`: gossip TCP port
- `interval_secs`: automatic gossip round interval
- `threshold_pct`: propagation threshold percentage
- `self_did`: current node DID
- `circle_id`: active CRL circle
- `other_members`: active gossip peers count
- `threshold_count`: required peer acknowledgements to mark propagation complete
- `sequence`: local CRL sequence
- `merkle_root`: local CRL Merkle root
- `entries`: total CRL entries in local store
- `propagated`: total entries whose propagation threshold is satisfied
- `rounds_initiated`: outgoing gossip rounds started by this node
- `rounds_served`: incoming gossip rounds served by this node
- `entries_merged`: total entries merged via gossip
- `last_round`: last recorded gossip round summary

### Nested `last_round` fields

- `direction`: typically `initiated` or inbound-serving equivalent
- `peer_did`: peer DID used in the last round
- `peer_node`: peer node name used in the last round
- `merged`: how many records this node merged in that last round
- `sent`: how many records this node sent in that last round
- `merkle_root`: local root after that round
- `at`: timestamp of that last round

## 2. `POST /api/v1/crl/gossip/trigger`

Backend handler:
- `src/api/handlers/crl.rs`
- function: `gossip_trigger`

Backend response type:
- `GossipTriggerResponse`

Exact top-level fields returned by backend:

```json
{
  "success": true,
  "peer_did": "did:guardian:...",
  "peer_node": "nodeB",
  "merged": 1,
  "pushed": 0,
  "peer_merged": 1,
  "merkle_root": "e8043ed9dfaee47ecdda776e4dfef30af5f78070e505bb6aa8a8aaec502e2a71",
  "newly_propagated": [
    "urn:uuid:..."
  ],
  "message": "gossip round completed"
}
```

### Meaning of each field

- `success`: round completed successfully
- `peer_did`: peer DID selected for this manual round
- `peer_node`: peer node selected for this manual round
- `merged`: how many records this node merged from peer during this round
- `pushed`: how many records this node sent to peer during this round
- `peer_merged`: how many records peer reports it merged from this node
- `merkle_root`: local CRL root after this round
- `newly_propagated`: entry IDs that crossed propagation threshold in this round
- `message`: backend status text

Important:
- This trigger talks to one random active peer only.
- `pushed` is record count, not node count.
- Backend does not currently return a separate "pushed_to_n_nodes" field.

## 3. What frontend currently shows vs hides

Frontend files:
- `frontend/src/app/services/crlService.ts`
- `frontend/src/app/screens/security/CrlOperationsPanel.tsx`

Current wiring:
- `gossipStatus()` calls `GET /crl/gossip/status`
- `triggerGossip()` calls `POST /crl/gossip/trigger`

Current behavior in UI:
- The `Gossip engine` card renders only the first 8 primitive fields from the status payload.
- The trigger response is not rendered anywhere in the screen.
- After trigger, frontend only shows a success toast and then reloads status.

### Status fields currently visible in UI

These are the first 8 primitive fields from the backend payload:

- `enabled`
- `port`
- `interval_secs`
- `threshold_pct`
- `self_did`
- `circle_id`
- `other_members`
- `threshold_count`

### Status fields coming from backend but not shown in current UI

- `sequence`
- `merkle_root`
- `entries`
- `propagated`
- `rounds_initiated`
- `rounds_served`
- `entries_merged`
- `last_round`

### Trigger-response fields coming from backend but not shown in current UI

- `success`
- `peer_did`
- `peer_node`
- `merged`
- `pushed`
- `peer_merged`
- `merkle_root`
- `newly_propagated`
- `message`

## 4. Best proof fields for client demo

If the UI is being improved for client-visible proof, the most useful fields are:

### From `gossip/status`

- `self_did`
- `other_members`
- `threshold_count`
- `sequence`
- `merkle_root`
- `entries`
- `propagated`
- `rounds_initiated`
- `entries_merged`
- `last_round.peer_node`
- `last_round.merged`
- `last_round.sent`
- `last_round.at`

### From `gossip/trigger`

- `success`
- `peer_node`
- `peer_did`
- `merged`
- `pushed`
- `peer_merged`
- `merkle_root`
- `newly_propagated`
- `message`

## 5. Code references

- Backend routes: `src/api/routes.rs`
- Backend handlers: `src/api/handlers/crl.rs`
- Gossip engine counters and last-round struct: `src/crl/gossip/engine.rs`
- Frontend service calls: `frontend/src/app/services/crlService.ts`
- Frontend panel: `frontend/src/app/screens/security/CrlOperationsPanel.tsx`
