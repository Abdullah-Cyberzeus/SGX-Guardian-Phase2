// Conflict priority 3 from docs/Guardian_PWA_Complete_Implementation_Plan.md
// §9.2: "Server delivery/read state advances local state; local state
// cannot regress it." Until now this rule was only documented, not
// enforced anywhere — a delayed/reordered sync response could overwrite a
// message already known to be "read" back to an earlier "delivered" state.
// `messageRepository.updateStatus` calls this to gate every status write.

const PROGRESSION: Record<string, number> = {
  pending_local: 0,
  pending: 0,
  queued: 0,
  accepted_by_guardian: 1,
  delivered_to_remote_guardian: 2,
  delivered: 2,
  read: 3,
};

const TERMINAL = new Set(["cancelled", "failed_permanent", "failed", "failed_retryable"]);

/**
 * Whether `incoming` should replace `current` as a message's delivery
 * status. A terminal outcome (cancelled/failed) never regresses once set;
 * any status may transition into a terminal one; among the non-terminal
 * delivery-progression statuses, only forward or equal movement applies.
 * An unrecognized status on either side fails open (applies it) rather
 * than silently dropping a legitimate but unmapped status value.
 */
export function shouldApplyIncomingStatus(current: string, incoming: string): boolean {
  if (current === incoming) return false;
  if (TERMINAL.has(current)) return false;
  if (TERMINAL.has(incoming)) return true;

  const currentRank = PROGRESSION[current];
  const incomingRank = PROGRESSION[incoming];
  if (currentRank === undefined || incomingRank === undefined) return true;
  return incomingRank >= currentRank;
}
