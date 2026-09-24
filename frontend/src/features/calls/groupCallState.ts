import type { GroupMemberState, GroupSession } from "./call.types";

const TERMINAL_LOCAL_STATES = new Set<GroupMemberState>(["declined", "left", "kicked"]);

export function isTerminalLocalGroupState(state?: GroupMemberState): boolean {
  return state !== undefined && TERMINAL_LOCAL_STATES.has(state);
}

export function selectActiveGroup(
  groups: GroupSession[],
  localDeviceId: string | undefined,
  locallyClosedGroupIds: ReadonlySet<string>,
): GroupSession | undefined {
  if (!localDeviceId) return undefined;

  return groups.find((candidate) => {
    if (candidate.state === "ended" || locallyClosedGroupIds.has(candidate.group_id)) return false;
    const localParticipant = candidate.participants[localDeviceId];
    return !!localParticipant && !isTerminalLocalGroupState(localParticipant.state);
  });
}
