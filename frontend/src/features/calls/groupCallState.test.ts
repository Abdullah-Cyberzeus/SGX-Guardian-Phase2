import { describe, expect, it } from "vitest";
import type { GroupMemberState, GroupSession } from "./call.types";
import { isTerminalLocalGroupState, selectActiveGroup } from "./groupCallState";

function session(
  groupId: string,
  participantState: GroupMemberState,
  state: GroupSession["state"] = "active",
): GroupSession {
  return {
    group_id: groupId,
    title: "Test call",
    host_device_id: "node-a",
    requested_media: ["audio"],
    state,
    participants: {
      "node-b": {
        device_id: "node-b",
        virtual_id: "virtual-b",
        nebula_ip: "192.168.100.2",
        role: "member",
        state: participantState,
        audio_allowed: true,
        video_allowed: true,
        media_ready: participantState === "joined",
      },
    },
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

describe("group call visibility", () => {
  it.each<GroupMemberState>(["left", "declined", "kicked"])(
    "treats %s as terminal for the local participant",
    (state) => expect(isTerminalLocalGroupState(state)).toBe(true),
  );

  it("does not restore a locally closed call from a stale active response", () => {
    expect(selectActiveGroup([session("group-1", "joined")], "node-b", new Set(["group-1"]))).toBeUndefined();
  });

  it("does not display ended calls or calls the local participant already left", () => {
    expect(selectActiveGroup([session("group-1", "joined", "ended")], "node-b", new Set())).toBeUndefined();
    expect(selectActiveGroup([session("group-2", "left")], "node-b", new Set())).toBeUndefined();
  });

  it("skips a terminal session and selects the next valid active call", () => {
    expect(selectActiveGroup(
      [session("group-1", "left"), session("group-2", "invited", "ringing")],
      "node-b",
      new Set(),
    )?.group_id).toBe("group-2");
  });
});
