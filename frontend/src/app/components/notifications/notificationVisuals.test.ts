import { describe, expect, it } from "vitest";
import { notificationRoute } from "./notificationVisuals";

describe("notificationRoute", () => {
  it("does not mistake communication object IDs for Circle IDs", () => {
    expect(notificationRoute("CircleNewMessage", "message-123")).toBe("/chats");
    expect(notificationRoute("CircleIncomingCall", "call-123")).toBe("/calls");
    expect(notificationRoute("CircleFileShared", "vault-123")).toBe("/storage");
  });

  it("uses actual Circle IDs for membership notifications", () => {
    expect(notificationRoute("CircleMemberPendingApproval", "circle/a")).toBe("/network/circle%2Fa/manage");
    expect(notificationRoute("CircleMemberJoined", "circle/a")).toBe("/network/circle%2Fa?tab=members");
  });

  it("encodes alert and device references", () => {
    expect(notificationRoute("AlertHigh", "alert/a")).toBe("/alerts/alert%2Fa");
    expect(notificationRoute("DeviceDiscovered", "device/a")).toBe("/devices/device%2Fa");
  });
});
