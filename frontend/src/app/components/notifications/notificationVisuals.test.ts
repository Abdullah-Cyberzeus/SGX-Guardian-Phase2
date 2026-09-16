import { describe, expect, it } from "vitest";
import { notificationBody, notificationRoute } from "./notificationVisuals";

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
    expect(notificationRoute("security_alert", "alert/a")).toBe("/alerts/alert%2Fa");
    expect(notificationRoute("DeviceDiscovered", "device/a")).toBe("/devices/device%2Fa");
  });

  it("opens the alert source list when alert notifications do not include a ref id", () => {
    expect(notificationRoute("AlertHigh")).toBe("/alerts");
    expect(notificationRoute("SecurityAlert")).toBe("/alerts");
    expect(notificationRoute("threat_alert")).toBe("/alerts");
  });
});

describe("notificationBody", () => {
  it("uses the resolved actor display name for message notifications", () => {
    expect(notificationBody(
      "CircleNewMessage",
      "New message from 192.168.1.25",
      "did:guardian:node-b",
      (did, fallback) => did === "did:guardian:node-b" ? "Node B" : fallback || "",
    )).toBe("New message from Node B");
  });

  it("falls back to the original sender label when no friendly name exists", () => {
    expect(notificationBody(
      "CircleNewMessage",
      "New message from 192.168.1.25",
      "did:guardian:unknown",
      (_did, fallback) => fallback || "",
    )).toBe("New message from 192.168.1.25");
  });
});
