import { describe, expect, it } from "vitest";
import type { NotificationPrefs } from "../../api/notifications";
import { communicationPopupEnabled, notificationEnabled } from "./NotificationContext";

function prefs(overrides: Partial<NotificationPrefs> = {}): NotificationPrefs {
  return {
    alerts: { high: true, medium: true, low: true },
    devices: { new_device: true, pending_approval: true, guardian_offline: true },
    circles: { new_message: true, incoming_call: true, member_joined: true },
    ...overrides,
  };
}

describe("notificationEnabled", () => {
  it("defaults to enabled (true) when prefs haven't loaded yet", () => {
    expect(notificationEnabled(null, "CircleNewMessage")).toBe(true);
  });

  it("maps each kind to its own preference toggle", () => {
    const p = prefs({ alerts: { high: false, medium: true, low: true } });
    expect(notificationEnabled(p, "AlertHigh")).toBe(false);
    expect(notificationEnabled(p, "AlertMedium")).toBe(true);
  });

  it("routes CircleNewMessage and CircleFileShared through the same circles.new_message toggle", () => {
    const p = prefs({ circles: { new_message: false, incoming_call: true, member_joined: true } });
    expect(notificationEnabled(p, "CircleNewMessage")).toBe(false);
    expect(notificationEnabled(p, "CircleFileShared")).toBe(false);
  });

  it("routes CircleMemberPendingApproval and CircleMemberJoined through the same member_joined toggle", () => {
    const p = prefs({ circles: { new_message: true, incoming_call: true, member_joined: false } });
    expect(notificationEnabled(p, "CircleMemberPendingApproval")).toBe(false);
    expect(notificationEnabled(p, "CircleMemberJoined")).toBe(false);
  });

  it("defaults to enabled for an unrecognized kind", () => {
    expect(notificationEnabled(prefs(), "SomeFutureKind")).toBe(true);
  });
});

describe("communicationPopupEnabled", () => {
  it("allows only the three communication event kinds to interrupt with a popup", () => {
    expect(communicationPopupEnabled("CircleNewMessage")).toBe(true);
    expect(communicationPopupEnabled("CircleFileShared")).toBe(true);
    expect(communicationPopupEnabled("CircleIncomingCall")).toBe(true);
  });

  it("blocks security/device events from popping up, even though they still record in history", () => {
    expect(communicationPopupEnabled("AlertHigh")).toBe(false);
    expect(communicationPopupEnabled("DeviceDiscovered")).toBe(false);
    expect(communicationPopupEnabled("GuardianOffline")).toBe(false);
  });
});
