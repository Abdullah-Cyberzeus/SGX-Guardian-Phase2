import { beforeEach, describe, expect, it } from "vitest";
import { deletePwaDatabase } from "../../pwa/db/database";
import { isWithinDnd, loadLocalNotificationPrefs, saveLocalNotificationPref } from "./notificationLocalPrefs";

beforeEach(async () => {
  await deletePwaDatabase();
});

describe("loadLocalNotificationPrefs / saveLocalNotificationPref", () => {
  it("returns defaults (all on, no DND window) when nothing has been saved", async () => {
    const prefs = await loadLocalNotificationPrefs();
    expect(prefs).toEqual({ masterEnabled: true, sound: true, vibration: true, dndStart: "", dndEnd: "" });
  });

  it("round-trips a saved preference", async () => {
    await saveLocalNotificationPref(undefined, "sound", false);
    const prefs = await loadLocalNotificationPrefs();
    expect(prefs.sound).toBe(false);
    expect(prefs.masterEnabled).toBe(true); // untouched keys keep their default
  });

  it("keeps per-DID scopes independent, so an admin's toggle doesn't bleed into a member's session on the same browser", async () => {
    await saveLocalNotificationPref("did:guardian:admin", "masterEnabled", false);
    await saveLocalNotificationPref("did:guardian:member", "masterEnabled", true);

    const adminPrefs = await loadLocalNotificationPrefs("did:guardian:admin");
    const memberPrefs = await loadLocalNotificationPrefs("did:guardian:member");
    const unscopedPrefs = await loadLocalNotificationPrefs();

    expect(adminPrefs.masterEnabled).toBe(false);
    expect(memberPrefs.masterEnabled).toBe(true);
    expect(unscopedPrefs.masterEnabled).toBe(true); // default: the scoped writes never touched the unscoped key
  });
});

describe("isWithinDnd", () => {
  it("is never within DND when no window is configured", () => {
    expect(isWithinDnd({ dndStart: "", dndEnd: "" }, new Date(2026, 0, 1, 23, 0))).toBe(false);
  });

  it("matches a same-day window (e.g. 09:00-17:00)", () => {
    const prefs = { dndStart: "09:00", dndEnd: "17:00" };
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 8, 59))).toBe(false);
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 9, 0))).toBe(true);
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 12, 0))).toBe(true);
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 16, 59))).toBe(true);
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 17, 0))).toBe(false); // end is exclusive
  });

  it("matches a window that wraps past midnight (e.g. 22:00-07:00)", () => {
    const prefs = { dndStart: "22:00", dndEnd: "07:00" };
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 23, 30))).toBe(true);
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 3, 0))).toBe(true);
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 6, 59))).toBe(true);
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 7, 0))).toBe(false); // end is exclusive
    expect(isWithinDnd(prefs, new Date(2026, 0, 1, 12, 0))).toBe(false); // midday, outside the wrapped window
  });

  it("treats an equal start and end as no window at all", () => {
    expect(isWithinDnd({ dndStart: "10:00", dndEnd: "10:00" }, new Date(2026, 0, 1, 10, 0))).toBe(false);
  });
});
