// Covers the remaining IndexedDB repositories that share the same
// list/save/replaceAll (or get/set) shape: contacts, files, calls,
// notifications, settings, sync state, and the encrypted membership record.
import { beforeEach, describe, expect, it } from "vitest";
import { deletePwaDatabase } from "./database";
import { contactRepository } from "./contactRepository";
import { fileRepository } from "./fileRepository";
import { callRepository } from "./callRepository";
import { notificationRepository } from "./notificationRepository";
import { settingsRepository } from "./settingsRepository";
import { syncStateRepository } from "./syncStateRepository";
import { membershipRepository } from "./membershipRepository";

beforeEach(async () => {
  await deletePwaDatabase();
});

describe("contactRepository", () => {
  it("saves and lists contacts", async () => {
    await contactRepository.save({ did: "did:guardian:alice", displayName: "Alice", online: true, updatedAt: Date.now() });
    const contacts = await contactRepository.list();
    expect(contacts).toHaveLength(1);
    expect(contacts[0].displayName).toBe("Alice");
  });

  it("replaceAll clears the store before writing the new set", async () => {
    await contactRepository.save({ did: "did:guardian:stale", displayName: "Stale", online: false, updatedAt: 1 });
    await contactRepository.replaceAll([
      { did: "did:guardian:alice", displayName: "Alice", online: true, updatedAt: 2 },
      { did: "did:guardian:bob", displayName: "Bob", online: false, updatedAt: 2 },
    ]);
    const contacts = await contactRepository.list();
    expect(contacts.map((c) => c.did).sort()).toEqual(["did:guardian:alice", "did:guardian:bob"]);
  });
});

describe("fileRepository", () => {
  it("saves and lists files", async () => {
    await fileRepository.save({ id: "f1", scopeId: "personal", name: "report.pdf", mime: "application/pdf", size: 1024, updatedAt: Date.now() });
    expect(await fileRepository.list("personal")).toHaveLength(1);
  });

  it("replaceForScope replaces one vault scope without clearing another", async () => {
    await fileRepository.save({ id: "stale", scopeId: "personal", name: "old.txt", mime: "text/plain", size: 1, updatedAt: 1 });
    await fileRepository.save({ id: "shared", scopeId: "circle:family", name: "shared.txt", mime: "text/plain", size: 3, updatedAt: 1 });
    await fileRepository.replaceForScope("personal", [
      { id: "f1", scopeId: "personal", name: "new.txt", mime: "text/plain", size: 2, updatedAt: 2 },
    ]);
    const files = await fileRepository.list("personal");
    expect(files.map((f) => f.id)).toEqual(["f1"]);
    expect((await fileRepository.list("circle:family")).map((f) => f.id)).toEqual(["shared"]);
  });
});

describe("callRepository", () => {
  it("lists calls newest-first by startedAt", async () => {
    await callRepository.save({ id: "c1", kind: "direct", direction: "outgoing", outcome: "completed", media: ["audio"], participantIds: ["did:guardian:bob"], title: "Bob", startedAt: 100, endedAt: "", durationSeconds: 30 });
    await callRepository.save({ id: "c2", kind: "direct", direction: "incoming", outcome: "completed", media: ["audio"], participantIds: ["did:guardian:carol"], title: "Carol", startedAt: 200, endedAt: "", durationSeconds: 10 });
    const calls = await callRepository.list();
    expect(calls.map((c) => c.id)).toEqual(["c2", "c1"]);
  });

  it("replaceAll removes stale call history entries", async () => {
    await callRepository.save({ id: "old", kind: "direct", direction: "incoming", outcome: "completed", media: ["audio"], participantIds: ["did:guardian:old"], title: "Old", startedAt: 100, endedAt: "", durationSeconds: 10 });
    await callRepository.replaceAll([
      { id: "new", kind: "direct", direction: "incoming", outcome: "completed", media: ["audio"], participantIds: ["did:guardian:new"], title: "New", startedAt: 200, endedAt: "", durationSeconds: 20 },
    ]);
    const calls = await callRepository.list();
    expect(calls.map((call) => call.id)).toEqual(["new"]);
  });
});

describe("notificationRepository", () => {
  it("lists notifications newest-first by createdAt", async () => {
    await notificationRepository.save({ id: "n1", kind: "message", title: "New message", body: "", severity: "info", createdAt: "2026-01-01T00:00:00Z", read: false, updatedAt: 1 });
    await notificationRepository.save({ id: "n2", kind: "message", title: "Newer message", body: "", severity: "info", createdAt: "2026-01-02T00:00:00Z", read: false, updatedAt: 2 });
    const notifications = await notificationRepository.list();
    expect(notifications.map((n) => n.id)).toEqual(["n2", "n1"]);
  });

  it("replaceAll clears the store before writing the new set", async () => {
    await notificationRepository.save({ id: "stale", kind: "message", title: "Stale", body: "", severity: "info", createdAt: "2026-01-01T00:00:00Z", read: true, updatedAt: 1 });
    await notificationRepository.replaceAll([{ id: "n1", kind: "message", title: "Fresh", body: "", severity: "info", createdAt: "2026-01-02T00:00:00Z", read: false, updatedAt: 2 }]);
    const notifications = await notificationRepository.list();
    expect(notifications.map((n) => n.id)).toEqual(["n1"]);
  });
});

describe("settingsRepository", () => {
  it("round-trips an arbitrary value by key", async () => {
    await settingsRepository.set("theme", "dark");
    expect(await settingsRepository.get<string>("theme")).toBe("dark");
  });

  it("returns undefined for a key that was never set", async () => {
    expect(await settingsRepository.get("missing")).toBeUndefined();
  });

  it("remove deletes the key", async () => {
    await settingsRepository.set("theme", "dark");
    await settingsRepository.remove("theme");
    expect(await settingsRepository.get("theme")).toBeUndefined();
  });
});

describe("syncStateRepository", () => {
  it("round-trips a per-resource sync cursor", async () => {
    await syncStateRepository.save({ key: "contacts", cursor: "abc123", sequence: 5 });
    const state = await syncStateRepository.get("contacts");
    expect(state?.cursor).toBe("abc123");
    expect(state?.sequence).toBe(5);
  });
});

describe("membershipRepository", () => {
  it("round-trips encrypted membership details", async () => {
    const details = {
      guardianDid: "did:guardian:host",
      circleIds: ["circle-1"],
      actorId: "did:guardian:member",
      role: "member",
    };
    await membershipRepository.save(details);
    const stored = await membershipRepository.get();
    expect(stored).toEqual(details);
  });

  it("returns undefined when no membership has been saved", async () => {
    expect(await membershipRepository.get()).toBeUndefined();
  });

  it("remove clears the stored membership", async () => {
    await membershipRepository.save({ guardianDid: "did:guardian:host", circleIds: [], actorId: "did:guardian:member", role: "member" });
    await membershipRepository.remove();
    expect(await membershipRepository.get()).toBeUndefined();
  });
});
