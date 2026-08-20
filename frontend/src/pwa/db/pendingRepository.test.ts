import { beforeEach, describe, expect, it } from "vitest";
import { deletePwaDatabase } from "./database";
import { pendingRepository } from "./pendingRepository";

beforeEach(async () => {
  await deletePwaDatabase();
});

describe("pendingRepository.enqueue", () => {
  it("creates a queued record with zero attempts and an expiry in the future", async () => {
    const before = Date.now();
    const record = await pendingRepository.enqueue("chat.send", { recipient_did: "did:guardian:bob" });
    expect(record.state).toBe("queued");
    expect(record.attempts).toBe(0);
    expect(record.kind).toBe("chat.send");
    expect(record.expiresAt).toBeGreaterThan(before);
    expect(record.id).toBeTruthy();
  });

  it("assigns a distinct id to each enqueued operation", async () => {
    const a = await pendingRepository.enqueue("chat.send", { content: "a" });
    const b = await pendingRepository.enqueue("chat.send", { content: "b" });
    expect(a.id).not.toBe(b.id);
  });
});

describe("pendingRepository.list", () => {
  it("orders operations oldest-first", async () => {
    await pendingRepository.save({ id: "later", kind: "chat.send", createdAt: 200, attempts: 0, state: "queued", payload: { version: 1, iv: "i", ciphertext: "c" } });
    await pendingRepository.save({ id: "earlier", kind: "chat.send", createdAt: 100, attempts: 0, state: "queued", payload: { version: 1, iv: "i", ciphertext: "c" } });
    const listed = await pendingRepository.list();
    expect(listed.map((item) => item.id)).toEqual(["earlier", "later"]);
  });
});

describe("pendingRepository.retry / cancel / remove — queue state machine transitions", () => {
  it("retry moves a failed_permanent operation back to queued and clears the error", async () => {
    await pendingRepository.save({ id: "op1", kind: "chat.send", createdAt: 1, attempts: 5, state: "failed_permanent", lastError: "expired", payload: { version: 1, iv: "i", ciphertext: "c" } });
    await pendingRepository.retry("op1");
    const [record] = await pendingRepository.list();
    expect(record.state).toBe("queued");
    expect(record.lastError).toBeUndefined();
  });

  it("cancel moves a queued operation to cancelled", async () => {
    await pendingRepository.save({ id: "op1", kind: "chat.send", createdAt: 1, attempts: 0, state: "queued", payload: { version: 1, iv: "i", ciphertext: "c" } });
    await pendingRepository.cancel("op1");
    const [record] = await pendingRepository.list();
    expect(record.state).toBe("cancelled");
  });

  it("retry/cancel on a nonexistent id is a no-op, not an error", async () => {
    await expect(pendingRepository.retry("missing")).resolves.toBeUndefined();
    await expect(pendingRepository.cancel("missing")).resolves.toBeUndefined();
    expect(await pendingRepository.list()).toHaveLength(0);
  });

  it("remove deletes the operation entirely", async () => {
    await pendingRepository.save({ id: "op1", kind: "chat.send", createdAt: 1, attempts: 0, state: "queued", payload: { version: 1, iv: "i", ciphertext: "c" } });
    await pendingRepository.remove("op1");
    expect(await pendingRepository.list()).toHaveLength(0);
  });
});
