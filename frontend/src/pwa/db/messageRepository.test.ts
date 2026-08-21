import { beforeEach, describe, expect, it } from "vitest";
import { deletePwaDatabase, readRecord } from "./database";
import { messageRepository } from "./messageRepository";
import { stores } from "./schema";

beforeEach(async () => {
  await deletePwaDatabase();
});

function chatValue(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    message_id: "m1",
    sender_did: "did:guardian:alice",
    recipient_did: "did:guardian:bob",
    encrypted_payload: JSON.stringify({ content: "hello there", attachment_id: null }),
    status: "delivered",
    ...overrides,
  };
}

describe("messageRepository.save / get / list", () => {
  it("saves a message and reads it back", async () => {
    await messageRepository.save({
      id: "m1",
      conversationId: "c1",
      timestamp: 100,
      sequence: 1,
      status: "delivered",
      value: chatValue(),
    });
    const stored = await messageRepository.get("m1");
    expect(stored?.conversationId).toBe("c1");
    expect(stored?.status).toBe("delivered");
  });

  it("lists a conversation's messages ordered by sequence, then timestamp", async () => {
    await messageRepository.save({ id: "m2", conversationId: "c1", timestamp: 50, sequence: 2, status: "delivered", value: chatValue({ message_id: "m2" }) });
    await messageRepository.save({ id: "m1", conversationId: "c1", timestamp: 10, sequence: 1, status: "delivered", value: chatValue({ message_id: "m1" }) });
    await messageRepository.save({ id: "other", conversationId: "c2", timestamp: 5, sequence: 1, status: "delivered", value: chatValue({ message_id: "other" }) });

    const listed = await messageRepository.list("c1");
    expect(listed.map((m) => m.id)).toEqual(["m1", "m2"]);
  });
});

describe("messageRepository.updateStatus / markCancelled / markPermanentFailure", () => {
  it("updates the record's status without losing the encrypted payload's other fields", async () => {
    await messageRepository.save({ id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "pending_local", value: chatValue({ status: "pending_local" }) });
    await messageRepository.updateStatus("m1", "delivered");
    const stored = await messageRepository.get("m1");
    expect(stored?.status).toBe("delivered");
  });

  it("is a no-op for a message id that doesn't exist", async () => {
    await expect(messageRepository.updateStatus("missing", "delivered")).resolves.toBeUndefined();
  });

  it("does not regress a message already marked read back to an earlier delivery state (conflict priority)", async () => {
    await messageRepository.save({ id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "read", value: chatValue({ status: "read" }) });
    await messageRepository.updateStatus("m1", "delivered_to_remote_guardian");
    expect((await messageRepository.get("m1"))?.status).toBe("read");
  });

  it("does not regress a locally read message when history sync saves delivered again", async () => {
    await messageRepository.save({
      id: "m1",
      conversationId: "c1",
      timestamp: 1,
      sequence: 1,
      status: "read",
      value: chatValue({ status: "read", read_by: ["did:guardian:bob"] }),
    });
    await messageRepository.save({
      id: "m1",
      conversationId: "c1",
      timestamp: 1,
      sequence: 1,
      status: "delivered",
      value: chatValue({ status: "delivered", read_by: [] }),
    });
    expect((await messageRepository.get("m1"))?.status).toBe("read");
  });

  it("marks every incoming message in a conversation as read locally", async () => {
    await messageRepository.save({ id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "delivered", value: chatValue({ message_id: "m1" }) });
    await messageRepository.save({ id: "m2", conversationId: "c1", timestamp: 2, sequence: 2, status: "delivered", value: chatValue({ message_id: "m2" }) });
    await messageRepository.save({ id: "own", conversationId: "c1", timestamp: 3, sequence: 3, status: "delivered", value: chatValue({ message_id: "own", sender_did: "did:guardian:bob" }) });

    const changed = await messageRepository.markConversationRead("c1", "did:guardian:bob", false);

    expect(changed.sort()).toEqual(["m1", "m2"]);
    expect((await messageRepository.get("m1"))?.status).toBe("read");
    expect((await messageRepository.get("m2"))?.status).toBe("read");
    expect((await messageRepository.get("own"))?.status).toBe("delivered");
  });

  it("markCancelled sets status to cancelled", async () => {
    await messageRepository.save({ id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "pending_local", value: chatValue() });
    await messageRepository.markCancelled("m1");
    expect((await messageRepository.get("m1"))?.status).toBe("cancelled");
  });

  it("markPermanentFailure sets status to failed_permanent", async () => {
    await messageRepository.save({ id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "queued", value: chatValue() });
    await messageRepository.markPermanentFailure("m1", "TTL expired");
    expect((await messageRepository.get("m1"))?.status).toBe("failed_permanent");
  });
});

describe("messageRepository.saveAndQueue", () => {
  it("atomically writes the message and enqueues a pending operation", async () => {
    await messageRepository.saveAndQueue(
      { id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "pending_local", value: chatValue() },
      { id: "op1", kind: "chat.send", value: { recipient_did: "did:guardian:bob", content: "hello" } },
    );
    const message = await messageRepository.get("m1");
    expect(message?.conversationId).toBe("c1");
    const pending = await readRecord(stores.pending, "op1");
    expect(pending?.kind).toBe("chat.send");
    expect(pending?.state).toBe("queued");
    expect(pending?.attempts).toBe(0);
  });
});

describe("messageRepository.search", () => {
  beforeEach(async () => {
    await messageRepository.save({
      id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "delivered",
      value: chatValue({ message_id: "m1", sender_did: "did:guardian:alice", recipient_did: "did:guardian:carol", encrypted_payload: JSON.stringify({ content: "let's meet at noon" }) }),
    });
    await messageRepository.save({
      id: "m2", conversationId: "c1", timestamp: 2, sequence: 2, status: "delivered",
      value: chatValue({ message_id: "m2", sender_did: "did:guardian:bob", encrypted_payload: JSON.stringify({ content: "sounds good, see you then" }) }),
    });
  });

  it("returns the full conversation when the query is empty", async () => {
    const results = await messageRepository.search("c1", "");
    expect(results).toHaveLength(2);
  });

  it("matches on message content, case-insensitively", async () => {
    const results = await messageRepository.search("c1", "NOON");
    expect(results).toHaveLength(1);
    expect((results[0] as { message_id: string }).message_id).toBe("m1");
  });

  it("requires every search term to match (AND, not OR)", async () => {
    const results = await messageRepository.search("c1", "meet noon");
    expect(results).toHaveLength(1);
    const none = await messageRepository.search("c1", "meet frog");
    expect(none).toHaveLength(0);
  });

  it("also matches against a resolved sender display name", async () => {
    const displayNameForDid = (did: string) => (did === "did:guardian:bob" ? "Bob Guardian" : undefined);
    const results = await messageRepository.search("c1", "Bob Guardian", displayNameForDid);
    expect(results).toHaveLength(1);
    expect((results[0] as { message_id: string }).message_id).toBe("m2");
  });

  it("scopes matches to the given conversation", async () => {
    await messageRepository.save({
      id: "m3", conversationId: "c2", timestamp: 1, sequence: 1, status: "delivered",
      value: chatValue({ message_id: "m3", encrypted_payload: JSON.stringify({ content: "noon meeting too" }) }),
    });
    const results = await messageRepository.search("c1", "noon");
    expect(results).toHaveLength(1);
  });
});

describe("messageRepository.remove", () => {
  it("deletes a message", async () => {
    await messageRepository.save({ id: "m1", conversationId: "c1", timestamp: 1, sequence: 1, status: "delivered", value: chatValue() });
    await messageRepository.remove("m1");
    expect(await messageRepository.get("m1")).toBeUndefined();
  });
});
