import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearStores, deletePwaDatabase, openPwaDatabase, putRecord, readAll } from "./database";
import { PWA_DB_NAME, stores } from "./schema";

beforeEach(async () => {
  await deletePwaDatabase();
});

afterEach(async () => {
  await deletePwaDatabase();
});

function openStoreNames(db: IDBDatabase): string[] {
  return Array.from(db.objectStoreNames).sort();
}

describe("openPwaDatabase", () => {
  it("creates every store from a fresh (version 0) database", async () => {
    const db = await openPwaDatabase();
    expect(openStoreNames(db)).toEqual(Object.values(stores).sort());
    db.close();
  });

  it("creates the indexes each repository relies on", async () => {
    const db = await openPwaDatabase();
    const tx = db.transaction([stores.messages, stores.calls, stores.pending, stores.notifications], "readonly");
    const messageIndexes = Array.from(tx.objectStore(stores.messages).indexNames).sort();
    expect(messageIndexes).toEqual([
      "conversation_status",
      "conversation_timestamp",
      "conversation_updated",
    ]);
    expect(Array.from(tx.objectStore(stores.calls).indexNames)).toContain("started_at");
    const pendingIndexes = Array.from(tx.objectStore(stores.pending).indexNames).sort();
    expect(pendingIndexes).toEqual(["kind_state_created", "state_created"]);
    expect(Array.from(tx.objectStore(stores.notifications).indexNames)).toContain("created_at");
    db.close();
  });

  it("clearStores empties only the named stores, leaving others untouched", async () => {
    await putRecord(stores.contacts, { did: "did:guardian:alice", displayName: "Alice", online: true, updatedAt: 1 });
    await putRecord(stores.settings, { key: "theme", value: "dark", updatedAt: 1 });
    await clearStores([stores.contacts]);
    expect(await readAll(stores.contacts)).toHaveLength(0);
    expect(await readAll(stores.settings)).toHaveLength(1);
  });

  it("reuses a single connection across calls instead of reopening", async () => {
    const first = await openPwaDatabase();
    const second = await openPwaDatabase();
    expect(second).toBe(first);
    first.close();
  });

  it("migrates a version-1 database (pre-notifications, pre-v3-indexes) up to the current schema without data loss", async () => {
    // Simulate a returning user whose IndexedDB was last written by the v1
    // schema: only the original 7 stores, none of the v2/v3 additions.
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.open(PWA_DB_NAME, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        db.createObjectStore(stores.membership, { keyPath: "id" });
        const messages = db.createObjectStore(stores.messages, { keyPath: "id" });
        messages.createIndex("conversation_timestamp", ["conversationId", "timestamp"]);
        db.createObjectStore(stores.contacts, { keyPath: "did" });
        db.createObjectStore(stores.files, { keyPath: "id" });
        db.createObjectStore(stores.calls, { keyPath: "id" }).createIndex("started_at", "startedAt");
        db.createObjectStore(stores.pending, { keyPath: "id" }).createIndex("state_created", ["state", "createdAt"]);
        db.createObjectStore(stores.settings, { keyPath: "key" });
        db.createObjectStore(stores.syncState, { keyPath: "key" });
      };
      request.onsuccess = () => {
        // Seed a pre-existing message so we can assert the upgrade doesn't
        // wipe it.
        const db = request.result;
        const tx = db.transaction(stores.messages, "readwrite");
        tx.objectStore(stores.messages).put({
          id: "m1",
          conversationId: "c1",
          timestamp: 1,
          sequence: 1,
          payload: { version: 1, iv: "iv", ciphertext: "ct" },
          status: "delivered",
        });
        tx.oncomplete = () => { db.close(); resolve(); };
        tx.onerror = () => reject(tx.error);
      };
      request.onerror = () => reject(request.error);
    });

    const db = await openPwaDatabase();
    expect(openStoreNames(db)).toEqual(Object.values(stores).sort());
    const messageIndexes = Array.from(
      db.transaction(stores.messages, "readonly").objectStore(stores.messages).indexNames,
    ).sort();
    expect(messageIndexes).toEqual(["conversation_status", "conversation_timestamp", "conversation_updated"]);

    const preserved = await new Promise((resolve, reject) => {
      const request = db.transaction(stores.messages, "readonly").objectStore(stores.messages).get("m1");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    expect(preserved).toMatchObject({ id: "m1", conversationId: "c1" });
    db.close();
  });
});
