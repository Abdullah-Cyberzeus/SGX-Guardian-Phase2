import { readAll, runAtomic } from "./database";
import { encryptValue } from "../crypto/vault";
import { stores, type MessageRecord, type PendingRecord } from "./schema";

export const messageRepository = {
  async list(conversationId: string) {
    return (await readAll(stores.messages)).filter((item) => item.conversationId === conversationId).sort((a, b) => a.sequence - b.sequence || a.timestamp - b.timestamp);
  },
  async save(record: Omit<MessageRecord, "payload"> & { value: unknown }) {
    const payload = await encryptValue(record.value);
    const { value: _plaintext, ...metadata } = record;
    return runAtomic([stores.messages], (tx) => { tx.objectStore(stores.messages).put({ ...metadata, payload }); });
  },
  async saveAndQueue(record: Omit<MessageRecord, "payload"> & { value: unknown }, operation: { id: string; kind: string; value: unknown }) {
    const [payload, pendingPayload] = await Promise.all([encryptValue(record.value), encryptValue(operation.value)]);
    const { value: _plaintext, ...metadata } = record;
    const pending: PendingRecord = { id: operation.id, kind: operation.kind, createdAt: Date.now(), attempts: 0, state: "queued", payload: pendingPayload };
    return runAtomic([stores.messages, stores.pending], (tx) => {
      tx.objectStore(stores.messages).put({ ...metadata, payload });
      tx.objectStore(stores.pending).put(pending);
    });
  },
};
