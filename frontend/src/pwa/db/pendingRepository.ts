import { deleteRecord, putRecord, readAll } from "./database";
import { encryptValue } from "../crypto/vault";
import { stores, type PendingRecord } from "./schema";
export const pendingRepository = {
  list: async () => (await readAll(stores.pending)).sort((a, b) => a.createdAt - b.createdAt),
  async enqueue(kind: string, value: unknown) { const record: PendingRecord = { id: crypto.randomUUID(), kind, createdAt: Date.now(), attempts: 0, state: "queued", payload: await encryptValue(value) }; await putRecord(stores.pending, record); return record; },
  save: (record: PendingRecord) => putRecord(stores.pending, record),
  remove: (id: string) => deleteRecord(stores.pending, id),
};
