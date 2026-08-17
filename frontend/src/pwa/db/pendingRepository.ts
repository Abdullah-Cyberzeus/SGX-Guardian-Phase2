import { deleteRecord, putRecord, readAll } from "./database";
import { encryptValue } from "../crypto/vault";
import { stores, type PendingRecord } from "./schema";
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export const pendingRepository = {
  list: async () => (await readAll(stores.pending)).sort((a, b) => a.createdAt - b.createdAt),
  async enqueue(kind: string, value: unknown) {
    const now = Date.now();
    const record: PendingRecord = { id: crypto.randomUUID(), kind, createdAt: now, attempts: 0, state: "queued", expiresAt: now + DEFAULT_TTL_MS, payload: await encryptValue(value) };
    await putRecord(stores.pending, record);
    return record;
  },
  save: (record: PendingRecord) => putRecord(stores.pending, record),
  async retry(id: string) {
    const record = (await readAll(stores.pending)).find((item) => item.id === id);
    if (!record) return;
    await putRecord(stores.pending, { ...record, state: "queued", lastError: undefined });
  },
  async cancel(id: string) {
    const record = (await readAll(stores.pending)).find((item) => item.id === id);
    if (!record) return;
    await putRecord(stores.pending, { ...record, state: "cancelled", lastError: undefined });
  },
  remove: (id: string) => deleteRecord(stores.pending, id),
};
