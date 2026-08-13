import { putRecord, readRecord } from "./database";
import { stores, type SyncStateRecord } from "./schema";
export const syncStateRepository = { get: (key: string) => readRecord(stores.syncState, key), save: (record: SyncStateRecord) => putRecord(stores.syncState, record) };
