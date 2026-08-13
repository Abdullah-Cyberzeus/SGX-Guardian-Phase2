import { putRecord, readAll } from "./database";
import { stores, type CallRecord } from "./schema";
export const callRepository = { list: async () => (await readAll(stores.calls)).sort((a, b) => b.startedAt - a.startedAt), save: (record: CallRecord) => putRecord(stores.calls, record) };
