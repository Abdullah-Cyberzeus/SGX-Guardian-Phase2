import { putRecord, readAll, runAtomic } from "./database";
import { stores, type CallRecord } from "./schema";

export const callRepository = {
  list: async () => (await readAll(stores.calls)).sort((a, b) => b.startedAt - a.startedAt),
  save: (record: CallRecord) => putRecord(stores.calls, record),
  replaceAll: (records: CallRecord[]) => runAtomic([stores.calls], (tx) => {
    const store = tx.objectStore(stores.calls);
    store.clear();
    records.forEach((record) => store.put(record));
  }),
};
