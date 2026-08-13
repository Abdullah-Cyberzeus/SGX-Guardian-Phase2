import { putRecord, readAll, runAtomic } from "./database";
import { stores, type FileRecord } from "./schema";
export const fileRepository = {
  list: () => readAll(stores.files),
  save: (record: FileRecord) => putRecord(stores.files, record),
  replaceAll: (records: FileRecord[]) => runAtomic([stores.files], (tx) => {
    const store = tx.objectStore(stores.files);
    store.clear();
    records.forEach((record) => store.put(record));
  }),
};
