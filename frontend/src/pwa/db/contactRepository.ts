import { putRecord, readAll, runAtomic } from "./database";
import { stores, type ContactRecord } from "./schema";
export const contactRepository = {
  list: () => readAll(stores.contacts),
  save: (record: ContactRecord) => putRecord(stores.contacts, record),
  replaceAll: (records: ContactRecord[]) => runAtomic([stores.contacts], (tx) => {
    const store = tx.objectStore(stores.contacts);
    store.clear();
    records.forEach((record) => store.put(record));
  }),
};
