import { putRecord, readAll, runAtomic } from "./database";
import { stores, type NotificationRecord } from "./schema";

export const notificationRepository = {
  list: async () => (await readAll(stores.notifications)).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)),
  save: (record: NotificationRecord) => putRecord(stores.notifications, record),
  replaceAll: (records: NotificationRecord[]) => runAtomic([stores.notifications], (tx) => {
    const store = tx.objectStore(stores.notifications);
    store.clear();
    records.forEach((record) => store.put(record));
  }),
};
