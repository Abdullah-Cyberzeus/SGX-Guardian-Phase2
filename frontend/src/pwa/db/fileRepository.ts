import { putRecord, readAll, runAtomic } from "./database";
import { stores, type FileRecord } from "./schema";
export const fileRepository = {
  list: async (scopeId: string) => (await readAll(stores.files))
    .filter((record) => record.scopeId === scopeId)
    .map((record) => ({ ...record, id: record.vaultId || record.id })),
  save: (record: FileRecord) => putRecord(stores.files, {
    ...record,
    vaultId: record.vaultId || record.id,
    id: `${record.scopeId}:${record.vaultId || record.id}`,
  }),
  replaceForScope: (scopeId: string, records: FileRecord[]) => runAtomic([stores.files], (tx) => {
    const store = tx.objectStore(stores.files);
    const cursor = store.openCursor();
    cursor.onsuccess = () => {
      const current = cursor.result;
      if (!current) {
        records.forEach((record) => store.put({
          ...record,
          vaultId: record.vaultId || record.id,
          id: `${scopeId}:${record.vaultId || record.id}`,
        }));
        return;
      }
      if ((current.value as FileRecord).scopeId === scopeId) current.delete();
      current.continue();
    };
  }),
};
