import { deleteRecord, putRecord, readRecord } from "./database";
import { stores } from "./schema";
export const settingsRepository = {
  async get<T>(key: string): Promise<T | undefined> { return (await readRecord(stores.settings, key))?.value as T | undefined; },
  set: (key: string, value: unknown) => putRecord(stores.settings, { key, value, updatedAt: Date.now() }),
  remove: (key: string) => deleteRecord(stores.settings, key),
};
