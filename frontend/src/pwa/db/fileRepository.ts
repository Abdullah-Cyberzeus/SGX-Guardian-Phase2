import { putRecord, readAll } from "./database";
import { stores, type FileRecord } from "./schema";
export const fileRepository = { list: () => readAll(stores.files), save: (record: FileRecord) => putRecord(stores.files, record) };
