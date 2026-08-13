import { putRecord, readAll } from "./database";
import { stores, type ContactRecord } from "./schema";
export const contactRepository = { list: () => readAll(stores.contacts), save: (record: ContactRecord) => putRecord(stores.contacts, record) };
