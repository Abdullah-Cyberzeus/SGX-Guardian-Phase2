import { deleteRecord, readRecord, putRecord } from "./database";
import { decryptValue, encryptValue } from "../crypto/vault";
import { stores, type MembershipDetails } from "./schema";

const ACTIVE = "active";
export const membershipRepository = {
  async get(): Promise<MembershipDetails | undefined> {
    const record = await readRecord(stores.membership, ACTIVE);
    return record ? decryptValue<MembershipDetails>(record.payload) : undefined;
  },
  async save(details: MembershipDetails) {
    const payload = await encryptValue(details);
    return putRecord(stores.membership, { id: ACTIVE, updatedAt: Date.now(), payload });
  },
  remove: () => deleteRecord(stores.membership, ACTIVE),
};
