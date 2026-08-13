import { clearStores, deletePwaDatabase, openPwaDatabase, readAll } from "./database";
import { encryptExport } from "../crypto/vault";
import { stores, type StoreName } from "./schema";

const ALL = Object.values(stores) as StoreName[];
const NON_MEMBERSHIP = ALL.filter((name) => name !== stores.membership && name !== stores.settings);

export async function storageEstimate() {
  const estimate = await navigator.storage?.estimate?.();
  return { usage: estimate?.usage || 0, quota: estimate?.quota || 0, percent: estimate?.quota ? (estimate.usage || 0) / estimate.quota * 100 : 0 };
}

export async function verifyDatabase() {
  const db = await openPwaDatabase();
  const missing = ALL.filter((name) => !db.objectStoreNames.contains(name));
  if (missing.length) throw new Error(`Offline database is missing stores: ${missing.join(", ")}`);
  return { valid: true, version: db.version };
}

export async function clearOfflineData(preserveMembership: boolean) {
  if (!preserveMembership) return deletePwaDatabase();
  await clearStores(NON_MEMBERSHIP);
  // The service-worker shell contains code/artwork only and is deliberately
  // retained so "clear cached data" cannot make the installed app unbootable.
}

export async function exportEncryptedArchive(passphrase: string) {
  const data: Record<string, unknown[]> = {};
  for (const name of ALL) {
    // Non-extractable CryptoKey material is deliberately excluded.
    data[name] = (await readAll(name)).filter((record: any) => record?.key !== "__local_crypto_key__");
  }
  return encryptExport({ exportedAt: new Date().toISOString(), databaseVersion: 1, data }, passphrase);
}
