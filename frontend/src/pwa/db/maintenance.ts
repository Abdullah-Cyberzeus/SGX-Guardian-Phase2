import { clearStores, deletePwaDatabase, openPwaDatabase, readAll } from "./database";
import { encryptExport } from "../crypto/vault";
import { stores, type StoreName } from "./schema";

const ALL = Object.values(stores) as StoreName[];
const NON_MEMBERSHIP = ALL.filter((name) => name !== stores.membership && name !== stores.settings);

/** Human-readable label per store, for the clear-cache/export UI. */
export const STORE_LABELS: Record<StoreName, string> = {
  [stores.membership]: "Membership",
  [stores.messages]: "Messages",
  [stores.contacts]: "Contacts",
  [stores.files]: "Files",
  [stores.calls]: "Call history",
  [stores.pending]: "Queued operations",
  [stores.settings]: "Settings",
  [stores.syncState]: "Sync state",
  [stores.notifications]: "Notifications",
};

/** Categories a user can pick from for a selective export — excludes
 * `membership` (device/session identity, not "data") and `settings` (local
 * preferences, not meaningful outside this browser). */
export const EXPORTABLE_CATEGORIES = ALL.filter(
  (name) => name !== stores.membership && name !== stores.settings,
);

export interface ClearImpact {
  perStore: Array<{ store: StoreName; label: string; count: number }>;
  total: number;
}

/** Per-store record counts for what a clear-cache action would remove, so
 * the confirm dialog can say exactly what's about to disappear. */
export async function estimateClearImpact(preserveMembership: boolean): Promise<ClearImpact> {
  const targets = preserveMembership ? NON_MEMBERSHIP : ALL;
  const perStore = await Promise.all(
    targets.map(async (store) => ({
      store,
      label: STORE_LABELS[store],
      count: (await readAll(store).catch(() => [])).length,
    })),
  );
  const nonEmpty = perStore.filter((entry) => entry.count > 0);
  return { perStore: nonEmpty, total: nonEmpty.reduce((sum, entry) => sum + entry.count, 0) };
}

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

/** `categories` selects which stores to include; omit for everything
 * exportable (membership/settings are never included — see
 * `EXPORTABLE_CATEGORIES`). */
export async function exportEncryptedArchive(passphrase: string, categories?: StoreName[]) {
  const targets = categories && categories.length ? categories : EXPORTABLE_CATEGORIES;
  const data: Record<string, unknown[]> = {};
  for (const name of targets) {
    // Non-extractable CryptoKey material is deliberately excluded.
    data[name] = (await readAll(name)).filter((record: any) => record?.key !== "__local_crypto_key__");
  }
  return encryptExport({ exportedAt: new Date().toISOString(), databaseVersion: 1, data }, passphrase);
}
