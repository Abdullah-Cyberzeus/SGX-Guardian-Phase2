import api from "../app/services/api";
import { deletePwaDatabase } from "./db/database";

const MONITORING_DB_NAME = "cervais_monitor";
const KNOWN_INDEXED_DBS = ["sgx-guardian-pwa"];

export function guardianOrigin() {
  try {
    return new URL(api.publicUrl("/health")).origin;
  } catch {
    return window.location.origin;
  }
}

export async function purgeOfflineShell() {
  if ("caches" in window) {
    const keys = await caches.keys().catch(() => []);
    await Promise.all(keys.map((key) => caches.delete(key)));
  }
  if ("serviceWorker" in navigator) {
    const registrations = await navigator.serviceWorker.getRegistrations().catch(() => []);
    await Promise.all(registrations.map((reg) => reg.unregister()));
  }
}

export async function purgeBrowserState() {
  await deletePwaDatabase().catch(() => undefined);
  const dbNames = new Set(KNOWN_INDEXED_DBS);
  if ("databases" in indexedDB) {
    const databases = await indexedDB.databases().catch(() => []);
    databases.forEach((database) => {
      if (database.name && database.name !== MONITORING_DB_NAME) dbNames.add(database.name);
    });
  }
  await Promise.all([...dbNames].map((name) => new Promise<void>((resolve) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  })));
  await purgeOfflineShell();
  localStorage.clear();
  sessionStorage.clear();
}

export async function purgeAndShowBrowserOffline() {
  await purgeBrowserState();
  window.location.replace(guardianOrigin());
}
