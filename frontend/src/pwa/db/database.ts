import { PWA_DB_NAME, PWA_DB_VERSION, stores, type StoreName, type StoreRecordMap } from "./schema";

let connection: Promise<IDBDatabase> | null = null;

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error || new Error("IndexedDB transaction aborted"));
    transaction.onerror = () => reject(transaction.error || new Error("IndexedDB transaction failed"));
  });
}

function hasIndex(store: IDBObjectStore, name: string) {
  return Array.from(store.indexNames).includes(name);
}

function migrate(database: IDBDatabase, oldVersion: number, transaction: IDBTransaction | null) {
  if (oldVersion < 1) {
    database.createObjectStore(stores.membership, { keyPath: "id" });
    const messages = database.createObjectStore(stores.messages, { keyPath: "id" });
    messages.createIndex("conversation_timestamp", ["conversationId", "timestamp"]);
    database.createObjectStore(stores.contacts, { keyPath: "did" });
    database.createObjectStore(stores.files, { keyPath: "id" });
    const calls = database.createObjectStore(stores.calls, { keyPath: "id" });
    calls.createIndex("started_at", "startedAt");
    const pending = database.createObjectStore(stores.pending, { keyPath: "id" });
    pending.createIndex("state_created", ["state", "createdAt"]);
    database.createObjectStore(stores.settings, { keyPath: "key" });
    database.createObjectStore(stores.syncState, { keyPath: "key" });
  }
  if (oldVersion < 2) {
    if (!database.objectStoreNames.contains(stores.notifications)) {
      const notifications = database.createObjectStore(stores.notifications, { keyPath: "id" });
      notifications.createIndex("created_at", "createdAt");
    }
  }
  if (oldVersion < 3) {
    if (transaction && database.objectStoreNames.contains(stores.messages)) {
      const messages = transaction.objectStore(stores.messages);
      if (!hasIndex(messages, "conversation_status")) messages.createIndex("conversation_status", ["conversationId", "status"]);
      if (!hasIndex(messages, "conversation_updated")) messages.createIndex("conversation_updated", ["conversationId", "updatedAt"]);
    }
    if (transaction && database.objectStoreNames.contains(stores.pending)) {
      const pending = transaction.objectStore(stores.pending);
      if (!hasIndex(pending, "kind_state_created")) pending.createIndex("kind_state_created", ["kind", "state", "createdAt"]);
    }
  }
}

export function openPwaDatabase(): Promise<IDBDatabase> {
  if (!connection) connection = new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) return reject(new Error("IndexedDB is unavailable"));
    const request = indexedDB.open(PWA_DB_NAME, PWA_DB_VERSION);
    request.onupgradeneeded = (event) => migrate(request.result, event.oldVersion, request.transaction);
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
    request.onerror = () => reject(request.error || new Error("PWA database could not be opened"));
    request.onblocked = () => reject(new Error("Close other Guardian tabs to upgrade offline storage"));
  });
  return connection.catch((error) => { connection = null; throw error; });
}

export async function readRecord<S extends StoreName>(store: S, key: IDBValidKey): Promise<StoreRecordMap[S] | undefined> {
  const db = await openPwaDatabase();
  return requestResult(db.transaction(store, "readonly").objectStore(store).get(key));
}

export async function readAll<S extends StoreName>(store: S): Promise<StoreRecordMap[S][]> {
  const db = await openPwaDatabase();
  return requestResult(db.transaction(store, "readonly").objectStore(store).getAll());
}

export async function putRecord<S extends StoreName>(store: S, value: StoreRecordMap[S]): Promise<void> {
  const db = await openPwaDatabase();
  const tx = db.transaction(store, "readwrite");
  tx.objectStore(store).put(value);
  await transactionDone(tx);
}

export async function deleteRecord(store: StoreName, key: IDBValidKey): Promise<void> {
  const db = await openPwaDatabase();
  const tx = db.transaction(store, "readwrite");
  tx.objectStore(store).delete(key);
  await transactionDone(tx);
}

export async function clearStores(names: StoreName[]): Promise<void> {
  const db = await openPwaDatabase();
  const tx = db.transaction(names, "readwrite");
  names.forEach((name) => tx.objectStore(name).clear());
  await transactionDone(tx);
}

export async function runAtomic<T>(names: StoreName[], work: (tx: IDBTransaction) => T): Promise<T> {
  const db = await openPwaDatabase();
  const tx = db.transaction(names, "readwrite");
  // IndexedDB may auto-commit as soon as control returns to the event loop.
  // Keep queue mutations synchronous so every request is registered on the
  // same transaction before waiting for its completion.
  const result = work(tx);
  await transactionDone(tx);
  return result;
}

export async function deletePwaDatabase(): Promise<void> {
  const db = await connection?.catch(() => null);
  db?.close();
  connection = null;
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(PWA_DB_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error || new Error("Offline database could not be reset"));
    request.onblocked = () => reject(new Error("Close other Guardian tabs before resetting offline data"));
  });
}

export { requestResult };
