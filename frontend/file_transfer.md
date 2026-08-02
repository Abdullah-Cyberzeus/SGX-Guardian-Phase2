// Frontend-only monitoring: captures JS errors, React errors, API errors, and
// slow calls. Events are persisted to IndexedDB (no backend calls).
//
// Inspect in DevTools console:
//   window.__monitoringLogs                    ← live in-memory array
//
//   const db = await new Promise(r => {
//     const req = indexedDB.open('cervais_monitor');
//     req.onsuccess = e => r(e.target.result);
//   });
//   const all = await new Promise(r => {
//     const req = db.transaction('events').objectStore('events').getAll();
//     req.onsuccess = e => r(e.target.result);
//   });
//   console.table(all);

export type EventType = 'js_error' | 'react_error' | 'api_error' | 'api_slow' | 'console_error';

export interface MonitoringEvent {
  id: string;
  type: EventType;
  timestamp: string;
  message: string;
  route: string;
  stack?: string;
  method?: string;
  url?: string;
  status?: number;
  duration?: number;
}

const DB_NAME = 'cervais_monitor';
const DB_VERSION = 1;
const STORE = 'events';
const MAX_EVENTS = 2000;
const SLOW_MS = 3000;

class MonitoringService {
  private buffer: MonitoringEvent[] = [];
  private consoleIntercepted = false;
  private db: IDBDatabase | null = null;

  init(): void {
    this.openDb();
    this.interceptConsole();
    (window as unknown as Record<string, unknown>)['__monitoringLogs'] = this.buffer;
  }

  private openDb(): void {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = (e.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { autoIncrement: true });
        store.createIndex('type', 'type', { unique: false });
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };
    req.onsuccess = (e) => {
      this.db = (e.target as IDBOpenDBRequest).result;
    };
    // IndexedDB unavailable (private browsing on some browsers) — in-memory only
    req.onerror = () => {};
  }

  capture(
    type: EventType,
    message: string,
    extras: Partial<Pick<MonitoringEvent, 'stack' | 'method' | 'url' | 'status' | 'duration'>> = {}
  ): void {
    const event: MonitoringEvent = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      type,
      timestamp: new Date().toISOString(),
      message: message.slice(0, 1000),
      route: window.location.pathname,
      ...extras,
    };
    this.buffer.push(event);
    this.persist(event);
  }

  trackApiCall(
    method: string,
    endpoint: string,
    status: number | null,
    duration: number,
    errorMsg?: string
  ): void {
    const isError = !!errorMsg || (status !== null && status >= 400);
    const isSlow = !isError && duration > SLOW_MS;

    if (isError) {
      this.capture('api_error', errorMsg || `HTTP ${status}`, {
        method,
        url: endpoint,
        status: status ?? undefined,
        duration,
      });
    } else if (isSlow) {
      this.capture('api_slow', `Slow response (${duration}ms)`, {
        method,
        url: endpoint,
        status: status ?? undefined,
        duration,
      });
    }
  }

  private persist(event: MonitoringEvent): void {
    if (!this.db) return;
    const tx = this.db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    store.add(event);
    // After inserting, trim the oldest records if over the cap
    const countReq = store.count();
    countReq.onsuccess = () => {
      const excess = countReq.result - MAX_EVENTS;
      if (excess <= 0) return;
      // Auto-increment means lower keys are older — cursor walks oldest-first
      const cursorReq = store.openCursor();
      let deleted = 0;
      cursorReq.onsuccess = (e) => {
        const cursor = (e.target as IDBRequest<IDBCursorWithValue | null>).result;
        if (cursor && deleted < excess) {
          cursor.delete();
          deleted++;
          cursor.continue();
        }
      };
    };
  }

  private interceptConsole(): void {
    if (this.consoleIntercepted) return;
    this.consoleIntercepted = true;

    const orig = console.error.bind(console);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    console.error = (...args: any[]) => {
      orig(...args);
      const msg = args
        .map((a) => (typeof a === 'string' ? a : a instanceof Error ? a.message : JSON.stringify(a)))
        .join(' ')
        .slice(0, 600);
      if (!msg.includes('[Monitor]') && !msg.includes('[ErrorBoundary]')) {
        this.capture('console_error', msg);
      }
    };
  }
}

export const monitoring = new MonitoringService();
