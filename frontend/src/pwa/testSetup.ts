// Vitest setup: polyfills IndexedDB (jsdom doesn't implement it) so
// pwa/db repositories and pwa/crypto's key-storage round-trip run against
// a real, in-memory IndexedDB implementation rather than a browser.
import 'fake-indexeddb/auto';
