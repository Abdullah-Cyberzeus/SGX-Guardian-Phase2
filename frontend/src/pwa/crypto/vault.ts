import { readRecord, putRecord } from "../db/database";
import { stores, type EncryptedRecord, type SettingRecord } from "../db/schema";

const KEY_RECORD = "__local_crypto_key__";
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (value: string) => Uint8Array.from(atob(value), (character) => character.charCodeAt(0));

async function localKey(): Promise<CryptoKey> {
  const existing = await readRecord(stores.settings, KEY_RECORD) as SettingRecord | undefined;
  if (existing?.value instanceof CryptoKey) return existing.value;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await putRecord(stores.settings, { key: KEY_RECORD, value: key, updatedAt: Date.now() });
  return key;
}

export async function encryptValue(value: unknown): Promise<EncryptedRecord> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await localKey(), encoder.encode(JSON.stringify(value)));
  return { version: 1, iv: b64(iv), ciphertext: b64(new Uint8Array(encrypted)) };
}

export async function decryptValue<T>(record: EncryptedRecord): Promise<T> {
  if (record.version !== 1) throw new Error("Unsupported encrypted-record version");
  const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(record.iv) }, await localKey(), unb64(record.ciphertext));
  return JSON.parse(decoder.decode(clear)) as T;
}

export async function encryptExport(value: unknown, passphrase: string) {
  if (passphrase.length < 12) throw new Error("Export passphrase must contain at least 12 characters");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 310_000 }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(value)));
  return { format: "sgx-pwa-export", version: 1, kdf: "PBKDF2-SHA256", iterations: 310_000, salt: b64(salt), iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) };
}
