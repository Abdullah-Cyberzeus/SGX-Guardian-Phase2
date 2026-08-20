import { beforeEach, describe, expect, it } from "vitest";
import { deletePwaDatabase } from "../db/database";
import { decryptValue, encryptExport, encryptValue } from "./vault";

// Each test gets a fresh IndexedDB so the lazily-generated local AES key
// doesn't leak state (and thus expected ciphertexts) across tests.
beforeEach(async () => {
  await deletePwaDatabase();
});

describe("encryptValue / decryptValue", () => {
  it("round-trips a JSON-serializable value", async () => {
    const original = { messageId: "m1", content: "hello", nested: [1, 2, 3] };
    const encrypted = await encryptValue(original);
    expect(encrypted.version).toBe(1);
    expect(encrypted.iv).toBeTruthy();
    expect(encrypted.ciphertext).toBeTruthy();

    const decrypted = await decryptValue<typeof original>(encrypted);
    expect(decrypted).toEqual(original);
  });

  it("produces a different ciphertext for the same value on repeat calls (fresh IV)", async () => {
    const a = await encryptValue("same-plaintext");
    const b = await encryptValue("same-plaintext");
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("reuses the same local key across calls within a session", async () => {
    // If the key weren't reused, decrypting a value encrypted earlier in
    // the same session would fail once `localKey()` is called again.
    const encrypted = await encryptValue("first");
    await encryptValue("second"); // second call to localKey()
    await expect(decryptValue(encrypted)).resolves.toBe("first");
  });

  it("rejects an encrypted-record version it doesn't understand", async () => {
    const encrypted = await encryptValue("value");
    const futureVersionRecord = { ...encrypted, version: 2 } as unknown as typeof encrypted;
    await expect(decryptValue(futureVersionRecord)).rejects.toThrow(
      "Unsupported encrypted-record version",
    );
  });
});

describe("encryptExport", () => {
  it("rejects a passphrase shorter than 12 characters", async () => {
    await expect(encryptExport({ a: 1 }, "short")).rejects.toThrow(
      "Export passphrase must contain at least 12 characters",
    );
  });

  it("accepts a 12-character passphrase (boundary) and produces a decryptable envelope", async () => {
    const passphrase = "twelve-chars"; // exactly 12
    const payload = { secret: "vault contents", count: 3 };
    const envelope = await encryptExport(payload, passphrase);

    expect(envelope.format).toBe("sgx-pwa-export");
    expect(envelope.kdf).toBe("PBKDF2-SHA256");
    expect(envelope.iterations).toBe(310_000);

    // Manually re-derive the key the same way `encryptExport` does, to
    // prove the envelope is genuinely decryptable and not just shaped
    // correctly — `vault.ts` has no `decryptExport` counterpart to call.
    const encoder = new TextEncoder();
    const unb64 = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
    const material = await crypto.subtle.importKey(
      "raw",
      encoder.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: unb64(envelope.salt), iterations: envelope.iterations },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const clear = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(envelope.iv) },
      key,
      unb64(envelope.ciphertext),
    );
    expect(JSON.parse(new TextDecoder().decode(clear))).toEqual(payload);
  });

  it("uses a fresh salt and IV on every export", async () => {
    const first = await encryptExport({ a: 1 }, "a-long-enough-passphrase");
    const second = await encryptExport({ a: 1 }, "a-long-enough-passphrase");
    expect(first.salt).not.toBe(second.salt);
    expect(first.iv).not.toBe(second.iv);
  });
});
