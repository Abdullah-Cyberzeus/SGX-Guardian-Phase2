import { deleteRecord, readAll, readRecord, runAtomic } from "./database";
import { encryptValue, decryptValue } from "../crypto/vault";
import { shouldApplyIncomingStatus } from "../sync/conflict";
import { stores, type MessageRecord, type PendingRecord } from "./schema";

const QUEUE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function normalizeSearchText(value: string) {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function textFromPayload(value: unknown) {
  if (!value || typeof value !== "object") return String(value ?? "");
  const record = value as Record<string, unknown>;
  const encryptedPayload = typeof record.encrypted_payload === "string" ? record.encrypted_payload : "";
  let content = "";
  let attachmentId = "";
  try {
    const parsed = JSON.parse(encryptedPayload) as Record<string, unknown>;
    content = typeof parsed.content === "string" ? parsed.content : "";
    attachmentId = typeof parsed.attachment_id === "string" ? parsed.attachment_id : "";
  } catch {
    content = encryptedPayload;
  }
  return [
    content,
    attachmentId,
    typeof record.sender_did === "string" ? record.sender_did : "",
    typeof record.recipient_did === "string" ? record.recipient_did : "",
    typeof record.group_id === "string" ? record.group_id : "",
  ].join(" ");
}

export const messageRepository = {
  async list(conversationId: string) {
    return (await readAll(stores.messages)).filter((item) => item.conversationId === conversationId).sort((a, b) => a.sequence - b.sequence || a.timestamp - b.timestamp);
  },
  get: (id: string) => readRecord(stores.messages, id),
  // Used after a successful offline-queue replay: the message keeps its place
  // in the cached conversation instead of disappearing until the next full
  // history reload.
  async updateStatus(id: string, status: string) {
    const existing = await readRecord(stores.messages, id);
    if (!existing) return;
    if (!shouldApplyIncomingStatus(existing.status, status)) return;
    const value = await decryptValue<Record<string, unknown>>(existing.payload);
    const payload = await encryptValue({ ...value, status });
    return runAtomic([stores.messages], (tx) => { tx.objectStore(stores.messages).put({ ...existing, status, updatedAt: Date.now(), payload }); });
  },
  async save(record: Omit<MessageRecord, "payload"> & { value: unknown }) {
    const payload = await encryptValue(record.value);
    const { value: _plaintext, ...metadata } = record;
    return runAtomic([stores.messages], (tx) => { tx.objectStore(stores.messages).put({ ...metadata, updatedAt: Date.now(), searchText: normalizeSearchText(textFromPayload(record.value)), payload }); });
  },
  async saveAndQueue(record: Omit<MessageRecord, "payload"> & { value: unknown }, operation: { id: string; kind: string; value: unknown }) {
    const [payload, pendingPayload] = await Promise.all([encryptValue(record.value), encryptValue(operation.value)]);
    const { value: _plaintext, ...metadata } = record;
    const now = Date.now();
    const pending: PendingRecord = { id: operation.id, kind: operation.kind, createdAt: now, attempts: 0, state: "queued", expiresAt: now + QUEUE_TTL_MS, payload: pendingPayload };
    return runAtomic([stores.messages, stores.pending], (tx) => {
      tx.objectStore(stores.messages).put({ ...metadata, updatedAt: now, searchText: normalizeSearchText(textFromPayload(record.value)), payload });
      tx.objectStore(stores.pending).put(pending);
    });
  },
  async markCancelled(id: string) {
    await this.updateStatus(id, "cancelled");
  },
  async markPermanentFailure(id: string, error: string) {
    const existing = await readRecord(stores.messages, id);
    if (!existing) return;
    const value = await decryptValue<Record<string, unknown>>(existing.payload);
    const payload = await encryptValue({ ...value, status: "failed_permanent", failure_reason: error });
    return runAtomic([stores.messages], (tx) => { tx.objectStore(stores.messages).put({ ...existing, status: "failed_permanent", updatedAt: Date.now(), payload }); });
  },
  async search(conversationId: string, query: string, displayNameForDid?: (did: string) => string | undefined) {
    const terms = normalizeSearchText(query).split(" ").filter(Boolean);
    if (!terms.length) return this.list(conversationId);
    const records = await this.list(conversationId);
    const matches = await Promise.all(records.map(async (record) => {
      const value = await decryptValue<Record<string, unknown>>(record.payload);
      const sender = typeof value.sender_did === "string" ? displayNameForDid?.(value.sender_did) || "" : "";
      const recipient = typeof value.recipient_did === "string" ? displayNameForDid?.(value.recipient_did) || "" : "";
      const haystack = normalizeSearchText([record.searchText || "", textFromPayload(value), sender, recipient].join(" "));
      return terms.every((term) => haystack.includes(term)) ? value : undefined;
    }));
    return matches.filter((value): value is Record<string, unknown> => Boolean(value));
  },
  remove: (id: string) => deleteRecord(stores.messages, id),
};
