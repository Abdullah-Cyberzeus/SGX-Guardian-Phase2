import { ApiError } from "../../app/services/api";
import { decryptValue } from "../crypto/vault";
import { messageRepository } from "../db/messageRepository";
import { pendingRepository } from "../db/pendingRepository";
import type { PendingRecord } from "../db/schema";

type ReplayHandler = (record: PendingRecord, payload: unknown) => Promise<void>;

const handlers = new Map<string, ReplayHandler>();
const MAX_ATTEMPTS = 96;

export function registerPendingReplayHandler(kind: string, handler: ReplayHandler) {
  handlers.set(kind, handler);
}

export async function pendingOperationCount() {
  return (await pendingRepository.list()).filter((record) => record.state === "queued" || record.state === "sending").length;
}

function isRevoked(error: unknown) {
  return error instanceof ApiError && error.status === 401;
}

function isPermanentFailure(record: PendingRecord, error: unknown) {
  if (record.expiresAt && Date.now() > record.expiresAt) return true;
  if (record.attempts >= MAX_ATTEMPTS) return true;
  if (error instanceof ApiError) return error.status === 400 || error.status === 404 || error.status === 409;
  return false;
}

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : "Pending operation failed";
}

export async function replayPendingOperations() {
  const records = await pendingRepository.list();
  let replayed = 0;
  let skipped = 0;

  for (const record of records) {
    if (record.state === "cancelled" || record.state === "failed_permanent") {
      skipped += 1;
      continue;
    }
    const handler = handlers.get(record.kind);
    if (!handler) {
      skipped += 1;
      continue;
    }

    const attempted = { ...record, attempts: record.attempts + 1, state: "sending" as const, lastAttemptAt: Date.now(), lastError: undefined };
    await pendingRepository.save(attempted);
    try {
      const payload = await decryptValue(record.payload);
      await handler(attempted, payload);
      await pendingRepository.remove(record.id);
      replayed += 1;
    } catch (error) {
      if (isRevoked(error)) {
        await pendingRepository.save({ ...attempted, state: "queued", lastError: messageOf(error) });
        throw error;
      }
      if (isPermanentFailure(attempted, error)) {
        const reason = messageOf(error);
        await pendingRepository.save({ ...attempted, state: "failed_permanent", lastError: reason });
        await messageRepository.markPermanentFailure(record.id, reason).catch(() => undefined);
        skipped += 1;
        continue;
      }
      // Guardian unreachable mid-replay, a recipient not currently attested,
      // or any other non-auth failure: this is retryable, so put it back to
      // "queued" (never "failed" — nothing ever un-fails it) and keep
      // replaying the rest of the batch instead of aborting on one item.
      // That is what keeps a message "Pending" while its peer is offline and
      // lets it go through automatically once the peer is reachable again.
      await pendingRepository.save({ ...attempted, state: "queued", lastError: messageOf(error) });
      skipped += 1;
    }
  }

  return { replayed, skipped, remaining: await pendingOperationCount() };
}
