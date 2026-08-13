import { ApiError } from "../../app/services/api";
import { decryptValue } from "../crypto/vault";
import { pendingRepository } from "../db/pendingRepository";
import type { PendingRecord } from "../db/schema";

type ReplayHandler = (record: PendingRecord, payload: unknown) => Promise<void>;

const handlers = new Map<string, ReplayHandler>();

export function registerPendingReplayHandler(kind: string, handler: ReplayHandler) {
  handlers.set(kind, handler);
}

export async function pendingOperationCount() {
  return (await pendingRepository.list()).filter((record) => record.state !== "failed").length;
}

function isRevoked(error: unknown) {
  return error instanceof ApiError && error.status === 401;
}

export async function replayPendingOperations() {
  const records = await pendingRepository.list();
  let replayed = 0;
  let skipped = 0;

  for (const record of records) {
    const handler = handlers.get(record.kind);
    if (!handler) {
      skipped += 1;
      continue;
    }

    const attempted = { ...record, attempts: record.attempts + 1, state: "sending" as const };
    await pendingRepository.save(attempted);
    try {
      const payload = await decryptValue(record.payload);
      await handler(attempted, payload);
      await pendingRepository.remove(record.id);
      replayed += 1;
    } catch (error) {
      if (isRevoked(error)) {
        await pendingRepository.save({ ...attempted, state: "queued" });
        throw error;
      }
      // Guardian unreachable mid-replay, a recipient not currently attested,
      // or any other non-auth failure: this is retryable, so put it back to
      // "queued" (never "failed" — nothing ever un-fails it) and keep
      // replaying the rest of the batch instead of aborting on one item.
      // That is what keeps a message "Pending" while its peer is offline and
      // lets it go through automatically once the peer is reachable again.
      await pendingRepository.save({ ...attempted, state: "queued" });
      skipped += 1;
    }
  }

  return { replayed, skipped, remaining: await pendingOperationCount() };
}
