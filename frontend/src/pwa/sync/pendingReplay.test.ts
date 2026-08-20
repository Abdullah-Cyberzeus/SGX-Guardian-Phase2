import { beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../../app/services/api";
import { deletePwaDatabase } from "../db/database";
import { pendingRepository } from "../db/pendingRepository";
import {
  pendingOperationCount,
  registerPendingReplayHandler,
  replayPendingOperations,
} from "./pendingReplay";

beforeEach(async () => {
  await deletePwaDatabase();
});

describe("pendingOperationCount", () => {
  it("counts only queued and sending operations", async () => {
    await pendingRepository.enqueue("test.queued", {});
    const sending = await pendingRepository.enqueue("test.queued", {});
    await pendingRepository.save({ ...sending, state: "sending" });
    await pendingRepository.enqueue("test.cancelled", {}).then((r) => pendingRepository.save({ ...r, state: "cancelled" }));
    await pendingRepository.enqueue("test.failed", {}).then((r) => pendingRepository.save({ ...r, state: "failed_permanent" }));

    expect(await pendingOperationCount()).toBe(2);
  });
});

describe("replayPendingOperations — queue state machine", () => {
  it("a successful replay removes the operation from the queue", async () => {
    registerPendingReplayHandler("test.success", async () => {});
    await pendingRepository.enqueue("test.success", { content: "hi" });

    const result = await replayPendingOperations();
    expect(result).toEqual({ replayed: 1, skipped: 0, remaining: 0 });
    expect(await pendingRepository.list()).toHaveLength(0);
  });

  it("a retryable failure (e.g. Guardian unreachable) goes back to queued, never a dead 'failed' state", async () => {
    registerPendingReplayHandler("test.retryable", async () => {
      throw new ApiError("network error", 0);
    });
    await pendingRepository.enqueue("test.retryable", {});

    const result = await replayPendingOperations();
    expect(result.replayed).toBe(0);
    expect(result.skipped).toBe(1);
    const [record] = await pendingRepository.list();
    expect(record.state).toBe("queued");
    expect(record.attempts).toBe(1);
    expect(record.lastError).toBe("network error");
  });

  it("a plain (non-ApiError) thrown error with no expiry/attempt-ceiling issue is retryable, not permanent", async () => {
    registerPendingReplayHandler("test.generic-error", async () => {
      throw new Error("unexpected client error");
    });
    await pendingRepository.enqueue("test.generic-error", {});

    await replayPendingOperations();
    const [record] = await pendingRepository.list();
    expect(record.state).toBe("queued");
  });

  it("a permanent failure status (400/404/409) moves the operation to failed_permanent", async () => {
    for (const status of [400, 404, 409]) {
      await deletePwaDatabase();
      registerPendingReplayHandler("test.permanent", async () => {
        throw new ApiError(`rejected ${status}`, status);
      });
      await pendingRepository.enqueue("test.permanent", {});

      await replayPendingOperations();
      const [record] = await pendingRepository.list();
      expect(record.state).toBe("failed_permanent");
    }
  });

  it("an expired operation is marked failed_permanent even if the handler would otherwise retry", async () => {
    registerPendingReplayHandler("test.expired", async () => {
      throw new Error("still unreachable");
    });
    const enqueued = await pendingRepository.enqueue("test.expired", {});
    await pendingRepository.save({ ...enqueued, expiresAt: Date.now() - 1000 });

    await replayPendingOperations();
    const [record] = await pendingRepository.list();
    expect(record.state).toBe("failed_permanent");
  });

  it("an operation that has hit the attempt ceiling is marked failed_permanent", async () => {
    registerPendingReplayHandler("test.ceiling", async () => {
      throw new Error("still unreachable");
    });
    const enqueued = await pendingRepository.enqueue("test.ceiling", {});
    await pendingRepository.save({ ...enqueued, attempts: 96 });

    await replayPendingOperations();
    const [record] = await pendingRepository.list();
    expect(record.state).toBe("failed_permanent");
  });

  it("a 401 (session revoked) re-queues the operation and rethrows to stop the batch", async () => {
    registerPendingReplayHandler("test.revoked", async () => {
      throw new ApiError("unauthorized", 401);
    });
    await pendingRepository.enqueue("test.revoked", {});

    await expect(replayPendingOperations()).rejects.toBeInstanceOf(ApiError);
    const [record] = await pendingRepository.list();
    expect(record.state).toBe("queued");
  });

  it("cancelled and failed_permanent operations are skipped without invoking any handler", async () => {
    let invoked = false;
    registerPendingReplayHandler("test.skip", async () => { invoked = true; });
    const cancelled = await pendingRepository.enqueue("test.skip", {});
    await pendingRepository.save({ ...cancelled, state: "cancelled" });
    const failed = await pendingRepository.enqueue("test.skip", {});
    await pendingRepository.save({ ...failed, state: "failed_permanent" });

    const result = await replayPendingOperations();
    expect(invoked).toBe(false);
    expect(result.skipped).toBe(2);
  });

  it("an operation with no registered handler is skipped, not lost", async () => {
    await pendingRepository.enqueue("test.no-handler-registered", {});
    const result = await replayPendingOperations();
    expect(result.skipped).toBe(1);
    expect(await pendingRepository.list()).toHaveLength(1);
  });
});
