import { describe, expect, it } from "vitest";
import { shouldApplyIncomingStatus } from "./conflict";

describe("shouldApplyIncomingStatus — docs §9.2 conflict priority 3", () => {
  it("applies forward progression along the delivery pipeline", () => {
    expect(shouldApplyIncomingStatus("pending_local", "accepted_by_guardian")).toBe(true);
    expect(shouldApplyIncomingStatus("accepted_by_guardian", "delivered_to_remote_guardian")).toBe(true);
    expect(shouldApplyIncomingStatus("delivered_to_remote_guardian", "read")).toBe(true);
  });

  it("never regresses a later delivery state back to an earlier one", () => {
    expect(shouldApplyIncomingStatus("read", "delivered_to_remote_guardian")).toBe(false);
    expect(shouldApplyIncomingStatus("delivered_to_remote_guardian", "accepted_by_guardian")).toBe(false);
    expect(shouldApplyIncomingStatus("read", "pending_local")).toBe(false);
  });

  it("is a no-op when the incoming status matches the current one", () => {
    expect(shouldApplyIncomingStatus("read", "read")).toBe(false);
    expect(shouldApplyIncomingStatus("pending_local", "pending_local")).toBe(false);
  });

  it("allows any non-terminal status to transition into a terminal one", () => {
    expect(shouldApplyIncomingStatus("pending_local", "failed_permanent")).toBe(true);
    expect(shouldApplyIncomingStatus("delivered_to_remote_guardian", "cancelled")).toBe(true);
  });

  it("never regresses out of a terminal status once set", () => {
    expect(shouldApplyIncomingStatus("failed_permanent", "pending_local")).toBe(false);
    expect(shouldApplyIncomingStatus("cancelled", "delivered_to_remote_guardian")).toBe(false);
    expect(shouldApplyIncomingStatus("failed_permanent", "accepted_by_guardian")).toBe(false);
  });

  it("fails open (applies the change) for a status string it doesn't recognize, rather than silently dropping it", () => {
    expect(shouldApplyIncomingStatus("pending_local", "some_future_status")).toBe(true);
    expect(shouldApplyIncomingStatus("some_future_status", "read")).toBe(true);
  });
});
