import { describe, expect, it } from "vitest";
import { normalizeNotification } from "./notifications";

describe("normalizeNotification", () => {
  it("accepts security notification aliases and alert id references", () => {
    const item = normalizeNotification({
      id: "n-1",
      notification_type: "security_alert",
      title: "Threat detected",
      message: "Suspicious traffic detected",
      severity: "high",
      alert_id: "alert/a",
      created_at: "2026-09-15T12:00:00Z",
    });

    expect(item.kind).toBe("AlertHigh");
    expect(item.refId).toBe("alert/a");
    expect(item.body).toBe("Suspicious traffic detected");
  });

  it("keeps missing kinds clickable as severity-based alert notifications", () => {
    const item = normalizeNotification({
      id: "n-2",
      title: "Alert",
      severity: "medium",
      source_id: "alert/b",
    });

    expect(item.kind).toBe("AlertMedium");
    expect(item.refId).toBe("alert/b");
  });
});
