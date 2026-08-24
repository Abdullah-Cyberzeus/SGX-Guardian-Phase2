import { describe, expect, it } from "vitest";
import { paletteCssVars, PRESENCE_COLORS, TRUST_COLORS } from "./palette";

describe("live topology palette", () => {
  it("publishes every presence and trust state as a CSS variable", () => {
    expect(paletteCssVars()).toEqual({
      "--clt-state-online": PRESENCE_COLORS.online,
      "--clt-state-stale": PRESENCE_COLORS.stale,
      "--clt-state-offline": PRESENCE_COLORS.offline,
      "--clt-state-unknown": PRESENCE_COLORS.unknown,
      "--clt-trust-verified": TRUST_COLORS.verified,
      "--clt-trust-pending": TRUST_COLORS.pending,
      "--clt-trust-failed": TRUST_COLORS.failed,
      "--clt-trust-never": TRUST_COLORS.never,
    });
  });

  it("keeps critical semantic states visually distinct", () => {
    expect(new Set(Object.values(PRESENCE_COLORS)).size).toBe(4);
    expect(TRUST_COLORS.verified).not.toBe(TRUST_COLORS.failed);
    expect(PRESENCE_COLORS.online).not.toBe(PRESENCE_COLORS.offline);
  });
});
