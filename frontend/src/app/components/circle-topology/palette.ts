import type { AttestationStatus, PresenceStatus } from "./types";

export const PRESENCE_COLORS: Record<PresenceStatus, string> = {
  online: "#22c55e",
  stale: "#f59e0b",
  offline: "#64748b",
  unknown: "#94a3b8",
};

export const TRUST_COLORS: Record<AttestationStatus, string> = {
  verified: "#38bdf8",
  pending: "#f59e0b",
  failed: "#ef4444",
  never: "#64748b",
};

/**
 * Injected onto `.clt-shell` at runtime so every presence/trust swatch in the
 * CSS (legend, minimap, live-state pill) reads the same values as the inline
 * SVG node colors above — no more hand-copied hex that can drift out of sync.
 * Deliberately namespaced away from the pre-existing `--clt-healthy` /
 * `--clt-warning` / `--clt-offline` vars, which are also used as generic
 * muted/warning text colors unrelated to node presence state.
 */
export function paletteCssVars(): Record<string, string> {
  return {
    "--clt-state-online": PRESENCE_COLORS.online,
    "--clt-state-stale": PRESENCE_COLORS.stale,
    "--clt-state-offline": PRESENCE_COLORS.offline,
    "--clt-state-unknown": PRESENCE_COLORS.unknown,
    "--clt-trust-verified": TRUST_COLORS.verified,
    "--clt-trust-pending": TRUST_COLORS.pending,
    "--clt-trust-failed": TRUST_COLORS.failed,
    "--clt-trust-never": TRUST_COLORS.never,
  };
}
