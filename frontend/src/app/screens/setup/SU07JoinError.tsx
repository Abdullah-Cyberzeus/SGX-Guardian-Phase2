// SU07 — Rejected/Error (P4.9, spec §32). Reached from SU06 the moment
// `useMeshLifecycle()` reports REJECTED or ERROR. "Retry" resets the
// lifecycle back to UNENROLLED (the same `/mesh/reset` P1.6 already
// exposes) and returns to the LAN search; "Reset" is the same action under
// a plainer label, kept as a separate, more prominent button since a
// rejection is more often something the operator needs to actually change
// (a different join code, asking the admin) than just try again verbatim.
import { useState } from "react";
import { useNavigate, useLocation } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import api from "../../services/api";
import nodeService from "../../services/nodeService";
import type { DiscoveredCa } from "../../services/meshDiscoveryService";

interface ErrorNavState {
  reason?: string | null;
  target?: DiscoveredCa;
}

export function SU07JoinError() {
  const navigate = useNavigate();
  const location = useLocation();
  const state = (location.state as ErrorNavState | null) ?? {};
  const [busy, setBusy] = useState(false);
  const [resetError, setResetError] = useState<string | null>(null);

  const resetAndReturn = async () => {
    setBusy(true);
    setResetError(null);
    try {
      const node = await nodeService.getStatus();
      await api.request("/mesh/reset", {
        method: "POST",
        body: JSON.stringify({ confirm_guardian_id: node.nodeId }),
      });
      navigate("/setup/join");
    } catch (e) {
      setResetError(e instanceof Error ? e.message : "Could not reset — try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="flex flex-col items-center"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)", padding: "24px 16px" }}
    >
      <div className="flex flex-col items-center gap-2" style={{ marginBottom: "24px" }}>
        <CervaisLogo width={96} />
        <h1
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-lg)",
            fontWeight: 700,
            color: "var(--foreground)",
          }}
        >
          Could not join {state.target?.circleName ?? "that circle"}
        </h1>
      </div>

      <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)", color: "var(--destructive, #dc2626)" }}>
            {state.reason ?? "The request was rejected or something went wrong."}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            The administrator of this circle may have declined the request, or it expired before
            anyone acted on it. You can try again — a fresh key and request are generated each
            time.
          </p>
          {resetError && (
            <p style={{ fontSize: "var(--text-xs)", color: "var(--destructive, #dc2626)", marginTop: "10px" }}>
              {resetError}
            </p>
          )}
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3" style={{ width: "100%", maxWidth: 440 }}>
        <Button size="lg" disabled={busy} onClick={() => void resetAndReturn()}>
          {busy ? "…" : "Try again"}
        </Button>
        <Button variant="outline" onClick={() => navigate("/setup")}>
          Back to setup
        </Button>
      </div>
    </div>
  );
}
