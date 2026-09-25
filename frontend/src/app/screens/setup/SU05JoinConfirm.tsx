// SU05 — Confirm CA (P4.9, spec §32). Reached from SU03's "Join Selected
// Circle" button, carrying the operator's chosen `DiscoveredCa` (and any
// join code typed in) via router state. One deliberate checkpoint before
// anything happens: the operator reads the circle name, the CA's guardian
// id and its fingerprint phrase and confirms it out loud against whoever
// showed them the join code / the other screen, the same out-of-band check
// spec §4.5 describes for a CA fingerprint generally.
import { useNavigate, useLocation } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import type { DiscoveredCa } from "../../services/meshDiscoveryService";

interface JoinNavState {
  target: DiscoveredCa;
  joinCode?: string;
}

export function SU05JoinConfirm() {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as JoinNavState | null;

  if (!state?.target) {
    // Reached directly (a refresh, a bookmarked link) rather than via
    // SU03's navigate-with-state — there is nothing to confirm without the
    // selected target, so send the operator back to pick one rather than
    // rendering a broken confirmation screen.
    navigate("/setup/join", { replace: true });
    return null;
  }
  const { target, joinCode } = state;

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
          Confirm this is the right circle
        </h1>
      </div>

      <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)" }}>{target.circleName}</CardTitle>
          <CardDescription style={{ fontSize: "var(--text-xs)" }}>
            Read the fingerprint phrase out loud and compare it with whoever gave you access —
            this is the only moment to catch a wrong network before joining it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-3">
            <div>
              <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                CA fingerprint
              </p>
              <p
                style={{
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-medium)",
                  color: "var(--foreground)",
                }}
              >
                {target.fingerprintWords}
              </p>
              <p
                style={{
                  fontFamily: "monospace",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                  wordBreak: "break-all",
                  marginTop: "4px",
                }}
              >
                {target.fingerprint}
              </p>
            </div>
            <div className="rounded-md" style={{ backgroundColor: "var(--muted)", padding: "10px 12px" }}>
              <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                CA Guardian: {target.caGuardianId} · {target.lanEndpoint}
              </p>
            </div>
            {joinCode ? (
              <div
                className="rounded-md flex items-center gap-2"
                style={{
                  backgroundColor: "var(--success-background, rgba(34,197,94,0.12))",
                  padding: "10px 12px",
                }}
              >
                <span style={{ fontSize: "var(--text-xs)", color: "var(--success, #16a34a)" }}>
                  Join code entered — matches this circle ✔
                </span>
              </div>
            ) : (
              <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                No join code — an administrator on this circle will need to approve your request
                manually.
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3" style={{ width: "100%", maxWidth: 440 }}>
        <Button
          size="lg"
          onClick={() => navigate("/setup/join/progress", { state: { target, joinCode } })}
        >
          This is my circle — Join
        </Button>
        <Button variant="outline" onClick={() => navigate("/setup/join")}>
          Back
        </Button>
      </div>
    </div>
  );
}
