// SU08 — Complete (P4.9, spec §32/§26 "member card"). Reached once
// `useMeshLifecycle()` reports ONLINE (or CIRCLE_MEMBER, if the socket/poll
// catches up mid-restart before the final activation tick lands) —
// `lifecycle.profile` is already populated at that point by the same
// `/api/v1/mesh/lifecycle` response SU06 was already watching, so this
// screen needs no fetch of its own.
import { useNavigate } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { useMeshLifecycle } from "../../contexts/MeshLifecycleContext";

export function SU08JoinComplete() {
  const navigate = useNavigate();
  const { lifecycle } = useMeshLifecycle();
  const profile = lifecycle?.profile;

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
          You're in
        </h1>
      </div>

      <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)" }}>
            {profile?.circleName ?? "Circle"}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-3">
            <div className="rounded-md" style={{ backgroundColor: "var(--muted)", padding: "10px 12px" }}>
              <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                Role: {profile?.role ?? "Member"} · Overlay IP: {profile?.overlayIp ?? "—"}
              </p>
            </div>
            <div>
              <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                CA fingerprint
              </p>
              <p
                style={{
                  fontFamily: "monospace",
                  fontSize: "var(--text-xs)",
                  color: "var(--foreground)",
                  wordBreak: "break-all",
                }}
              >
                {profile?.caFingerprint ?? "—"}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3" style={{ width: "100%", maxWidth: 440 }}>
        <Button size="lg" onClick={() => navigate("/home", { replace: true })}>
          Go to Dashboard
        </Button>
      </div>
    </div>
  );
}
