// SU01 — Setup Choice (P1.8, spec §32 "Initial state").
//
// Reached once an admin account exists but this Guardian is not yet ONLINE
// (routed here by SYS02SplashScreen and ProtectedRoute — see
// contexts/MeshLifecycleContext.tsx). Shows what this Guardian already knows
// about itself — id, DID, hardware backing — and the two ways to give it a
// circle. Create/Join themselves are Phase 2/3 work; this screen's own scope
// is choosing between them and showing where this Guardian stands today.
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { useMeshLifecycle, TERMINAL_FAILURE_STATES } from "../../contexts/MeshLifecycleContext";
import didService, { type DIDStatus } from "../../services/didService";
import nodeService, { type NodeStatus } from "../../services/nodeService";
import pcrService from "../../services/pcrService";

interface Badge {
  label: string;
  tone: "ok" | "warn" | "muted";
}

function StatusBadge({ badge }: { badge: Badge }) {
  const toneStyle: Record<Badge["tone"], { bg: string; fg: string }> = {
    ok: { bg: "var(--success-background, rgba(34,197,94,0.12))", fg: "var(--success, #16a34a)" },
    warn: { bg: "var(--warning-background, rgba(234,179,8,0.14))", fg: "var(--warning, #b45309)" },
    muted: { bg: "var(--muted)", fg: "var(--muted-foreground)" },
  };
  const style = toneStyle[badge.tone];
  return (
    <span
      className="inline-flex items-center rounded-full px-3 py-1"
      style={{
        backgroundColor: style.bg,
        color: style.fg,
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        letterSpacing: "0.02em",
      }}
    >
      {badge.label}
    </span>
  );
}

function didBadge(did: DIDStatus | null): Badge {
  if (!did) return { label: "DID — checking…", tone: "muted" };
  if (did.status && did.status.toLowerCase() !== "active") {
    return { label: `DID ${did.status}`, tone: "warn" };
  }
  return { label: "DID active", tone: "ok" };
}

function hardwareBadge(did: DIDStatus | null): Badge {
  if (!did) return { label: "Hardware key — checking…", tone: "muted" };
  const source = (did.se050UidSource || "").toLowerCase();
  if (!source || source.includes("unavailable") || source.includes("software")) {
    return { label: "Software key backend", tone: "warn" };
  }
  return { label: "SE050 hardware key", tone: "ok" };
}

function stateHeadline(state: string): string {
  switch (state) {
    case "UNENROLLED":
      return "Not yet in a circle";
    case "PENDING_APPROVAL":
      return "Waiting for an administrator to approve this request";
    case "REJECTED":
      return "The last enrollment request was rejected";
    case "ERROR":
      return "The last enrollment attempt failed";
    default:
      return "Setting up…";
  }
}

export function SU01SetupChoice() {
  const navigate = useNavigate();
  const { lifecycle, refresh } = useMeshLifecycle();
  const [node, setNode] = useState<NodeStatus | null>(null);
  const [did, setDid] = useState<DIDStatus | null>(null);
  const [integrityOk, setIntegrityOk] = useState<boolean | null>(null);

  // A pending/in-progress enrollment can complete while the operator is
  // sitting on this screen (WS push from MeshLifecycleContext) — leave
  // automatically rather than requiring a manual navigation once ONLINE.
  useEffect(() => {
    if (lifecycle?.state === "ONLINE") {
      navigate("/home", { replace: true });
    }
  }, [lifecycle?.state, navigate]);

  useEffect(() => {
    let cancelled = false;
    void nodeService.getStatus().then((s) => !cancelled && setNode(s)).catch(() => {});
    void didService.getStatus().then((s) => !cancelled && setDid(s)).catch(() => {});
    void pcrService
      .getStatus()
      .then((s) => !cancelled && setIntegrityOk(s.baselineExists))
      .catch(() => !cancelled && setIntegrityOk(null));
    return () => {
      cancelled = true;
    };
  }, []);

  const state = lifecycle?.state ?? "UNENROLLED";
  const isFailure = TERMINAL_FAILURE_STATES.has(state);
  const isBusy = !isFailure && state !== "UNENROLLED";

  const badges: Badge[] = [
    didBadge(did),
    hardwareBadge(did),
    ...(integrityOk === false ? [{ label: "No PCR baseline yet", tone: "muted" as const }] : []),
  ];

  return (
    <div
      className="flex flex-col items-center"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)", padding: "24px 16px" }}
    >
      <div className="flex flex-col items-center gap-2" style={{ marginBottom: "28px" }}>
        <CervaisLogo width={96} />
        <h1
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-lg)",
            fontWeight: 700,
            color: "var(--foreground)",
          }}
        >
          Set up this Guardian
        </h1>
      </div>

      <Card style={{ width: "100%", maxWidth: 420, marginBottom: "20px" }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            Guardian ID
          </CardTitle>
          <CardDescription
            style={{
              fontFamily: "monospace",
              fontSize: "var(--text-base)",
              color: "var(--foreground)",
            }}
          >
            {node?.nodeId ?? "…"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2" style={{ marginBottom: "12px" }}>
            {badges.map((badge) => (
              <StatusBadge key={badge.label} badge={badge} />
            ))}
          </div>
          <div
            className="rounded-md"
            style={{
              backgroundColor: isFailure ? "var(--destructive-background, rgba(239,68,68,0.1))" : "var(--muted)",
              padding: "12px 14px",
            }}
          >
            <p
              style={{
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-medium)",
                color: isFailure ? "var(--destructive, #dc2626)" : "var(--foreground)",
                margin: 0,
              }}
            >
              {stateHeadline(state)}
            </p>
            {lifecycle?.detail && (
              <p
                style={{
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                  marginTop: "4px",
                  wordBreak: "break-word",
                }}
              >
                {lifecycle.detail}
              </p>
            )}
            {isFailure && (
              <Button
                variant="outline"
                size="sm"
                style={{ marginTop: "10px" }}
                onClick={() => refresh()}
              >
                Retry
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {!isBusy && (
        <div className="flex flex-col gap-3" style={{ width: "100%", maxWidth: 420 }}>
          <Button size="lg" onClick={() => navigate("/setup/create")}>
            Create Mesh Circle
          </Button>
          <Button
            variant="outline"
            size="lg"
            onClick={() =>
              window.alert(
                "Joining an existing circle lands with a later update — this Guardian cannot yet discover or enroll into one from this screen.",
              )
            }
          >
            Join Existing Circle
          </Button>
        </div>
      )}
    </div>
  );
}
