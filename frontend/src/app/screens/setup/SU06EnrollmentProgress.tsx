// SU06 — Enrollment progress (P4.9, spec §32). Triggers the actual join
// (`POST /api/v1/mesh/join`) on mount, then renders a live stepper purely
// from `useMeshLifecycle()` — the same "watch the lifecycle through
// whatever restart happens" pattern SU02CreateCircle already established
// for circle creation. On REJECTED/ERROR, hands off to SU07; on
// ONLINE/CIRCLE_MEMBER, to SU08.
import { useEffect, useRef, useState } from "react";
import { useNavigate, useLocation } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { useMeshLifecycle, type LifecycleState } from "../../contexts/MeshLifecycleContext";
import { joinService } from "../../services/enrollService";
import api from "../../services/api";
import nodeService from "../../services/nodeService";
import type { DiscoveredCa } from "../../services/meshDiscoveryService";

interface JoinNavState {
  target: DiscoveredCa;
  joinCode?: string;
}

const STEP_STATES: LifecycleState[] = [
  "ENROLLING",
  "PENDING_APPROVAL",
  "CERTIFICATE_RECEIVED",
  "CERTIFICATE_VALIDATED",
  "CIRCLE_MEMBER",
  "ONLINE",
];
const STEP_LABELS = [
  "Key generated & request sent",
  "Awaiting approval",
  "Certificate received",
  "Validated",
  "Circle member",
  "Mesh online",
];

function stepIndexFor(state: LifecycleState | undefined): number {
  if (!state) return -1;
  const idx = STEP_STATES.indexOf(state);
  // UNENROLLED (before the join call lands) reads as "not started yet" —
  // everything else not in the list (BOOT, INITIALIZING, CREATING_CIRCLE,
  // DISCOVERING_CA, WAITING_FOR_CA_SELECTION, CONNECTING_TO_REMOTE_CA)
  // cannot actually occur mid-join, so -1 ("nothing shown yet") is correct
  // for them too rather than guessing.
  return idx;
}

const CIRCLE_MEMBER_INDEX = STEP_STATES.indexOf("CIRCLE_MEMBER");
// Once approved, the real backend sequence (poll → verify → install →
// restart) routinely completes in well under a second — faster than a
// human can read five step labels, and the restart itself then cuts the
// connection before the UI could render every intermediate state anyway.
// `displayedIndex` walks toward wherever the real lifecycle state actually
// is at this pace instead of jumping straight there, purely so the steps
// read as a sequence rather than a stuck spinner followed by a jump-cut.
const STEP_ANIMATION_MS = 450;

export function SU06EnrollmentProgress() {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as JoinNavState | null;
  const { lifecycle } = useMeshLifecycle();
  const [startError, setStartError] = useState<string | null>(null);
  const startedRef = useRef(false);
  const [displayedIndex, setDisplayedIndex] = useState(-1);

  useEffect(() => {
    if (!state?.target || startedRef.current) return;
    startedRef.current = true;
    joinService
      .join({
        lanEndpoint: state.target.lanEndpoint,
        circleId: state.target.circleId,
        joinCode: state.joinCode,
      })
      .catch((e) => setStartError(e instanceof Error ? e.message : "Could not start the join."));
  }, [state]);

  // Monotonic target: the real lifecycle can only move forward during a
  // single join attempt (or jump to REJECTED/ERROR, handled separately
  // below), so the displayed step never needs to walk backward either.
  const targetIndex = Math.max(displayedIndex, stepIndexFor(lifecycle?.state));

  useEffect(() => {
    if (displayedIndex >= targetIndex) return;
    const timer = window.setTimeout(() => setDisplayedIndex((i) => i + 1), STEP_ANIMATION_MS);
    return () => window.clearTimeout(timer);
  }, [displayedIndex, targetIndex]);

  useEffect(() => {
    if (lifecycle?.state === "REJECTED" || lifecycle?.state === "ERROR") {
      navigate("/setup/join/error", {
        replace: true,
        state: { reason: lifecycle.detail, target: state?.target },
      });
      return;
    }
    // Wait for the animation to actually catch up to "Circle member" before
    // leaving this screen — otherwise the operator never sees the last
    // couple of steps complete, the exact jump-cut this rework exists to
    // avoid.
    if (
      (lifecycle?.state === "ONLINE" || lifecycle?.state === "CIRCLE_MEMBER") &&
      displayedIndex >= CIRCLE_MEMBER_INDEX
    ) {
      navigate("/setup/join/complete", { replace: true, state: { target: state?.target } });
    }
  }, [lifecycle?.state, lifecycle?.detail, displayedIndex, navigate, state?.target]);

  if (!state?.target) {
    navigate("/setup/join", { replace: true });
    return null;
  }

  const currentIndex = displayedIndex;
  const cancellable = lifecycle?.state === "PENDING_APPROVAL";
  // True the moment the real backend has already finished (CIRCLE_MEMBER)
  // but the on-screen animation is still walking there, or the restart
  // itself is already underway (the WS/poll connection may already be
  // down) — either way, "waiting for a restart" is a truer label than a
  // bare per-step spinner at this point.
  const finishingUp =
    displayedIndex >= CIRCLE_MEMBER_INDEX &&
    (lifecycle?.state === "CIRCLE_MEMBER" || lifecycle?.state === "ONLINE");

  const cancel = async () => {
    try {
      const node = await nodeService.getStatus();
      await api.request("/mesh/reset", {
        method: "POST",
        body: JSON.stringify({ confirm_guardian_id: node.nodeId }),
      });
    } catch {
      // Best-effort — the request store's own TTL (7 days) is the backstop
      // if this fails for some reason; the operator can just navigate away.
    }
    navigate("/setup/join");
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
          Joining {state.target.circleName}…
        </h1>
      </div>

      <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)" }}>Progress</CardTitle>
        </CardHeader>
        <CardContent>
          {startError && (
            <p style={{ fontSize: "var(--text-xs)", color: "var(--destructive, #dc2626)", marginBottom: "12px" }}>
              {startError}
            </p>
          )}
          <div className="flex flex-col gap-3">
            {STEP_LABELS.map((label, idx) => {
              const done = currentIndex > idx;
              const active = currentIndex === idx;
              return (
                <div key={label} className="flex items-center gap-3">
                  <div
                    className="rounded-full flex items-center justify-center shrink-0"
                    style={{
                      width: 22,
                      height: 22,
                      backgroundColor: done
                        ? "var(--success, #16a34a)"
                        : active
                          ? "var(--primary)"
                          : "var(--muted)",
                      color: done || active ? "white" : "var(--muted-foreground)",
                      fontSize: "var(--text-xs)",
                    }}
                  >
                    {done ? "✓" : idx + 1}
                  </div>
                  <span
                    style={{
                      fontSize: "var(--text-sm)",
                      color: active ? "var(--foreground)" : "var(--muted-foreground)",
                      fontWeight: active ? "var(--font-weight-medium)" : undefined,
                    }}
                  >
                    {label}
                  </span>
                  {active && (
                    <div
                      className="rounded-full animate-spin"
                      style={{
                        width: 14,
                        height: 14,
                        border: "2px solid var(--muted)",
                        borderTopColor: "var(--primary)",
                        marginLeft: "auto",
                      }}
                    />
                  )}
                </div>
              );
            })}
          </div>
          {finishingUp && (
            <p
              style={{
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
                marginTop: "12px",
                textAlign: "center",
              }}
            >
              Restarting to activate the mesh… this page will update automatically.
            </p>
          )}
        </CardContent>
      </Card>

      {cancellable && (
        <Button variant="outline" onClick={() => void cancel()}>
          Cancel
        </Button>
      )}
    </div>
  );
}
