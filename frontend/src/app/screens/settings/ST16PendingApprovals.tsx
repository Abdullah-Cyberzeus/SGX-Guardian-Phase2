import { Fingerprint, Loader2, Server, ShieldCheck, X } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import type { CertificateDecision, CertificateRequest } from "../../../api/certificates";
import { useCertificateRequest } from "../../../features/certificates/CertificateRequestContext";
import { useGuardianConnectivity } from "../../../pwa/connectivity/GuardianConnectivityContext";
import { PageHeader } from "../../components/PageHeader";
import { enrollRequestService, type EnrollRequest } from "../../services/enrollService";

// P4.7 — requests from the P4.3 store (circles created via Phase 2+),
// entirely separate from the legacy YAML-backed list above: its own fetch,
// its own state, appended below rather than merged into
// `CertificateRequestContext`'s existing (WS-driven, YAML-backed) model.
function MeshEnrollRequestsPanel() {
  const [requests, setRequests] = useState<EnrollRequest[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => {
    enrollRequestService
      .list()
      .then((all) => setRequests(all.filter((r) => r.state === "pending")))
      .catch((e) => setError(e instanceof Error ? e.message : "Could not load requests."));
  };

  useEffect(() => {
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => window.clearInterval(interval);
  }, []);

  const act = async (request: EnrollRequest, decision: "approve" | "reject") => {
    setBusyId(request.requestId);
    try {
      if (decision === "approve") {
        await enrollRequestService.approve(request.requestId);
        toast.success("Enrollment request approved");
      } else {
        await enrollRequestService.reject(request.requestId);
        toast.success("Enrollment request rejected");
      }
      refresh();
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Decision failed");
    } finally {
      setBusyId(null);
    }
  };

  if (requests.length === 0 && !error) return null;

  return (
    <div className="flex flex-col gap-4" style={{ marginTop: "8px" }}>
      <div>
        <p className="text-sm font-medium" style={{ color: "var(--foreground)" }}>
          Mesh circle join requests
        </p>
        <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>
          Requests to join a circle created here (Phase 2+), separate from the legacy list above.
        </p>
      </div>
      {error && (
        <div
          className="rounded-lg border p-3 text-sm"
          style={{ borderColor: "var(--destructive)", color: "var(--destructive)" }}
        >
          {error}
        </div>
      )}
      {requests.map((request) => {
        const isActive = busyId === request.requestId;
        const failedChecks = request.policyReport.checks.filter((c) => !c.passed);
        return (
          <article
            key={request.requestId}
            className="rounded-xl border border-border p-4 md:p-5"
            style={{ background: "var(--card)" }}
          >
            <div className="flex items-start gap-3">
              <div
                className="rounded-lg p-2.5"
                style={{ background: "color-mix(in srgb, var(--primary) 12%, transparent)", color: "var(--primary)" }}
              >
                <Server size={20} />
              </div>
              <div className="min-w-0 flex-1">
                <p className="font-semibold break-all" style={{ color: "var(--foreground)" }}>
                  {request.guardianId}
                </p>
                <p className="text-sm mt-1" style={{ color: "var(--muted-foreground)" }}>
                  {request.hwBackend} · {request.hasJoinCode ? "join code offered" : "manual approval"}
                </p>
                <p className="text-xs mt-2 break-all flex items-start gap-1.5" style={{ color: "var(--muted-foreground)" }}>
                  <Fingerprint size={13} className="mt-0.5 shrink-0" /> {request.subjectDid}
                </p>
                <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>
                  Requested {new Date(request.createdAt).toLocaleString()}
                </p>
                {request.policyReport.checks.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {request.policyReport.checks.map((check) => (
                      <span
                        key={check.name}
                        title={check.detail}
                        className="text-xs rounded-full px-2 py-0.5"
                        style={{
                          background: check.passed
                            ? "var(--success-background, rgba(34,197,94,0.12))"
                            : "var(--destructive-background, rgba(239,68,68,0.1))",
                          color: check.passed ? "var(--success, #16a34a)" : "var(--destructive, #dc2626)",
                        }}
                      >
                        {check.passed ? "✔" : "✖"} {check.name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="flex flex-col sm:flex-row gap-2 mt-4 sm:justify-end">
              <button
                disabled={isActive}
                onClick={() => void act(request, "reject")}
                className="rounded-md px-4 py-2.5 text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50"
                style={{
                  border: "1px solid color-mix(in srgb, var(--destructive) 40%, var(--border))",
                  color: "var(--destructive)",
                  background: "transparent",
                }}
              >
                <X size={15} /> Reject
              </button>
              <button
                disabled={isActive}
                title={failedChecks.length > 0 ? `${failedChecks.length} check(s) failed` : undefined}
                onClick={() => void act(request, "approve")}
                className="rounded-md px-4 py-2.5 text-sm font-semibold flex items-center justify-center gap-2 disabled:opacity-50"
                style={{ border: 0, color: "var(--primary-foreground)", background: "var(--primary)" }}
              >
                {isActive ? <Loader2 className="animate-spin" size={15} /> : <ShieldCheck size={15} />} Approve
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );
}

const validRoles = new Set<CertificateDecision>(["member", "lighthouse", "relay", "lh_relay"]);

function approvalRole(request: CertificateRequest): CertificateDecision {
  const requested = request.requested_role.trim().toLowerCase() as CertificateDecision;
  return validRoles.has(requested) ? requested : "member";
}

export function ST16PendingApprovals() {
  const { pendingRequests, socketConnected, working, error, decide } = useCertificateRequest();
  const { reachable } = useGuardianConnectivity();
  const [activeNode, setActiveNode] = useState<string>();
  const actionsDisabled = working || !reachable;
  const disabledTitle = !reachable ? "Guardian unreachable — reconnect to make changes" : undefined;

  const act = async (request: CertificateRequest, decision: CertificateDecision) => {
    setActiveNode(request.node_id);
    try {
      await decide(decision, request);
      toast.success(decision === "reject" ? "Certificate request rejected" : "Certificate request approved");
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Certificate decision failed");
    } finally {
      setActiveNode(undefined);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Pending Approvals" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-3xl p-4 md:p-6 flex flex-col gap-4 pb-8">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium" style={{ color: "var(--foreground)" }}>Node certificate requests</p>
              <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>
                Closing a popup keeps its request here until you approve or reject it.
              </p>
            </div>
            <span className="text-xs rounded-full px-2.5 py-1" style={{ background: "var(--muted)", color: "var(--muted-foreground)" }}>
              {socketConnected ? "Live" : "Syncing"}
            </span>
          </div>

          {error && <div className="rounded-lg border p-3 text-sm" style={{ borderColor: "var(--destructive)", color: "var(--destructive)" }}>{error}</div>}

          {pendingRequests.length === 0 ? (
            <div className="rounded-xl border border-border flex flex-col items-center justify-center text-center p-10 gap-3" style={{ background: "var(--card)" }}>
              <ShieldCheck size={30} style={{ color: "var(--primary)" }} />
              <p className="font-semibold" style={{ color: "var(--foreground)" }}>No pending approvals</p>
              <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>New certificate requests will appear here automatically.</p>
            </div>
          ) : pendingRequests.map((request) => {
            const role = approvalRole(request);
            const isActive = working && activeNode === request.node_id;
            return (
              <article key={`${request.node_id}:${request.requested_at}`} className="rounded-xl border border-border p-4 md:p-5" style={{ background: "var(--card)" }}>
                <div className="flex items-start gap-3">
                  <div className="rounded-lg p-2.5" style={{ background: "color-mix(in srgb, var(--primary) 12%, transparent)", color: "var(--primary)" }}><Server size={20} /></div>
                  <div className="min-w-0 flex-1">
                    <p className="font-semibold break-all" style={{ color: "var(--foreground)" }}>{request.node_id}</p>
                    <p className="text-sm mt-1" style={{ color: "var(--muted-foreground)" }}>{request.overlay_ip} · Requested role: {request.requested_role}</p>
                    <p className="text-xs mt-2 break-all flex items-start gap-1.5" style={{ color: "var(--muted-foreground)" }}><Fingerprint size={13} className="mt-0.5 shrink-0" /> {request.public_key_fingerprint}</p>
                    <p className="text-xs mt-1" style={{ color: "var(--muted-foreground)" }}>Requested {new Date(request.requested_at).toLocaleString()}</p>
                  </div>
                </div>
                <div className="flex flex-col sm:flex-row gap-2 mt-4 sm:justify-end">
                  <button disabled={actionsDisabled} title={disabledTitle} onClick={() => void act(request, "reject")} className="rounded-md px-4 py-2.5 text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50" style={{ border: "1px solid color-mix(in srgb, var(--destructive) 40%, var(--border))", color: "var(--destructive)", background: "transparent" }}><X size={15} /> Reject</button>
                  <button disabled={actionsDisabled} title={disabledTitle} onClick={() => void act(request, role)} className="rounded-md px-4 py-2.5 text-sm font-semibold flex items-center justify-center gap-2 disabled:opacity-50" style={{ border: 0, color: "var(--primary-foreground)", background: "var(--primary)" }}>
                    {isActive ? <Loader2 className="animate-spin" size={15} /> : <ShieldCheck size={15} />} Approve {role.replace("_", " + ")}
                  </button>
                </div>
              </article>
            );
          })}

          <MeshEnrollRequestsPanel />
        </div>
      </div>
    </div>
  );
}
