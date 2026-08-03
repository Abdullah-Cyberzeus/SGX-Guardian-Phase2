import { Fingerprint, Loader2, Server, ShieldCheck, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import type { CertificateDecision, CertificateRequest } from "../../../api/certificates";
import { useCertificateRequest } from "../../../features/certificates/CertificateRequestContext";
import { PageHeader } from "../../components/PageHeader";

const validRoles = new Set<CertificateDecision>(["member", "lighthouse", "relay", "lh_relay"]);

function approvalRole(request: CertificateRequest): CertificateDecision {
  const requested = request.requested_role.trim().toLowerCase() as CertificateDecision;
  return validRoles.has(requested) ? requested : "member";
}

export function ST16PendingApprovals() {
  const { pendingRequests, socketConnected, working, error, decide } = useCertificateRequest();
  const [activeNode, setActiveNode] = useState<string>();

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
                  <button disabled={working} onClick={() => void act(request, "reject")} className="rounded-md px-4 py-2.5 text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50" style={{ border: "1px solid color-mix(in srgb, var(--destructive) 40%, var(--border))", color: "var(--destructive)", background: "transparent" }}><X size={15} /> Reject</button>
                  <button disabled={working} onClick={() => void act(request, role)} className="rounded-md px-4 py-2.5 text-sm font-semibold flex items-center justify-center gap-2 disabled:opacity-50" style={{ border: 0, color: "var(--primary-foreground)", background: "var(--primary)" }}>
                    {isActive ? <Loader2 className="animate-spin" size={15} /> : <ShieldCheck size={15} />} Approve {role.replace("_", " + ")}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </div>
  );
}
