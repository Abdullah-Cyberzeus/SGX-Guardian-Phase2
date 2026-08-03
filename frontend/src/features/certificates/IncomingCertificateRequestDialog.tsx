import { Fingerprint, Server, ShieldCheck, X } from "lucide-react";
import { useState } from "react";
import type { CertificateDecision } from "../../api/certificates";
import { useCertificateRequest } from "./CertificateRequestContext";

const validRoles = new Set<CertificateDecision>(["member", "lighthouse", "relay", "lh_relay"]);

export function IncomingCertificateRequestDialog() {
  const { request, working, error, dismiss, decide } = useCertificateRequest();
  const [failure, setFailure] = useState<string>();
  if (!request) return null;
  const requestedRole = request.requested_role.trim().toLowerCase() as CertificateDecision;
  const approvalRole: CertificateDecision = validRoles.has(requestedRole) ? requestedRole : "member";

  const act = async (decision: CertificateDecision) => {
    setFailure(undefined);
    try { await decide(decision); }
    catch (cause) { setFailure(cause instanceof Error ? cause.message : "Certificate decision failed"); }
  };

  return <aside className="incoming-call-toast" role="alertdialog" aria-labelledby="incoming-cert-title">
    <div className="incoming-call-icon"><Server size={20} /></div>
    <div className="min-w-0 flex-1">
      <strong id="incoming-cert-title">New node certificate request</strong>
      <span>{request.node_id} · {request.overlay_ip}</span>
      <small className={failure || error ? "call-toast-error" : undefined}><Fingerprint size={12} className="inline-block" /> {failure || error || `${request.public_key_fingerprint} · ${request.requested_role}`}</small>
    </div>
    <button className="incoming-decline-icon" disabled={working} onClick={() => dismiss(request)} aria-label="Dismiss certificate request for now"><X size={17} /></button>
    <div className="incoming-call-actions">
      <button disabled={working} onClick={() => void act("reject")}>Reject</button>
      <button className="accept" disabled={working} onClick={() => void act(approvalRole)}><ShieldCheck size={14} /> {working ? "Saving…" : `Approve ${approvalRole.replace("_", " + ")}`}</button>
    </div>
  </aside>;
}
