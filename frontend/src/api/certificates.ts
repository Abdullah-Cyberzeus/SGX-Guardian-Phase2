import { api, apiUrl, authToken } from "./http";

export type CertificateDecision = "reject" | "member" | "lighthouse" | "relay" | "lh_relay";

export interface CertificateRequest {
  node_id: string;
  requested_at: string;
  overlay_ip: string;
  public_key_fingerprint: string;
  requested_role: string;
  approve: string;
}

export const certificatesApi = {
  requests: () => api<CertificateRequest[]>("/cert/requests"),
  decide: (node_id: string, decision: CertificateDecision) =>
    api<{ status: string; message?: string }>("/cert/approve", {
      method: "POST",
      body: JSON.stringify({ node_id, decision }),
    }),
};

/**
 * Subscribe to certificate-request events when the Guardian exposes
 * /cert/requests/ws. REST synchronization remains the compatibility fallback.
 */
export function openCertificateRequestSocket(
  onChange: (requests?: CertificateRequest[]) => void,
  onState: (connected: boolean) => void,
): () => void {
  const endpoint = new URL(apiUrl("/cert/requests/ws"), window.location.origin);
  endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
  if (authToken()) endpoint.searchParams.set("access_token", authToken());
  const socket = new WebSocket(endpoint);
  socket.onopen = () => onState(true);
  socket.onclose = () => onState(false);
  socket.onerror = () => onState(false);
  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(String(event.data)) as {
        type?: string;
        request?: CertificateRequest;
        data?: CertificateRequest;
        requests?: CertificateRequest[];
      };
      if (message.type === "cert.requests.snapshot") {
        onChange(Array.isArray(message.requests) ? message.requests : undefined);
      } else if (["cert.request.created", "cert.request.updated", "certificate_request"].includes(message.type ?? "")) {
        onChange(message.request || message.data ? [message.request ?? message.data as CertificateRequest] : undefined);
      }
    } catch {
      // Ignore malformed events; the REST synchronization loop remains active.
    }
  };
  return () => socket.close();
}
