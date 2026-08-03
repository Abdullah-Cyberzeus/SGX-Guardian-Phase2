import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { certificatesApi, openCertificateRequestSocket, type CertificateDecision, type CertificateRequest } from "../../api/certificates";

interface CertificateRequestContextValue {
  request?: CertificateRequest;
  pendingRequests: CertificateRequest[];
  socketConnected: boolean;
  working: boolean;
  error?: string;
  dismiss(request?: CertificateRequest): void;
  decide(decision: CertificateDecision, request?: CertificateRequest): Promise<void>;
}

const Context = createContext<CertificateRequestContextValue | null>(null);

function isPending(request: CertificateRequest) {
  return request.approve.trim().toLowerCase() === "false";
}

export function CertificateRequestProvider({ children }: { children: ReactNode }) {
  const [requests, setRequests] = useState<CertificateRequest[]>([]);
  const [socketConnected, setSocketConnected] = useState(false);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string>();
  const dismissed = useRef(new Set<string>());
  const [dismissVersion, setDismissVersion] = useState(0);

  const refresh = useCallback(async () => {
    try {
      const next = await certificatesApi.requests();
      setRequests(Array.isArray(next) ? next : []);
      setError(undefined);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Certificate requests could not be loaded");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 3_000);
    const closeSocket = openCertificateRequestSocket((snapshot) => {
      if (snapshot) {
        setRequests(snapshot);
        setError(undefined);
      } else {
        void refresh();
      }
    }, setSocketConnected);
    return () => { window.clearInterval(timer); closeSocket(); };
  }, [refresh]);

  const pendingRequests = useMemo(() => requests.filter(isPending), [requests]);
  const request = useMemo(
    () => pendingRequests.find((item) => !dismissed.current.has(`${item.node_id}:${item.requested_at}`)),
    [pendingRequests, dismissVersion],
  );

  const dismiss = useCallback((item = request) => {
    if (!item) return;
    dismissed.current.add(`${item.node_id}:${item.requested_at}`);
    setDismissVersion((version) => version + 1);
  }, [request]);

  const decide = useCallback(async (decision: CertificateDecision, item = request) => {
    if (!item || working) return;
    setWorking(true);
    setError(undefined);
    try {
      await certificatesApi.decide(item.node_id, decision);
      dismissed.current.add(`${item.node_id}:${item.requested_at}`);
      setRequests((current) => current.filter((candidate) => candidate.node_id !== item.node_id));
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Certificate decision failed");
      throw cause;
    } finally {
      setWorking(false);
    }
  }, [refresh, request, working]);

  const value = useMemo(
    () => ({ request, pendingRequests, socketConnected, working, error, dismiss, decide }),
    [request, pendingRequests, socketConnected, working, error, dismiss, decide],
  );
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useCertificateRequest() {
  const value = useContext(Context);
  if (!value) throw new Error("useCertificateRequest must be inside CertificateRequestProvider");
  return value;
}
