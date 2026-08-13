import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

interface ConnectivityState { reachable: boolean; checking: boolean; lastSeen?: number; checkNow: () => Promise<void>; }
const Context = createContext<ConnectivityState>({ reachable: true, checking: true, checkNow: async () => {} });

export function GuardianConnectivityProvider({ children }: { children: ReactNode }) {
  const [reachable, setReachable] = useState(true);
  const [checking, setChecking] = useState(true);
  const [lastSeen, setLastSeen] = useState<number | undefined>();

  const checkNow = async () => {
    setChecking(true);
    try {
      const response = await fetch("/api/v1/health", { cache: "no-store", signal: AbortSignal.timeout(2500) });
      if (!response.ok) throw new Error("Guardian health check failed");
      setReachable(true);
      setLastSeen(Date.now());
    } catch {
      setReachable(false);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    void checkNow();
    const timer = window.setInterval(() => void checkNow(), 10_000);
    const foreground = () => { if (document.visibilityState === "visible") void checkNow(); };
    document.addEventListener("visibilitychange", foreground);
    return () => { window.clearInterval(timer); document.removeEventListener("visibilitychange", foreground); };
  }, []);

  const value = useMemo(() => ({ reachable, checking, lastSeen, checkNow }), [reachable, checking, lastSeen]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export const useGuardianConnectivity = () => useContext(Context);
