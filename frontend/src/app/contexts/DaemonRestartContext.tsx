import { createContext, useContext, useState, useCallback, ReactNode } from "react";

interface DaemonRestartContextType {
  showBanner: boolean;
  message: string;
  triggerRestart: (message?: string) => void;
  dismissBanner: () => void;
}

const DaemonRestartContext = createContext<DaemonRestartContextType | undefined>(undefined);

export function DaemonRestartProvider({ children }: { children: ReactNode }) {
  const [showBanner, setShowBanner] = useState(false);
  const [message, setMessage] = useState("");

  const triggerRestart = useCallback((msg?: string) => {
    setMessage(msg || "Key rotation completed. Guardian daemon restart required for changes to take effect.");
    setShowBanner(true);
  }, []);

  const dismissBanner = useCallback(() => {
    setShowBanner(false);
    setMessage("");
  }, []);

  return (
    <DaemonRestartContext.Provider value={{ showBanner, message, triggerRestart, dismissBanner }}>
      {children}
    </DaemonRestartContext.Provider>
  );
}

export function useDaemonRestart() {
  const context = useContext(DaemonRestartContext);
  if (!context) {
    throw new Error("useDaemonRestart must be used within a DaemonRestartProvider");
  }
  return context;
}
