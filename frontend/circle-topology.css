import { AlertTriangle, X, RefreshCw } from "lucide-react";
import { useDaemonRestart } from "../contexts/DaemonRestartContext";
import { toast } from "sonner";
import { useState } from "react";

export function DaemonRestartBanner() {
  const { showBanner, message, dismissBanner } = useDaemonRestart();
  const [isRestarting, setIsRestarting] = useState(false);

  if (!showBanner) return null;

  const handleRestart = () => {
    setIsRestarting(true);
    // Simulate daemon restart
    setTimeout(() => {
      setIsRestarting(false);
      dismissBanner();
      toast.success("Daemon restarted successfully", {
        description: "All services are now running with updated keys",
      });
    }, 2000);
  };

  return (
    <div
      className="fixed top-0 left-0 right-0 z-[100] flex items-center gap-3 px-4 py-3"
      style={{
        backgroundColor: "var(--chart-5)",
        color: "white",
        boxShadow: "0 2px 8px rgba(0,0,0,0.2)",
      }}
    >
      <AlertTriangle size={20} style={{ flexShrink: 0 }} />
      <p
        className="flex-1"
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-sm)",
          fontWeight: "var(--font-weight-medium)",
        }}
      >
        {message}
      </p>
      <button
        onClick={handleRestart}
        disabled={isRestarting}
        className="flex items-center gap-2 px-3 py-1.5 rounded transition-opacity"
        style={{
          backgroundColor: "rgba(255,255,255,0.2)",
          border: "1px solid rgba(255,255,255,0.3)",
          color: "white",
          cursor: isRestarting ? "not-allowed" : "pointer",
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-semibold)",
          opacity: isRestarting ? 0.7 : 1,
        }}
      >
        <RefreshCw
          size={14}
          style={{ animation: isRestarting ? "spin 1s linear infinite" : "none" }}
        />
        {isRestarting ? "Restarting..." : "Restart Now"}
      </button>
      <button
        onClick={dismissBanner}
        className="flex items-center justify-center rounded transition-opacity hover:opacity-80"
        style={{
          width: "28px",
          height: "28px",
          backgroundColor: "rgba(255,255,255,0.1)",
          border: "none",
          cursor: "pointer",
        }}
        aria-label="Dismiss"
      >
        <X size={16} />
      </button>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
