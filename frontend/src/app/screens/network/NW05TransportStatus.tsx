import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  Wifi,
  Network,
  CheckCircle2,
  XCircle,
  Lock,
  LockOpen,
  Loader2,
  Radio,
  Signal,
} from "lucide-react";
import { useTransportList, useTransportStatus } from "../../hooks/useApiData";
import { transportService } from "../../services/transportService";
import type { TransportInterface } from "../../services/transportService";
import { networkInterfaceDisplay } from "../../utils/networkInterfaceDisplay";
import type { InterfaceGroup } from "../../utils/networkInterfaceDisplay";
import { toast } from "sonner";

function transportIcon(transport: string) {
  const t = transport.toLowerCase();
  if (t.includes("wifi") || t.includes("wlan")) return <Wifi size={16} />;
  if (t.includes("lte") || t.includes("cellular")) return <Signal size={16} />;
  if (t.includes("nebula") || t.includes("overlay")) return <Radio size={16} />;
  return <Network size={16} />;
}

function InterfaceCard({
  iface,
  isActive,
  isLocked,
  onLock,
  locking,
}: {
  iface: TransportInterface;
  isActive: boolean;
  isLocked: boolean;
  onLock: (name: string) => void;
  locking: boolean;
}) {
  const meta = networkInterfaceDisplay(iface.name);
  return (
    <div
      className="rounded-lg border p-4 flex flex-col gap-3"
      style={{
        backgroundColor: "var(--card)",
        borderColor: isActive ? "var(--primary)" : "var(--border)",
        borderWidth: isActive ? "2px" : "1px",
      }}
    >
    <div className="flex items-center gap-3">
      <div
        className="flex items-center justify-center rounded-lg flex-shrink-0"
        style={{
          width: "40px",
          height: "40px",
          backgroundColor: iface.available
            ? "color-mix(in srgb, var(--chart-2) 15%, transparent)"
            : "color-mix(in srgb, var(--muted-foreground) 15%, transparent)",
          color: iface.available ? "var(--chart-2)" : "var(--muted-foreground)",
        }}
      >
        {transportIcon(iface.transport)}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            {meta.displayName}
          </p>
          {isActive && (
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-medium)", color: "var(--primary)", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", padding: "2px 6px", borderRadius: "4px" }}>
              Active
            </span>
          )}
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          {meta.description}
        </p>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "2px" }}>
          {meta.category} · {iface.name}
        </p>
        {iface.ip && (
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
            {iface.ip}
          </p>
        )}
      </div>

      <div className="flex flex-col items-end gap-1">
        <span
          className="flex items-center gap-1"
          style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: iface.available ? "var(--chart-2)" : "var(--muted-foreground)" }}
        >
          {iface.available ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
          {iface.available ? "Up" : "Down"}
        </span>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          {iface.status}
        </span>
      </div>
    </div>

      <button
        onClick={() => onLock(iface.name)}
        disabled={locking || isLocked || !iface.available}
        className="w-full flex items-center justify-center gap-2 py-2 rounded-lg"
        style={{
          backgroundColor: isLocked
            ? "color-mix(in srgb, var(--muted-foreground) 10%, transparent)"
            : "color-mix(in srgb, var(--primary) 10%, transparent)",
          border: `1px solid ${isLocked
            ? "var(--border)"
            : "color-mix(in srgb, var(--primary) 25%, transparent)"}`,
          color: isLocked ? "var(--muted-foreground)" : "var(--primary)",
          cursor: locking || isLocked || !iface.available ? "not-allowed" : "pointer",
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-medium)",
          opacity: !iface.available ? 0.6 : 1,
        }}
      >
        {locking ? <Loader2 size={12} className="animate-spin" /> : <Lock size={12} />}
        {isLocked ? "Locked" : "Lock to this interface"}
      </button>
    </div>
  );
}

export function NW05TransportStatus() {
  const navigate = useNavigate();
  const { data: listData, loading: listLoading, refetch: refetchList } = useTransportList();
  const { data: statusData, loading: statusLoading, refetch: refetchStatus } = useTransportStatus();
  const [pendingLockIface, setPendingLockIface] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);

  const node = listData?.node ?? statusData?.node ?? "";

  const handleLock = async (interfaceName: string) => {
    if (!node) {
      toast.error("Node id not available");
      return;
    }
    setPendingLockIface(interfaceName);
    try {
      const result = await transportService.lock(node, interfaceName);
      if (result.ok) {
        toast.success("Transport locked", { description: result.message });
        await Promise.all([refetchList(), refetchStatus()]);
      } else {
        toast.error("Failed to lock transport");
      }
    } catch (err) {
      toast.error("Failed to lock transport", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setPendingLockIface(null);
    }
  };

  const handleUnlock = async () => {
    if (!node) {
      toast.error("Node id not available");
      return;
    }
    setUnlocking(true);
    try {
      const result = await transportService.unlock(node);
      if (result.ok) {
        toast.success("Transport unlocked", { description: result.message });
        await Promise.all([refetchList(), refetchStatus()]);
      } else {
        toast.error("Failed to unlock transport");
      }
    } catch (err) {
      toast.error("Failed to unlock transport", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setUnlocking(false);
    }
  };

  const loading = listLoading || statusLoading;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  const interfaces = listData?.interfaces ?? [];
  const activeInterface = statusData?.active ?? listData?.active;
  const activeMeta = activeInterface ? networkInterfaceDisplay(activeInterface.name) : null;
  const lock = statusData?.lock ?? listData?.lock;
  const groupedInterfaces = useMemo(() => {
    const groups: Record<InterfaceGroup, TransportInterface[]> = {
      "WIRELESS CONNECTIONS": [],
      "GUARDIAN NETWORK": [],
      INFRASTRUCTURE: [],
    };
    for (const iface of [...interfaces].sort((a, b) => a.priority - b.priority)) {
      groups[networkInterfaceDisplay(iface.name).group].push(iface);
    }
    return groups;
  }, [interfaces]);

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Transport" subtitle="Network Interfaces" onBack={() => navigate("/network")} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
        {/* Active Transport Banner */}
        <div
          className="flex items-center gap-3 p-4 rounded-lg"
          style={{
            backgroundColor: activeInterface
              ? "color-mix(in srgb, var(--primary) 10%, transparent)"
              : "color-mix(in srgb, var(--muted-foreground) 10%, transparent)",
            border: `1px solid ${activeInterface
              ? "color-mix(in srgb, var(--primary) 25%, transparent)"
              : "var(--border)"}`,
          }}
        >
          <Network size={24} style={{ color: activeInterface ? "var(--primary)" : "var(--muted-foreground)", flexShrink: 0 }} />
          <div className="flex-1">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Active Transport
            </p>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: activeInterface ? "var(--primary)" : "var(--muted-foreground)" }}>
              {activeInterface && activeMeta ? `${activeMeta.displayName} (${activeMeta.category})` : "None"}
            </p>
          </div>
          {lock && (
            <button
              onClick={handleUnlock}
              disabled={unlocking}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-md"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
                color: "var(--destructive)",
                cursor: unlocking ? "not-allowed" : "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)",
              }}
              title={`Locked to ${lock}`}
            >
              {unlocking ? <Loader2 size={12} className="animate-spin" /> : <LockOpen size={12} />}
              {unlocking ? "Unlocking…" : `Unlock (${lock})`}
            </button>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <Network size={18} style={{ color: "var(--primary)", margin: "0 auto 8px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>
              {interfaces.length}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Total</p>
          </div>
          <div className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <CheckCircle2 size={18} style={{ color: "var(--chart-2)", margin: "0 auto 8px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--chart-2)" }}>
              {interfaces.filter(i => i.available).length}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Available</p>
          </div>
          <div className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <XCircle size={18} style={{ color: "var(--muted-foreground)", margin: "0 auto 8px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>
              {interfaces.filter(i => !i.available).length}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Down</p>
          </div>
        </div>

        {/* Interface List */}
        <div className="flex flex-col gap-4">
          {interfaces.length === 0 ? (
            <div className="rounded-lg border p-6 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
              <Network size={32} style={{ color: "var(--muted-foreground)", margin: "0 auto 12px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                No interfaces found
              </p>
            </div>
          ) : (
            (Object.entries(groupedInterfaces) as [InterfaceGroup, TransportInterface[]][])
              .filter(([, groupInterfaces]) => groupInterfaces.length > 0)
              .map(([group, groupInterfaces]) => (
                <section key={group}>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "12px" }}>
                    {group}
                  </p>
                  <div className="flex flex-col gap-3">
                    {groupInterfaces.map(iface => (
                      <InterfaceCard
                        key={iface.name}
                        iface={iface}
                        isActive={activeInterface?.name === iface.name}
                        isLocked={lock === iface.name}
                        onLock={handleLock}
                        locking={pendingLockIface === iface.name}
                      />
                    ))}
                  </div>
                </section>
              ))
          )}
        </div>

        {/* Node Info */}
        {listData?.node && (
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center" }}>
            Node: {listData.node}
          </p>
        )}
        </div>
      </div>
    </div>
  );
}
