import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router";
import {
  Plus, Search, Cpu, Shield, Trash2, Loader2, Info, LayoutList, ChevronRight
} from "lucide-react";
import { toast } from "sonner";
import { deviceService, type PairedDevice, type DiscoveredDevice, type DeviceDetail } from "../../services/deviceService";
import * as Dialog from "@radix-ui/react-dialog";

type Tab = "paired" | "unpaired";

// â”€â”€ Status dot for paired guardian â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function StatusDot({ status }: { status: string }) {
  const isPending = status === "pending_bootstrap";
  return (
    <span
      style={{
        display: "inline-block",
        width: "8px",
        height: "8px",
        borderRadius: "50%",
        flexShrink: 0,
        backgroundColor: isPending ? "var(--chart-5)" : "var(--chart-2)",
        animation: isPending ? "pulse 2s ease-in-out infinite" : undefined,
      }}
    />
  );
}

// â”€â”€ DeviceDetailPanel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function DeviceDetailPanel({
  deviceId,
  onClose,
  onUnpair
}: {
  deviceId: string;
  onClose: () => void;
  onUnpair: (id: string) => void;
}) {
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    deviceService.getDevice(deviceId)
      .then((data) => {
        if (active) setDetail(data);
      })
      .catch((e: any) => {
        if (active) toast.error(e.message || "Failed to load device details");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [deviceId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 size={32} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
      </div>
    );
  }

  if (!detail) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Info size={32} style={{ color: "var(--muted-foreground)" }} />
        <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Failed to load details</p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)" }}>
      {/* Header */}
      <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="rounded-lg flex items-center justify-center" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
            <Shield size={20} style={{ color: "var(--primary)" }} />
          </div>
          <div>
            <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Guardian Node</h3>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{detail.serial}</p>
          </div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted-foreground)" }}>
          <XIcon />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-6">
        {/* Status */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>STATUS</p>
          <div className="flex items-center gap-2">
            <StatusDot status={detail.status} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", textTransform: "capitalize" }}>{detail.status}</span>
          </div>
        </div>

        {/* Info list */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>DEVICE INFO</p>
          <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--background)" }}>
            {[
              { label: "Node ID", value: detail.nodeId, mono: true },
              { label: "DID", value: detail.did, mono: true },
              { label: "Overlay IP", value: detail.overlayIp || "N/A", mono: true },
              { label: "Bootstrap Status", value: detail.bootstrapStatus },
            ].map(({ label, value, mono }, i, arr) => (
              <div key={label} className="flex items-center justify-between px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
                <span style={{ fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-all", maxWidth: "200px", textAlign: "right" }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        {detail.status !== 'unpaired' && (
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>ACTIONS</p>
            <button
              onClick={() => { onClose(); onUnpair(detail.deviceId); }}
              className="w-full flex items-center justify-center gap-2 rounded-lg"
              style={{ height: "44px", backgroundColor: "color-mix(in srgb, var(--destructive) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)", color: "var(--destructive)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer" }}
            >
              <Trash2 size={16} /> Unpair Guardian
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function XIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"></line>
      <line x1="6" y1="6" x2="18" y2="18"></line>
    </svg>
  );
}

// â”€â”€ Main component â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
export function DV01DevicesList() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("paired");
  const [search, setSearch] = useState("");

  const [devices, setDevices] = useState<PairedDevice[]>([]);
  const [loading, setLoading] = useState(true);

  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [unpairId, setUnpairId] = useState<string | null>(null);
  const [unpairLoading, setUnpairLoading] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const data = await deviceService.listDevices();
      setDevices(Array.isArray(data) ? data : []);
    } catch (e: any) {
      console.warn("Failed to load devices", e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Tab change resets selection
  useEffect(() => {
    setSelectedDeviceId(null);
  }, [tab]);

  const handleUnpair = async () => {
    if (!unpairId) return;
    setUnpairLoading(true);
    try {
      await deviceService.unpairDevice(unpairId);
      toast.success("Device unpaired");
      setUnpairId(null);
      if (selectedDeviceId === unpairId) setSelectedDeviceId(null);
      loadData();
    } catch (e: any) {
      toast.error(e.message || "Failed to unpair device");
    } finally {
      setUnpairLoading(false);
    }
  };

  const pairedDevices = devices.filter(d => d.status !== 'unpaired');
  const unpairedDevices = devices.filter(d => d.status === 'unpaired');

  const filteredPaired = pairedDevices.filter(d => !search || d.serial.toLowerCase().includes(search.toLowerCase()) || d.nodeId.toLowerCase().includes(search.toLowerCase()));
  const filteredUnpaired = unpairedDevices.filter(d => !search || d.serial.toLowerCase().includes(search.toLowerCase()) || d.nodeId.toLowerCase().includes(search.toLowerCase()));

  const Header = (
    <div className="flex flex-col justify-center flex-shrink-0 px-5 h-20 border-b border-border bg-card relative overflow-hidden">
      <div className="absolute inset-0 opacity-10" style={{ background: "linear-gradient(90deg, var(--primary) 0%, transparent 100%)" }} />
      <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.2, position: "relative" }}>
        Devices
      </h2>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.3, position: "relative" }}>
        Manage your connected Guardians
      </p>
    </div>
  );

  const StatCards = (
    <div className="flex gap-4 px-5 py-5 border-b border-border bg-background">
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Cpu size={16} style={{ color: "var(--primary)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Total Devices</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{devices.length}</p>
      </div>
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-2">
          <Shield size={16} style={{ color: "var(--chart-2)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Paired</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{pairedDevices.length}</p>
      </div>
      <div className="flex-1 rounded-xl p-4 border border-border shadow-sm flex flex-col justify-between" style={{ backgroundColor: "var(--card)" }}>
        <div className="flex items-center gap-2 mb-2">
          <LayoutList size={16} style={{ color: "var(--muted-foreground)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)" }}>Unpaired</span>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>{unpairedDevices.length}</p>
      </div>
    </div>
  );

  const Controls = (
    <div className="flex flex-col gap-4 px-5 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 p-1 rounded-lg" style={{ backgroundColor: "var(--secondary)", border: "1px solid var(--border)" }}>
          <button
            onClick={() => setTab("paired")}
            style={{ padding: "6px 16px", borderRadius: "var(--radius)", backgroundColor: tab === "paired" ? "var(--background)" : "transparent", color: tab === "paired" ? "var(--foreground)" : "var(--muted-foreground)", boxShadow: tab === "paired" ? "0 1px 3px rgba(0,0,0,0.1)" : "none", border: "none", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer", transition: "all 0.2s" }}
          >
            Paired
          </button>
          <button
            onClick={() => setTab("unpaired")}
            style={{ padding: "6px 16px", borderRadius: "var(--radius)", backgroundColor: tab === "unpaired" ? "var(--background)" : "transparent", color: tab === "unpaired" ? "var(--foreground)" : "var(--muted-foreground)", boxShadow: tab === "unpaired" ? "0 1px 3px rgba(0,0,0,0.1)" : "none", border: "none", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", cursor: "pointer", transition: "all 0.2s" }}
          >
            Unpaired
          </button>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative" style={{ width: "240px" }}>
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "var(--muted-foreground)" }} />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search serial or node ID..."
              className="w-full pl-9 pr-3 outline-none"
              style={{ height: "36px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", transition: "border-color 0.2s" }}
            />
          </div>
          <button onClick={() => navigate("/settings/device-pairing")} className="flex items-center justify-center gap-2 px-4 shadow-sm" style={{ height: "36px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", transition: "opacity 0.2s" }}>
            <Plus size={16} /> Pair New Guardian
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex flex-col h-[100dvh] md:flex-row overflow-hidden bg-background">
      <div className="flex flex-col flex-1 border-r border-border min-w-0">
        {Header}
        {StatCards}
        {Controls}

        {/* List area */}
        <div className="flex-1 overflow-y-auto px-5 pb-6">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <Loader2 size={24} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
              <span className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Loading...</span>
            </div>
          ) : tab === "paired" ? (
            filteredPaired.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center border border-dashed border-border rounded-xl" style={{ backgroundColor: "var(--card)" }}>
                <div className="rounded-full flex items-center justify-center mb-4" style={{ width: "64px", height: "64px", backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)" }}>
                  <Shield size={32} style={{ color: "var(--primary)" }} />
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>No paired Guardians found</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Click 'Pair New Guardian' to get started</p>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {filteredPaired.map((device) => (
                  <button
                    key={device.deviceId}
                    onClick={() => setSelectedDeviceId(device.deviceId)}
                    className="w-full text-left flex items-center justify-between p-4 rounded-xl border transition-all shadow-sm"
                    style={{
                      backgroundColor: selectedDeviceId === device.deviceId ? "color-mix(in srgb, var(--primary) 6%, var(--card))" : "var(--card)",
                      borderColor: selectedDeviceId === device.deviceId ? "var(--primary)" : "var(--border)",
                      cursor: "pointer"
                    }}
                  >
                    <div className="flex items-center gap-4">
                      <div className="rounded-lg flex items-center justify-center flex-shrink-0 shadow-sm" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}>
                        <Shield size={20} style={{ color: "var(--primary)" }} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <StatusDot status={device.status} />
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{device.serial}</p>
                        </div>
                        <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.nodeId}</p>
                      </div>
                    </div>
                    <ChevronRight size={18} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                ))}
              </div>
            )
          ) : (
            filteredUnpaired.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center border border-dashed border-border rounded-xl" style={{ backgroundColor: "var(--card)" }}>
                <div className="rounded-full flex items-center justify-center mb-4" style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}>
                  <LayoutList size={32} style={{ color: "var(--muted-foreground)" }} />
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>No unpaired Guardians found</p>
                <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Unpaired devices will appear here</p>
              </div>
            ) : (
              <div className="flex flex-col gap-3">
                {filteredUnpaired.map((device) => (
                  <button
                    key={device.deviceId}
                    onClick={() => setSelectedDeviceId(device.deviceId)}
                    className="w-full text-left flex items-center justify-between p-4 rounded-xl border transition-all shadow-sm"
                    style={{
                      backgroundColor: selectedDeviceId === device.deviceId ? "color-mix(in srgb, var(--primary) 6%, var(--card))" : "var(--card)",
                      borderColor: selectedDeviceId === device.deviceId ? "var(--primary)" : "var(--border)",
                      cursor: "pointer"
                    }}
                  >
                    <div className="flex items-center gap-4">
                      <div className="rounded-lg flex items-center justify-center flex-shrink-0 shadow-sm" style={{ width: "40px", height: "40px", backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}>
                        <LayoutList size={20} style={{ color: "var(--muted-foreground)" }} />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{device.serial}</p>
                        </div>
                        <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.nodeId} Â· Unpaired</p>
                      </div>
                    </div>
                    <ChevronRight size={18} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                ))}
              </div>
            )
          )}
        </div>
      </div>

      {/* Side panel for paired/unpaired devices */}
      <div className="hidden md:flex flex-col" style={{ width: "380px", backgroundColor: "var(--card)", borderLeft: "1px solid var(--border)", boxShadow: "-4px 0 15px rgba(0,0,0,0.02)" }}>
        {selectedDeviceId ? (
          <DeviceDetailPanel deviceId={selectedDeviceId} onClose={() => setSelectedDeviceId(null)} onUnpair={setUnpairId} />
        ) : (
          <div className="flex flex-col items-center justify-center h-full p-8 text-center">
            <Cpu size={48} style={{ color: "var(--muted-foreground)", opacity: 0.2, marginBottom: "16px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>Select a Guardian</p>
            <p className="mt-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>Click a device from the list to view its connection details and status</p>
          </div>
        )}
      </div>

      {/* Mobile side panel overlay */}
      {selectedDeviceId && (
        <div className="md:hidden fixed inset-0 z-50 flex justify-end" style={{ backgroundColor: "rgba(0,0,0,0.5)" }} onClick={() => setSelectedDeviceId(null)}>
          <div className="w-[85vw] max-w-[360px] h-full shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <DeviceDetailPanel deviceId={selectedDeviceId} onClose={() => setSelectedDeviceId(null)} onUnpair={setUnpairId} />
          </div>
        </div>
      )}

      {/* Unpair Confirm Dialog */}
      <Dialog.Root open={!!unpairId} onOpenChange={(open) => !open && setUnpairId(null)}>
        <Dialog.Portal>
          <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.6)", zIndex: 99 }} />
          <Dialog.Content
            style={{
              position: "fixed", top: "50%", left: "50%", transform: "translate(-50%,-50%)", zIndex: 100,
              backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "var(--radius-card)",
              padding: "24px", width: "320px", maxWidth: "90vw"
            }}
          >
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "8px" }}>
              Unpair Guardian
            </Dialog.Title>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", marginBottom: "20px", lineHeight: 1.6 }}>
              Are you sure you want to unpair this device? This will remove its binding to your account.
            </Dialog.Description>
            <div style={{ display: "flex", gap: "8px" }}>
              <Dialog.Close asChild>
                <button style={{ flex: 1, height: "40px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>
                  Cancel
                </button>
              </Dialog.Close>
              <button
                onClick={handleUnpair}
                disabled={unpairLoading}
                style={{ flex: 1, height: "40px", backgroundColor: "var(--destructive)", border: "none", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "white", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px" }}
              >
                {unpairLoading ? <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} /> : <Trash2 size={14} />}
                Unpair
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}

