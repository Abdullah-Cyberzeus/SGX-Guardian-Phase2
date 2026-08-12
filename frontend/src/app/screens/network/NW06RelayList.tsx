import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  Radio,
  CheckCircle2,
  XCircle,
  Loader2,
  Users,
  Wifi,
  Settings,
  Save,
  X,
  Power,
  TowerControl,
  Server,
} from "lucide-react";
import {
  useRelayList,
  useLighthouseList,
  useMemberList,
  useRelayLighthouseList,
  useDIDDocumentPeers,
} from "../../hooks/useApiData";
import { useContactNames } from "../../contexts/ContactNameContext";
import { relayService } from "../../services/relayService";
import type { RelayNode, RegistryNode } from "../../services/relayService";
import type { DIDDocumentPeerSummary } from "../../services/didService";
import { toast } from "sonner";

type NodeEntry = RegistryNode & Partial<Pick<RelayNode, "maxPeers" | "maxBandwidthMbps" | "currentMbps">>;

type TabKey = "relays" | "lighthouses" | "members" | "dual";

type RoleOverride = { relayEnabled?: boolean; lighthouseEnabled?: boolean };

const TABS: { key: TabKey; label: string; icon: typeof Radio }[] = [
  { key: "relays", label: "Relays", icon: Radio },
  { key: "lighthouses", label: "Lighthouses", icon: TowerControl },
  { key: "members", label: "Members", icon: Server },
  { key: "dual", label: "Relay + LH", icon: Wifi },
];

function BandwidthBar({ current, max }: { current: number; max: number }) {
  const pct = max > 0 ? Math.min((current / max) * 100, 100) : 0;
  const color = pct > 80 ? "var(--destructive)" : pct > 50 ? "var(--chart-4)" : "var(--chart-2)";
  return (
    <div style={{ width: "100%", height: "4px", backgroundColor: "var(--muted)", borderRadius: "2px", overflow: "hidden" }}>
      <div style={{ width: `${pct}%`, height: "100%", backgroundColor: color, borderRadius: "2px", transition: "width 0.3s" }} />
    </div>
  );
}

function RoleBadge({ label, enabled, icon: Icon }: { label: string; enabled: boolean; icon: typeof Radio }) {
  return (
    <span
      className="flex items-center gap-1 rounded-md px-1.5 py-0.5"
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        backgroundColor: enabled
          ? "color-mix(in srgb, var(--chart-2) 12%, transparent)"
          : "color-mix(in srgb, var(--muted-foreground) 10%, transparent)",
        color: enabled ? "var(--chart-2)" : "var(--muted-foreground)",
        border: `1px solid ${enabled
          ? "color-mix(in srgb, var(--chart-2) 25%, transparent)"
          : "var(--border)"}`,
      }}
    >
      <Icon size={10} />
      {label}
    </span>
  );
}

function RoleToggleButton({
  enabled,
  label,
  icon: Icon,
  busy,
  onClick,
}: {
  enabled: boolean;
  label: string;
  icon: typeof Radio;
  busy: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className="flex items-center justify-center gap-2 py-2 rounded-lg"
      style={{
        backgroundColor: enabled
          ? "color-mix(in srgb, var(--destructive) 10%, transparent)"
          : "color-mix(in srgb, var(--chart-2) 12%, transparent)",
        border: `1px solid ${enabled
          ? "color-mix(in srgb, var(--destructive) 25%, transparent)"
          : "color-mix(in srgb, var(--chart-2) 25%, transparent)"}`,
        color: enabled ? "var(--destructive)" : "var(--chart-2)",
        cursor: busy ? "not-allowed" : "pointer",
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        opacity: busy ? 0.7 : 1,
      }}
    >
      {busy ? <Loader2 size={14} className="animate-spin" /> : <Icon size={14} />}
      {enabled ? `Disable ${label}` : `Enable ${label}`}
    </button>
  );
}

function NodeCard({
  node,
  icon: Icon,
  togglingRole,
  onToggleRelay,
  onToggleLighthouse,
  onSetLimits,
  peerDid,
}: {
  node: NodeEntry;
  icon: typeof Radio;
  togglingRole: "relay" | "lighthouse" | null;
  onToggleRelay: (node: NodeEntry) => void;
  onToggleLighthouse: (node: NodeEntry) => void;
  onSetLimits?: (node: NodeEntry) => void;
  peerDid?: string;
}) {
  const { displayForDid } = useContactNames();
  const hasRuntime = typeof node.maxBandwidthMbps === "number";
  const nodeDisplayName = displayForDid(peerDid, node.node);
  return (
    <div
      className="rounded-lg border p-4 flex flex-col gap-3"
      style={{
        backgroundColor: "var(--card)",
        borderColor: node.active ? "var(--primary)" : "var(--border)",
        borderWidth: node.active ? "2px" : "1px",
      }}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div
            className="flex items-center justify-center rounded-lg flex-shrink-0"
            style={{
              width: "40px",
              height: "40px",
              backgroundColor: node.active
                ? "color-mix(in srgb, var(--primary) 15%, transparent)"
                : "color-mix(in srgb, var(--muted-foreground) 15%, transparent)",
              color: node.active ? "var(--primary)" : "var(--muted-foreground)",
            }}
          >
            <Icon size={18} />
          </div>
          <div>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {nodeDisplayName}
            </p>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              {node.overlayIp}
            </p>
          </div>
        </div>
        <span
          className="flex items-center gap-1"
          style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: node.active ? "var(--chart-2)" : "var(--muted-foreground)" }}
        >
          {node.active ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
          {node.active ? "Active" : "Inactive"}
        </span>
      </div>

      {/* Roles */}
      <div className="flex items-center gap-2">
        <RoleBadge label="Relay" enabled={!!node.relayEnabled} icon={Radio} />
        <RoleBadge label="Lighthouse" enabled={!!node.lighthouseEnabled} icon={TowerControl} />
      </div>

      {/* Bandwidth (relay runtime nodes only) */}
      {hasRuntime && (
        <>
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                <Wifi size={12} /> Bandwidth
              </span>
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                {(node.currentMbps ?? 0).toFixed(1)} / {node.maxBandwidthMbps} Mbps
              </span>
            </div>
            <BandwidthBar current={node.currentMbps ?? 0} max={node.maxBandwidthMbps ?? 0} />
          </div>

          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              <Users size={12} /> Max Peers
            </span>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              {node.maxPeers}
            </span>
          </div>
        </>
      )}

      {/* Actions */}
      <div className="grid grid-cols-2 gap-2">
        <RoleToggleButton
          enabled={!!node.relayEnabled}
          label="Relay"
          icon={Power}
          busy={togglingRole === "relay"}
          onClick={() => onToggleRelay(node)}
        />
        <RoleToggleButton
          enabled={!!node.lighthouseEnabled}
          label="Lighthouse"
          icon={TowerControl}
          busy={togglingRole === "lighthouse"}
          onClick={() => onToggleLighthouse(node)}
        />
      </div>
      {hasRuntime && onSetLimits && (
        <button
          onClick={() => onSetLimits(node)}
          className="flex items-center justify-center gap-2 py-2 rounded-lg"
          style={{
            backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)",
            border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
            color: "var(--primary)",
            cursor: "pointer",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-medium)",
          }}
        >
          <Settings size={14} />
          Set Limits
        </button>
      )}
    </div>
  );
}

function LimitsModal({
  relay,
  onClose,
  onSave,
}: {
  relay: NodeEntry;
  onClose: () => void;
  onSave: (maxPeers: number, maxBandwidthMbps: number) => Promise<void>;
}) {
  const [maxPeers, setMaxPeers] = useState(String(relay.maxPeers ?? 1));
  const [maxBandwidth, setMaxBandwidth] = useState(String(relay.maxBandwidthMbps ?? 1));
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    await onSave(Number(maxPeers), Number(maxBandwidth));
    setSaving(false);
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") onClose();
    if (e.key === "Enter" && !saving) handleSave();
  };

  return (
    <div
      className="fixed inset-0 flex items-center justify-center z-50 p-4"
      style={{ backgroundColor: "rgba(0,0,0,0.6)", backdropFilter: "blur(2px)" }}
      onClick={onClose}
      onKeyDown={handleKey}
    >
      <div
        className="w-full flex flex-col gap-5 rounded-2xl p-6 shadow-2xl"
        style={{ backgroundColor: "var(--card)", border: "1px solid var(--border)", maxWidth: "400px" }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div
              className="flex items-center justify-center rounded-xl"
              style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", flexShrink: 0 }}
            >
              <Radio size={18} style={{ color: "var(--primary)" }} />
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Set Relay Limits
              </p>
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
                {relay.node}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex items-center justify-center rounded-lg"
            style={{ width: "32px", height: "32px", background: "none", border: "1px solid var(--border)", cursor: "pointer", color: "var(--muted-foreground)", flexShrink: 0 }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Current values */}
        <div
          className="flex items-center justify-between rounded-lg px-4 py-3"
          style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}
        >
          <div className="flex items-center gap-2">
            <Wifi size={13} style={{ color: "var(--muted-foreground)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Current</span>
          </div>
          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
            {relay.maxPeers} peers · {relay.maxBandwidthMbps} Mbps
          </span>
        </div>

        {/* Inputs */}
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                Max Peers
              </label>
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--primary)" }}>
                {maxPeers || "—"}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setMaxPeers(v => String(Math.max(1, Number(v) - 1)))}
                className="flex items-center justify-center rounded-lg flex-shrink-0"
                style={{ width: "36px", height: "36px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", cursor: "pointer", color: "var(--foreground)", fontSize: "18px", fontWeight: "bold" }}
              >
                −
              </button>
              <input
                type="number"
                min={1}
                value={maxPeers}
                onChange={e => setMaxPeers(e.target.value)}
                className="no-spinner"
                style={{
                  flex: 1, padding: "8px 12px", borderRadius: "8px",
                  border: "1px solid var(--border)", backgroundColor: "var(--background)",
                  color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace",
                  fontSize: "var(--text-sm)", outline: "none", textAlign: "center",
                }}
              />
              <button
                onClick={() => setMaxPeers(v => String(Number(v) + 1))}
                className="flex items-center justify-center rounded-lg flex-shrink-0"
                style={{ width: "36px", height: "36px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", cursor: "pointer", color: "var(--foreground)", fontSize: "18px", fontWeight: "bold" }}
              >
                +
              </button>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                Max Bandwidth
              </label>
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--primary)" }}>
                {maxBandwidth || "—"} Mbps
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setMaxBandwidth(v => String(Math.max(1, Number(v) - 1)))}
                className="flex items-center justify-center rounded-lg flex-shrink-0"
                style={{ width: "36px", height: "36px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", cursor: "pointer", color: "var(--foreground)", fontSize: "18px", fontWeight: "bold" }}
              >
                −
              </button>
              <input
                type="number"
                min={1}
                value={maxBandwidth}
                onChange={e => setMaxBandwidth(e.target.value)}
                className="no-spinner"
                style={{
                  flex: 1, padding: "8px 12px", borderRadius: "8px",
                  border: "1px solid var(--border)", backgroundColor: "var(--background)",
                  color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace",
                  fontSize: "var(--text-sm)", outline: "none", textAlign: "center",
                }}
              />
              <button
                onClick={() => setMaxBandwidth(v => String(Number(v) + 1))}
                className="flex items-center justify-center rounded-lg flex-shrink-0"
                style={{ width: "36px", height: "36px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", cursor: "pointer", color: "var(--foreground)", fontSize: "18px", fontWeight: "bold" }}
              >
                +
              </button>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3 pt-1">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl"
            style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex-1 py-2.5 rounded-xl flex items-center justify-center gap-2"
            style={{ backgroundColor: "var(--primary)", border: "none", color: "var(--primary-foreground)", cursor: saving ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", opacity: saving ? 0.7 : 1 }}
          >
            {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
            {saving ? "Saving…" : "Save Limits"}
          </button>
        </div>
      </div>

      <style>{`
        .no-spinner::-webkit-outer-spin-button,
        .no-spinner::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
        .no-spinner { -moz-appearance: textfield; }
      `}</style>
    </div>
  );
}

export function NW06RelayList() {
  const navigate = useNavigate();
  const relayData = useRelayList();
  const lighthouseData = useLighthouseList();
  const memberData = useMemberList();
  const dualData = useRelayLighthouseList();
  const didPeersData = useDIDDocumentPeers();

  const [tab, setTab] = useState<TabKey>("relays");
  const [editingRelay, setEditingRelay] = useState<NodeEntry | null>(null);
  const [toggling, setToggling] = useState<{ node: string; role: "relay" | "lighthouse" } | null>(null);
  // Per-node, per-role optimistic override. The 10s poll can race with an
  // in-flight toggle and momentarily report the pre-toggle role state, which
  // made disabled nodes "come back" on the next tick. The override keeps the
  // user's intent visible until the backend catches up (reconciled below).
  const [roleOverride, setRoleOverride] = useState<Record<string, RoleOverride>>({});
  const didByNode = new Map<string, string>();
  (didPeersData.data?.peers ?? []).forEach((peer: DIDDocumentPeerSummary) => {
    const node = peer.node_name?.trim();
    if (node && peer.did) didByNode.set(node.toLowerCase(), peer.did);
  });
  const didForNode = (node: string) => didByNode.get(node.trim().toLowerCase());

  // Older backends don't send role flags on /relay/list; presence in the
  // relay list means the relay role is on, so default relayEnabled to true.
  const baseRelays: NodeEntry[] = (relayData.data?.relays ?? []).map(r => ({
    ...r,
    relayEnabled: r.relayEnabled ?? true,
    lighthouseEnabled: r.lighthouseEnabled ?? false,
  }));
  const baseLighthouses: NodeEntry[] = lighthouseData.data?.lighthouses ?? [];
  const baseMembers: NodeEntry[] = memberData.data?.members ?? [];
  const baseDuals: NodeEntry[] = (dualData.data?.relayLighthouses ?? []).map(r => ({
    ...r,
    relayEnabled: r.relayEnabled ?? true,
    lighthouseEnabled: r.lighthouseEnabled ?? true,
  }));

  // Apply optimistic overrides on top of the backend-derived role flags.
  const applyOverride = (n: NodeEntry): NodeEntry => {
    const o = roleOverride[n.node];
    return o ? { ...n, ...o } : n;
  };
  const relays = baseRelays.map(applyOverride);
  const lighthouses = baseLighthouses.map(applyOverride);
  const members = baseMembers.map(applyOverride);
  const duals = baseDuals.map(applyOverride);

  // Look up a node's backend-reported role flags wherever it currently lives
  // (toggling a role can move a node between the four lists).
  const baseByNode: Record<string, NodeEntry> = {};
  for (const n of [...baseRelays, ...baseLighthouses, ...baseMembers, ...baseDuals]) {
    baseByNode[n.node] = n;
  }
  // Signature of polled role state; drives reconciliation when polls land.
  const baseSignature = [...baseRelays, ...baseLighthouses, ...baseMembers, ...baseDuals]
    .map(n => `${n.node}:${n.relayEnabled ? 1 : 0}${n.lighthouseEnabled ? 1 : 0}`)
    .join("|");

  // Drop each override field once the backend reflects the desired state, so
  // normal polling takes over again.
  useEffect(() => {
    setRoleOverride(prev => {
      const next: Record<string, RoleOverride> = {};
      let changed = false;
      for (const [node, desired] of Object.entries(prev)) {
        const base = baseByNode[node];
        const remaining: RoleOverride = {};
        if (desired.relayEnabled !== undefined && !(base && base.relayEnabled === desired.relayEnabled)) {
          remaining.relayEnabled = desired.relayEnabled;
        }
        if (desired.lighthouseEnabled !== undefined && !(base && base.lighthouseEnabled === desired.lighthouseEnabled)) {
          remaining.lighthouseEnabled = desired.lighthouseEnabled;
        }
        const remainingKeys = Object.keys(remaining).length;
        if (remainingKeys === 0) {
          changed = true; // fully reconciled — drop the node
          continue;
        }
        if (remainingKeys !== Object.keys(desired).length) changed = true;
        next[node] = remaining;
      }
      return changed ? next : prev;
    });
    // baseByNode is derived from baseSignature; re-run only when polls change it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [baseSignature]);

  const clearOverrideField = (node: string, field: keyof RoleOverride) => {
    setRoleOverride(prev => {
      if (!prev[node]) return prev;
      const entry = { ...prev[node] };
      delete entry[field];
      const next = { ...prev };
      if (Object.keys(entry).length === 0) delete next[node];
      else next[node] = entry;
      return next;
    });
  };

  // Toggling a role can move a node between the four lists, so refresh all.
  const refetchAll = async () => {
    await Promise.all([
      relayData.refetch(),
      lighthouseData.refetch(),
      memberData.refetch(),
      dualData.refetch(),
    ]);
  };

  const handleToggle = async (node: NodeEntry, role: "relay" | "lighthouse") => {
    const current = role === "relay" ? !!node.relayEnabled : !!node.lighthouseEnabled;
    const desired = !current;
    const label = role === "relay" ? "Relay" : "Lighthouse";
    const field: keyof RoleOverride = role === "relay" ? "relayEnabled" : "lighthouseEnabled";
    setToggling({ node: node.node, role });
    // Optimistically reflect the user's intent so the next poll can't flip the
    // role back before the write has propagated on the backend.
    setRoleOverride(prev => ({ ...prev, [node.node]: { ...prev[node.node], [field]: desired } }));
    try {
      const result =
        role === "relay"
          ? await relayService.toggle(node.node, desired)
          : await relayService.toggleLighthouse(node.node, desired);
      if (result.ok) {
        toast.success(result.enabled ? `${label} enabled` : `${label} disabled`, {
          description: result.message,
        });
        // Trust the toggle response; keep the override until polled data
        // confirms it (handled by the reconciliation effect above).
        setRoleOverride(prev => ({ ...prev, [node.node]: { ...prev[node.node], [field]: result.enabled } }));
        await refetchAll();
      } else {
        toast.error(`Failed to update ${label.toLowerCase()} state`);
        clearOverrideField(node.node, field);
      }
    } catch (err) {
      toast.error(`Failed to toggle ${label.toLowerCase()}`, {
        description: err instanceof Error ? err.message : undefined,
      });
      clearOverrideField(node.node, field);
    } finally {
      setToggling(null);
    }
  };

  const handleSetLimits = async (maxPeers: number, maxBandwidthMbps: number) => {
    if (!editingRelay) return;
    try {
      const result = await relayService.setLimits(editingRelay.node, maxPeers, maxBandwidthMbps);
      if (result.ok) {
        toast.success("Limits updated", {
          description: `${editingRelay.node}: ${maxPeers} peers · ${maxBandwidthMbps} Mbps${result.pcrSafe ? "" : " (PCR check required)"}`,
        });
        await refetchAll();
      } else {
        toast.error("Failed to update limits");
      }
    } catch {
      toast.error("Failed to update relay limits");
    }
    setEditingRelay(null);
  };

  if (relayData.loading && lighthouseData.loading && memberData.loading && dualData.loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  const listByTab: Record<TabKey, { nodes: NodeEntry[]; icon: typeof Radio; empty: string; heading: string }> = {
    relays: { nodes: relays, icon: Radio, empty: "No relay nodes found", heading: "RELAY NODES" },
    lighthouses: { nodes: lighthouses, icon: TowerControl, empty: "No lighthouse nodes found", heading: "LIGHTHOUSE NODES" },
    members: { nodes: members, icon: Server, empty: "No member nodes found", heading: "MEMBER NODES" },
    dual: { nodes: duals, icon: Wifi, empty: "No relay + lighthouse nodes found", heading: "RELAY + LIGHTHOUSE NODES" },
  };
  const current = listByTab[tab];

  const stats: { label: string; count: number; icon: typeof Radio; color: string }[] = [
    { label: "Relays", count: relays.length, icon: Radio, color: "var(--primary)" },
    { label: "Lighthouses", count: lighthouses.length, icon: TowerControl, color: "var(--chart-4)" },
    { label: "Members", count: members.length, icon: Server, color: "var(--muted-foreground)" },
    { label: "Relay + LH", count: duals.length, icon: Wifi, color: "var(--chart-2)" },
  ];

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Network Nodes" subtitle="Relay & Lighthouse Management" onBack={() => navigate("/network")} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-4xl p-4 md:p-6 flex flex-col gap-4">
        {/* Stats */}
        <div className="grid grid-cols-4 gap-2">
          {stats.map(s => (
            <div key={s.label} className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
              <s.icon size={16} style={{ color: s.color, margin: "0 auto 6px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>
                {s.count}
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{s.label}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div
          className="grid grid-cols-4 gap-1 rounded-lg p-1"
          style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}
        >
          {TABS.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className="flex items-center justify-center gap-1.5 py-2 rounded-md"
              style={{
                backgroundColor: tab === t.key ? "var(--card)" : "transparent",
                border: tab === t.key ? "1px solid var(--border)" : "1px solid transparent",
                color: tab === t.key ? "var(--foreground)" : "var(--muted-foreground)",
                cursor: "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)",
              }}
            >
              <t.icon size={13} />
              {t.label}
            </button>
          ))}
        </div>

        {/* Node List */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "12px" }}>
            {current.heading}
          </p>
          <div className="flex flex-col gap-3">
            {current.nodes.length === 0 ? (
              <div className="rounded-lg border p-6 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
                <current.icon size={32} style={{ color: "var(--muted-foreground)", margin: "0 auto 12px" }} />
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                  {current.empty}
                </p>
              </div>
            ) : (
              current.nodes.map(node => (
                <NodeCard
                  key={node.node}
                  node={node}
                  icon={current.icon}
                  togglingRole={toggling?.node === node.node ? toggling.role : null}
                  onToggleRelay={n => handleToggle(n, "relay")}
                  onToggleLighthouse={n => handleToggle(n, "lighthouse")}
                  onSetLimits={setEditingRelay}
                  peerDid={didForNode(node.node)}
                />
              ))
            )}
          </div>
        </div>
        </div>
      </div>

      {editingRelay && (
        <LimitsModal
          relay={editingRelay}
          onClose={() => setEditingRelay(null)}
          onSave={handleSetLimits}
        />
      )}

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
