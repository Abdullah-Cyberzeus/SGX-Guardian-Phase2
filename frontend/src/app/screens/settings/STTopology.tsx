import { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { mockGuardian, mockDevices } from "../../data/mockData";
import { X, AlertTriangle, ChevronRight, Ban, Users, UserPlus, Loader2 } from "lucide-react";
import { useGuardianInfo, useDevices } from "../../hooks/useApiData";

interface Node {
  id: string;
  label: string;
  did?: string;
  online: boolean;
  isCenter?: boolean;
  isUnknown?: boolean;
  isSecondaryGuardian?: boolean;
  securityScore?: number;
  ip?: string;
}

export type TopologyScenario = "default" | "solo" | "large" | "dual-guardian";

// ── Static secondary guardian node ────────────────────────────────────────────
const secondGuardian: Node = {
  id: "guardian-2",
  label: "Guardian-TX-099",
  online: true,
  isCenter: false,
  isSecondaryGuardian: true,
  securityScore: 91,
  ip: "192.168.1.105",
};

function getNodePosition(index: number, total: number, radius: number, cx: number, cy: number) {
  const angle = (index / total) * 2 * Math.PI - Math.PI / 2;
  return { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
}

// ── Embeddable topology canvas (legacy radial — used inside Settings only) ─────
function STTopologyCanvas({ scenario = "default" }: { scenario?: TopologyScenario }) {
  const navigate = useNavigate();
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [blockConfirm, setBlockConfirm] = useState(false);
  const [showMore, setShowMore] = useState(false);

  // Fetch data from API with fallback to mock data
  const { data: guardianData, loading: guardianLoading } = useGuardianInfo();
  const { data: devicesData, loading: devicesLoading } = useDevices();

  const guardian = useMemo(() => {
    return guardianData || mockGuardian;
  }, [guardianData]);

  const devices = useMemo(() => {
    if (!devicesData) return mockDevices;
    return devicesData.devices || mockDevices;
  }, [devicesData]);

  // Compute nodes dynamically from API data
  const centerNode: Node = useMemo(() => ({
    id: "guardian",
    label: guardian.name || mockGuardian.name,
    online: true,
    isCenter: true,
    securityScore: 85,
    ip: guardian.ip || mockGuardian.ip,
  }), [guardian]);

  const defaultPeers: Node[] = useMemo(() => {
    return devices
      .filter((d: any) => d.status === "online" || d.id !== "dev_005")
      .map((d: any) => ({
        id: d.id,
        label: d.name,
        online: d.status === "online",
        isUnknown: d.category === "pending" || d.manufacturer === "Unknown",
        securityScore: d.securityScore,
        ip: d.ip,
      }));
  }, [devices]);

  const largePeers: Node[] = useMemo(() => [
    ...defaultPeers,
    { id: "peer-e", label: "HMI-Terminal-01", online: true, securityScore: 77, ip: "10.0.6.11" },
    { id: "peer-f", label: "RTU-Sensor-04", online: false, securityScore: 60, ip: "10.0.7.22" },
    { id: "peer-g", label: "Historian-Server", online: true, securityScore: 88, ip: "10.0.8.33" },
    { id: "peer-h", label: "Switch-Core-01", online: true, securityScore: 95, ip: "10.0.9.44" },
  ], [defaultPeers]);

  const dualPeers: Node[] = useMemo(() => defaultPeers.slice(0, 3), [defaultPeers]);

  const loading = guardianLoading || devicesLoading;

  const svgSize = 340;
  const cx = svgSize / 2;
  const cy = svgSize / 2;
  const radius = 110;
  const MAX_VISIBLE = 6;

  // Show loading state
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-8" style={{ flex: 1 }}>
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: "var(--primary)" }} />
      </div>
    );
  }

  const handleNodeTap = (node: Node, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedNode(selectedNode?.id === node.id ? null : node);
    setBlockConfirm(false);
  };

  const scoreLabel = (s?: number) => {
    if (s === undefined || s === 0) return "Unknown";
    if (s >= 80) return "Secure";
    if (s >= 50) return "Moderate";
    return "Critical";
  };
  const scoreColor = (s?: number) => {
    if (!s) return "var(--chart-5)";
    if (s >= 80) return "var(--chart-2)";
    if (s >= 50) return "var(--chart-5)";
    return "var(--destructive)";
  };

  // ── Solo scenario ──────────────────────────────────────────────────────────
  if (scenario === "solo") {
    return (
      <div className="flex flex-col items-center p-4" style={{ flex: 1 }}>
        <div className="w-full rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)", maxWidth: "500px" }}>
          <div className="relative" style={{ touchAction: "manipulation" }}>
            <svg width="100%" viewBox={`0 0 ${svgSize} ${svgSize}`} style={{ display: "block" }}>
              {/* Dashed ring suggesting where peers will appear */}
              <circle
                cx={cx} cy={cy} r={radius}
                fill="none"
                stroke="var(--border)"
                strokeWidth="1.5"
                strokeDasharray="6 5"
                opacity={0.6}
              />
              {/* Center Guardian node */}
              <g style={{ cursor: "default" }}>
                <circle cx={cx} cy={cy} r={32} fill="color-mix(in srgb, var(--primary) 18%, transparent)" stroke="var(--primary)" strokeWidth="2" />
                <circle cx={cx} cy={cy} r={22} fill="var(--primary)" />
                <text x={cx} y={cy + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", fontWeight: 700, fill: "var(--primary-foreground)" }}>
                  GX
                </text>
                <text x={cx} y={cy + 50} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fill: "var(--foreground)", fontWeight: 600 }}>
                  {guardian.name}
                </text>
                <text x={cx} y={cy + 63} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fill: "var(--primary)", fontWeight: 600, letterSpacing: "0.04em" }}>
                  You
                </text>
              </g>
            </svg>
          </div>
        </div>

        {/* Empty state message */}
        <div className="flex flex-col items-center gap-3 mt-6 text-center px-4">
          <div
            className="rounded-full flex items-center justify-center"
            style={{ width: "56px", height: "56px", backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)" }}
          >
            <Users size={24} style={{ color: "var(--primary)" }} />
          </div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
            Your Circle of Trust is empty
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6, maxWidth: "240px" }}>
            Invite members to see your network topology.
          </p>
          <button
            onClick={() => navigate("/network")}
            className="flex items-center gap-2 px-5 rounded-md transition-opacity active:opacity-80 mt-1"
            style={{
              height: "44px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
              border: "none", cursor: "pointer", borderRadius: "var(--radius)",
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)",
            }}
          >
            <UserPlus size={15} />
            Invite Member
          </button>
        </div>
      </div>
    );
  }

  // ── Large scenario ─────────────────────────────────────────────────────────
  if (scenario === "large") {
    const visiblePeers = largePeers.slice(0, MAX_VISIBLE);
    const hiddenCount = largePeers.length - MAX_VISIBLE;

    return (
      <div className="flex flex-col items-center p-4" style={{ flex: 1 }}>
        <div
          className="w-full rounded-lg border border-border overflow-hidden"
          style={{ backgroundColor: "var(--card)", maxWidth: "500px" }}
        >
          {/* Legend */}
          <div className="flex items-center gap-4 px-4 py-3 border-b border-border">
            {[
              { color: "var(--primary)", label: "Guardian" },
              { color: "var(--chart-2)", label: "Online" },
              { color: "var(--chart-5)", label: "Unknown" },
              { color: "var(--muted-foreground)", label: "Offline" },
            ].map(({ color, label }) => (
              <div key={label} className="flex items-center gap-1.5">
                <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: color }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
              </div>
            ))}
          </div>

          <div className="relative" style={{ touchAction: "manipulation" }} onClick={() => setSelectedNode(null)}>
            <svg width="100%" viewBox={`0 0 ${svgSize} ${svgSize}`} style={{ display: "block" }}>
              {/* Connection lines for visible peers */}
              {visiblePeers.map((node, i) => {
                const total = MAX_VISIBLE + (hiddenCount > 0 ? 1 : 0);
                const pos = getNodePosition(i, total, radius, cx, cy);
                return (
                  <line key={node.id}
                    x1={cx} y1={cy} x2={pos.x} y2={pos.y}
                    stroke={node.isUnknown ? "color-mix(in srgb, var(--chart-5) 60%, transparent)" : node.online ? "var(--border)" : "color-mix(in srgb, var(--border) 50%, transparent)"}
                    strokeWidth="1.5"
                    strokeDasharray={node.online ? "0" : "4 3"}
                  />
                );
              })}
              {/* "+N more" slot line */}
              {hiddenCount > 0 && (() => {
                const total = MAX_VISIBLE + 1;
                const pos = getNodePosition(MAX_VISIBLE, total, radius, cx, cy);
                return <line x1={cx} y1={cy} x2={pos.x} y2={pos.y} stroke="var(--border)" strokeWidth="1" strokeDasharray="3 3" opacity={0.5} />;
              })()}

              {/* Center Guardian */}
              <g onClick={(e) => handleNodeTap(centerNode, e)} style={{ cursor: "pointer" }}>
                <circle cx={cx} cy={cy} r={28} fill="color-mix(in srgb, var(--primary) 18%, transparent)" stroke="var(--primary)" strokeWidth="2" />
                <circle cx={cx} cy={cy} r={18} fill="var(--primary)" />
                <text x={cx} y={cy + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", fontWeight: 700, fill: "var(--primary-foreground)" }}>GX</text>
                <text x={cx} y={cy + 44} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fill: "var(--foreground)", fontWeight: 600 }}>
                  {guardian.name}
                </text>
              </g>

              {/* Visible peer nodes */}
              {visiblePeers.map((node, i) => {
                const total = MAX_VISIBLE + (hiddenCount > 0 ? 1 : 0);
                const pos = getNodePosition(i, total, radius, cx, cy);
                const initials = node.label.substring(0, 2).toUpperCase();
                const nodeColor = node.isUnknown ? "var(--chart-5)" : node.online ? "var(--chart-2)" : "var(--border)";
                return (
                  <g key={node.id} onClick={(e) => handleNodeTap(node, e)} style={{ cursor: "pointer" }}>
                    {node.isUnknown && (
                      <circle cx={pos.x} cy={pos.y} r={26} fill="none"
                        stroke="color-mix(in srgb, var(--chart-5) 55%, transparent)" strokeWidth="2.5" strokeDasharray="3 2" />
                    )}
                    <circle cx={pos.x} cy={pos.y} r={20}
                      fill={node.isUnknown ? "color-mix(in srgb, var(--chart-5) 18%, var(--muted))" : "var(--muted)"}
                      stroke={nodeColor} strokeWidth={node.isUnknown ? "2" : "1.5"} />
                    {node.isUnknown ? (
                      <>
                        <polygon
                          points={`${pos.x + 14},${pos.y - 20} ${pos.x + 8},${pos.y - 9} ${pos.x + 20},${pos.y - 9}`}
                          fill="var(--chart-5)" stroke="var(--card)" strokeWidth="1.5"
                        />
                        <text x={pos.x + 14} y={pos.y - 12} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "7px", fontWeight: 700, fill: "var(--background)" }}>!</text>
                        <text x={pos.x} y={pos.y + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", fill: "var(--chart-5)", fontWeight: 700 }}>?</text>
                      </>
                    ) : (
                      <>
                        <circle cx={pos.x + 13} cy={pos.y - 13} r={5} fill={nodeColor} stroke="var(--card)" strokeWidth="1.5" />
                        <text x={pos.x} y={pos.y + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fontWeight: 600, fill: "var(--foreground)" }}>{initials}</text>
                      </>
                    )}
                    <text x={pos.x} y={pos.y + 34} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fill: node.isUnknown ? "var(--chart-5)" : "var(--muted-foreground)" }}>
                      {node.label.length > 16 ? node.label.substring(0, 16) + "…" : node.label}
                    </text>
                  </g>
                );
              })}

              {/* "+N more" ghost node */}
              {hiddenCount > 0 && (() => {
                const total = MAX_VISIBLE + 1;
                const pos = getNodePosition(MAX_VISIBLE, total, radius, cx, cy);
                return (
                  <g onClick={(e) => { e.stopPropagation(); setShowMore(true); }} style={{ cursor: "pointer" }}>
                    <circle cx={pos.x} cy={pos.y} r={20} fill="var(--muted)" stroke="var(--border)" strokeWidth="1.5" strokeDasharray="4 3" />
                    <text x={pos.x} y={pos.y + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fontWeight: 700, fill: "var(--muted-foreground)" }}>
                      +{hiddenCount}
                    </text>
                    <text x={pos.x} y={pos.y + 34} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fill: "var(--muted-foreground)" }}>
                      more
                    </text>
                  </g>
                );
              })()}
            </svg>
          </div>
        </div>

        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "12px", textAlign: "center" }}>
          {largePeers.filter((n) => n.online).length} of {largePeers.length} peers online · Tap a node for details
        </p>

        {/* Show more sheet */}
        {showMore && (
          <div
            className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer"
            style={{ backgroundColor: "rgba(0,0,0,0.5)", maxWidth: "440px", margin: "0 auto" }}
            onClick={() => setShowMore(false)}
          >
            <div className="w-full rounded-t-2xl md:rounded-2xl border-t md:border border-border" style={{ backgroundColor: "var(--card)", maxHeight: "50dvh", display: "flex", flexDirection: "column" }} onClick={(e) => e.stopPropagation()}>
              <div className="flex justify-center pt-3 pb-1 md:hidden">
                <div style={{ width: "36px", height: "4px", borderRadius: "2px", backgroundColor: "var(--border)" }} />
              </div>
              <div className="px-5 pb-2 flex items-center justify-between">
                <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                  {hiddenCount} more peers
                </h3>
                <button onClick={() => setShowMore(false)} style={{ background: "none", border: "none", cursor: "pointer" }}>
                  <X size={18} style={{ color: "var(--muted-foreground)" }} />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto px-5 pb-6">
                {largePeers.slice(MAX_VISIBLE).map((node) => (
                  <div key={node.id} className="flex items-center gap-3 py-3 border-b border-border">
                    <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: node.online ? "var(--chart-2)" : "var(--muted-foreground)", flexShrink: 0 }} />
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>{node.label}</span>
                    {node.ip && <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", marginLeft: "auto" }}>{node.ip}</span>}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Node detail sheet */}
        {selectedNode && (
          <NodeDetailSheet
            node={selectedNode}
            onClose={() => { setSelectedNode(null); setBlockConfirm(false); }}
            blockConfirm={blockConfirm}
            setBlockConfirm={setBlockConfirm}
            scoreLabel={scoreLabel}
            scoreColor={scoreColor}
          />
        )}
      </div>
    );
  }

  // ── Dual Guardian scenario ─────────────────────────────────────────────────
  if (scenario === "dual-guardian") {
    const peers = dualPeers;
    const allNodes = [secondGuardian, ...peers];

    return (
      <div className="flex flex-col items-center p-4" style={{ flex: 1 }}>
        <div
          className="w-full rounded-lg border border-border overflow-hidden"
          style={{ backgroundColor: "var(--card)", maxWidth: "500px" }}
        >
          {/* Legend */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border flex-wrap">
            {[
              { color: "var(--primary)", label: "Your Guardian", solid: true },
              { color: "var(--primary)", label: "Partner Guardian", solid: false },
              { color: "var(--chart-2)", label: "Online" },
              { color: "var(--muted-foreground)", label: "Offline" },
            ].map(({ color, label, solid }) => (
              <div key={label} className="flex items-center gap-1.5">
                <div style={{
                  width: "8px", height: "8px", borderRadius: "50%",
                  backgroundColor: solid === false ? "transparent" : color,
                  border: solid === false ? `2px solid ${color}` : undefined,
                }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
              </div>
            ))}
          </div>

          <div className="relative" style={{ touchAction: "manipulation" }} onClick={() => setSelectedNode(null)}>
            <svg width="100%" viewBox={`0 0 ${svgSize} ${svgSize}`} style={{ display: "block" }}>
              {/* Lines from center to all peers */}
              {allNodes.map((node, i) => {
                const pos = getNodePosition(i, allNodes.length, radius, cx, cy);
                return (
                  <line key={node.id} x1={cx} y1={cy} x2={pos.x} y2={pos.y}
                    stroke={node.isSecondaryGuardian ? "color-mix(in srgb, var(--primary) 50%, transparent)" : node.online ? "var(--border)" : "color-mix(in srgb, var(--border) 50%, transparent)"}
                    strokeWidth={node.isSecondaryGuardian ? "2" : "1.5"}
                    strokeDasharray={!node.online ? "4 3" : "0"}
                  />
                );
              })}

              {/* Center (your Guardian) — solid purple */}
              <g onClick={(e) => handleNodeTap(centerNode, e)} style={{ cursor: "pointer" }}>
                <circle cx={cx} cy={cy} r={28} fill="color-mix(in srgb, var(--primary) 18%, transparent)" stroke="var(--primary)" strokeWidth="2.5" />
                <circle cx={cx} cy={cy} r={18} fill="var(--primary)" />
                <text x={cx} y={cy + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", fontWeight: 700, fill: "var(--primary-foreground)" }}>GX</text>
                <text x={cx} y={cy + 44} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fill: "var(--primary)", fontWeight: 700 }}>You</text>
              </g>

              {/* Peer nodes including second guardian */}
              {allNodes.map((node, i) => {
                const pos = getNodePosition(i, allNodes.length, radius, cx, cy);
                const isG2 = node.isSecondaryGuardian;
                const nodeColor = isG2 ? "var(--primary)" : node.online ? "var(--chart-2)" : "var(--border)";
                const initials = isG2 ? "GX" : node.label.substring(0, 2).toUpperCase();
                return (
                  <g key={node.id} onClick={(e) => handleNodeTap(node, e)} style={{ cursor: "pointer" }}>
                    {/* Second guardian: outlined ring */}
                    {isG2 && (
                      <circle cx={pos.x} cy={pos.y} r={24} fill="none" stroke="color-mix(in srgb, var(--primary) 30%, transparent)" strokeWidth="2" strokeDasharray="0" />
                    )}
                    <circle cx={pos.x} cy={pos.y} r={20}
                      fill={isG2 ? "transparent" : "var(--muted)"}
                      stroke={nodeColor}
                      strokeWidth={isG2 ? "2.5" : "1.5"}
                    />
                    <circle cx={pos.x + 13} cy={pos.y - 13} r={5} fill={isG2 ? "var(--primary)" : nodeColor} stroke="var(--card)" strokeWidth="1.5" />
                    <text x={pos.x} y={pos.y + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: isG2 ? "10px" : "9px", fontWeight: isG2 ? 700 : 600, fill: isG2 ? "var(--primary)" : "var(--foreground)" }}>
                      {initials}
                    </text>
                    <text x={pos.x} y={pos.y + 34} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fill: isG2 ? "var(--primary)" : "var(--muted-foreground)" }}>
                      {node.label.length > 12 ? node.label.substring(0, 12) + "…" : node.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "12px", textAlign: "center" }}>
          2 Guardians · {[...peers].filter((n) => n.online).length + 1} peers online · Tap a node for details
        </p>

        {selectedNode && (
          <NodeDetailSheet
            node={selectedNode}
            onClose={() => { setSelectedNode(null); setBlockConfirm(false); }}
            blockConfirm={blockConfirm}
            setBlockConfirm={setBlockConfirm}
            scoreLabel={scoreLabel}
            scoreColor={scoreColor}
          />
        )}
      </div>
    );
  }

  // ── Default scenario ───────────────────────────────────────────────────────
  const peerNodes = defaultPeers;

  return (
    <div className="flex flex-col items-center p-4" style={{ flex: 1 }}>
      <div
        className="w-full rounded-lg border border-border overflow-hidden relative"
        style={{ backgroundColor: "var(--card)", maxWidth: "500px" }}
      >
        {/* Legend */}
        <div className="flex items-center gap-4 px-4 py-3 border-b border-border">
          {[
            { color: "var(--primary)", label: "Guardian" },
            { color: "var(--chart-2)", label: "Online" },
            { color: "var(--chart-5)", label: "Unknown" },
            { color: "var(--muted-foreground)", label: "Offline" },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-1.5">
              <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: color }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</span>
            </div>
          ))}
        </div>

        <div className="relative" style={{ touchAction: "manipulation" }} onClick={() => setSelectedNode(null)}>
          <svg width="100%" viewBox={`0 0 ${svgSize} ${svgSize}`} style={{ display: "block" }}>
            {peerNodes.map((node, i) => {
              const pos = getNodePosition(i, peerNodes.length, radius, cx, cy);
              return (
                <g key={node.id}>
                  <line x1={cx} y1={cy} x2={pos.x} y2={pos.y}
                    stroke={node.isUnknown ? "color-mix(in srgb, var(--chart-5) 60%, transparent)" : node.online ? "var(--border)" : "color-mix(in srgb, var(--border) 50%, transparent)"}
                    strokeWidth="1.5" strokeDasharray={node.online ? "0" : "4 3"}
                  />
                  <text x={(cx + pos.x) / 2} y={(cy + pos.y) / 2 - 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fill: "var(--muted-foreground)" }}>
                    WiFi
                  </text>
                </g>
              );
            })}

            <g onClick={(e) => handleNodeTap(centerNode, e)} style={{ cursor: "pointer" }}>
              <circle cx={cx} cy={cy} r={28} fill="color-mix(in srgb, var(--primary) 18%, transparent)" stroke="var(--primary)" strokeWidth="2" />
              <circle cx={cx} cy={cy} r={18} fill="var(--primary)" />
              <text x={cx} y={cy + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", fontWeight: 700, fill: "var(--primary-foreground)" }}>GX</text>
              <text x={cx} y={cy + 44} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fill: "var(--foreground)", fontWeight: 600 }}>
                {guardian.name}
              </text>
            </g>

            {peerNodes.map((node, i) => {
              const pos = getNodePosition(i, peerNodes.length, radius, cx, cy);
              const initials = node.label.substring(0, 2).toUpperCase();
              const nodeColor = node.isUnknown ? "var(--chart-5)" : node.online ? "var(--chart-2)" : "var(--border)";
              return (
                <g key={node.id} onClick={(e) => handleNodeTap(node, e)} style={{ cursor: "pointer" }}>
                  {node.isUnknown && (
                    <circle cx={pos.x} cy={pos.y} r={26} fill="none"
                      stroke="color-mix(in srgb, var(--chart-5) 55%, transparent)" strokeWidth="2.5" strokeDasharray="3 2" />
                  )}
                  <circle cx={pos.x} cy={pos.y} r={20}
                    fill={node.isUnknown ? "color-mix(in srgb, var(--chart-5) 18%, var(--muted))" : "var(--muted)"}
                    stroke={nodeColor} strokeWidth={node.isUnknown ? "2" : "1.5"} />
                  {node.isUnknown ? (
                    <>
                      <polygon
                        points={`${pos.x + 14},${pos.y - 20} ${pos.x + 8},${pos.y - 9} ${pos.x + 20},${pos.y - 9}`}
                        fill="var(--chart-5)" stroke="var(--card)" strokeWidth="1.5"
                      />
                      <text x={pos.x + 14} y={pos.y - 12} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "7px", fontWeight: 700, fill: "var(--background)" }}>!</text>
                      <text x={pos.x} y={pos.y + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", fill: "var(--chart-5)", fontWeight: 700 }}>?</text>
                    </>
                  ) : (
                    <>
                      <circle cx={pos.x + 13} cy={pos.y - 13} r={5} fill={nodeColor} stroke="var(--card)" strokeWidth="1.5" />
                      <text x={pos.x} y={pos.y + 4} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fontWeight: 600, fill: "var(--foreground)" }}>{initials}</text>
                    </>
                  )}
                  <text x={pos.x} y={pos.y + 34} textAnchor="middle" style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fill: node.isUnknown ? "var(--chart-5)" : "var(--muted-foreground)" }}>
                    {node.label.length > 16 ? node.label.substring(0, 16) + "…" : node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      </div>

      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "12px", textAlign: "center" }}>
        {peerNodes.filter((n) => n.online).length} of {peerNodes.length} peers online · Tap a node for details
      </p>

      {selectedNode && (
        <NodeDetailSheet
          node={selectedNode}
          onClose={() => { setSelectedNode(null); setBlockConfirm(false); }}
          blockConfirm={blockConfirm}
          setBlockConfirm={setBlockConfirm}
          scoreLabel={scoreLabel}
          scoreColor={scoreColor}
        />
      )}
    </div>
  );
}

// ── Shared node detail bottom sheet ──────────────────────────────────────────
function NodeDetailSheet({
  node, onClose, blockConfirm, setBlockConfirm, scoreLabel, scoreColor,
}: {
  node: Node;
  onClose: () => void;
  blockConfirm: boolean;
  setBlockConfirm: (v: boolean) => void;
  scoreLabel: (s?: number) => string;
  scoreColor: (s?: number) => string;
}) {
  const navigate = useNavigate();
  return (
    <div
      className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer"
      style={{ backgroundColor: "rgba(0,0,0,0.5)", maxWidth: "440px", margin: "0 auto" }}
      onClick={onClose}
    >
      <div
        className="w-full rounded-t-2xl md:rounded-2xl border-t md:border border-border"
        style={{ backgroundColor: "var(--card)", maxHeight: "50dvh", display: "flex", flexDirection: "column" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-center pt-3 pb-1 md:hidden">
          <div style={{ width: "36px", height: "4px", borderRadius: "2px", backgroundColor: "var(--border)" }} />
        </div>

        <div className="px-5 pb-2 flex items-center justify-between">
          <div className="flex items-center gap-2">
            {node.isUnknown && <AlertTriangle size={15} style={{ color: "var(--chart-5)" }} />}
            {node.isSecondaryGuardian && <div style={{ width: "8px", height: "8px", borderRadius: "50%", border: "2px solid var(--primary)", flexShrink: 0 }} />}
            <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: node.isUnknown ? "var(--chart-5)" : node.isSecondaryGuardian ? "var(--primary)" : "var(--foreground)" }}>
              {node.label}
            </h3>
            {node.isSecondaryGuardian && (
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--primary)", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", padding: "1px 6px", borderRadius: "var(--radius-sm)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}>
                Guardian
              </span>
            )}
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer" }}>
            <X size={18} style={{ color: "var(--muted-foreground)" }} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 pb-6">
          <div className="flex items-center gap-3 mb-4">
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: node.isUnknown ? "var(--chart-5)" : node.online ? "var(--chart-2)" : "var(--muted-foreground)", flexShrink: 0 }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
              {node.isUnknown ? "Unknown device — unverified" : node.online ? "Online" : "Offline"}
            </span>
            {node.ip && (
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginLeft: "auto" }}>
                {node.ip}
              </span>
            )}
          </div>

          {!node.isCenter && (
            <div className="flex items-center justify-between mb-5 p-3 rounded-lg" style={{ backgroundColor: "var(--muted)" }}>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Security Score</span>
              <div className="flex items-center gap-1.5">
                <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: scoreColor(node.securityScore) }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: scoreColor(node.securityScore) }}>
                  {node.securityScore || "—"} · {scoreLabel(node.securityScore)}
                </span>
              </div>
            </div>
          )}

          {!blockConfirm ? (
            <div className="flex gap-3">
              {!node.isCenter && (
                <button
                  onClick={() => navigate(node.isSecondaryGuardian ? `/home/guardian` : `/devices/${node.id}`)}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                  style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
                >
                  <ChevronRight size={16} /> {node.isSecondaryGuardian ? "View Guardian" : "View Device"}
                </button>
              )}
              {!node.isCenter && !node.isSecondaryGuardian && (
                <button
                  onClick={() => setBlockConfirm(true)}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                  style={{ height: "48px", backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)", color: "var(--destructive)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
                >
                  <Ban size={16} /> Block
                </button>
              )}
              {node.isCenter && (
                <button
                  onClick={() => navigate("/home/guardian")}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                  style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
                >
                  <ChevronRight size={16} /> View Guardian
                </button>
              )}
            </div>
          ) : (
            <div className="rounded-lg border p-4 flex flex-col gap-3" style={{ borderColor: "color-mix(in srgb, var(--destructive) 30%, transparent)", backgroundColor: "color-mix(in srgb, var(--destructive) 6%, var(--card))" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Block {node.label}?</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>This will immediately revoke network access for this device.</p>
              <div className="flex gap-2">
                <button onClick={() => setBlockConfirm(false)} className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "40px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }}>Cancel</button>
                <button onClick={onClose} className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "40px", backgroundColor: "var(--destructive)", color: "var(--destructive-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}>Block Device</button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Full-page screen ──────────────────────────────────────────
export function STTopology() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Network Topology" />
      <STTopologyCanvas />
    </div>
  );
}
