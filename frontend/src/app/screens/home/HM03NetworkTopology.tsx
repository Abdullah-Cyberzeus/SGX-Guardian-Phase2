import { PageHeader } from "../../components/PageHeader";
import { EnterpriseTopology } from "../../components/topology/EnterpriseTopology";

/** Kept for backward compat — NW01CirclesList and NW04CircleDetail still
 *  import { TopologyCanvas }. The old per-circle SVG is replaced with the
 *  enterprise scene; the optional `scenario` prop is accepted but ignored. */
export type TopologyScenario = "default" | "solo" | "large" | "dual-guardian";

export function TopologyCanvas(_: { scenario?: TopologyScenario } = {}) {
  // Fills its parent. NW01 right rail and NW04 tab both wrap us in a vertical
  // flex/overflow region with no explicit height — so use height: 100%.
  return (
    <div style={{ width: "100%", height: "100%", minHeight: 420, position: "relative" }}>
      <EnterpriseTopology variant="embed" />
    </div>
  );
}

export function HM03NetworkTopology() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Network Topology" />

      <div
        className="flex items-center px-4 md:px-6 py-2 border-b border-border"
        style={{ backgroundColor: "var(--card)", flexShrink: 0 }}
      >
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          Tap nodes for details · Drag to pan · Scroll to zoom · Use the maximise icon for full view
        </p>
      </div>

      <div style={{ flex: 1, position: "relative", minHeight: 0 }}>
        <EnterpriseTopology />
      </div>
    </div>
  );
}
