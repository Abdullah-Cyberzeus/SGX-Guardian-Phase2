import { Minus, Plus, RotateCcw, Maximize2, X } from "lucide-react";
import logoUrl from "../../../assets/sgx-guardian-logo.png";

export type FilterMode =
  | "all" | "trusted" | "shared" | "threats" | "offline"
  | "alpha" | "bravo" | "charlie" | "delta";

type StatPill = { id: FilterMode; cls: string; num: number; label: string };
type ZonePill = { id: FilterMode; cls: string; label: string };

const PILLS: StatPill[] = [
  { id: "all", cls: "guard", num: 4, label: "Guardians" },
  { id: "trusted", cls: "dev", num: 159, label: "Devices" },
  { id: "shared", cls: "share", num: 5, label: "Shared" },
  { id: "threats", cls: "threat", num: 2, label: "Threats" },
  { id: "offline", cls: "offline", num: 6, label: "Offline" },
];

const ZONE_PILLS: ZonePill[] = [
  { id: "alpha", cls: "alpha", label: "Alpha" },
  { id: "bravo", cls: "bravo", label: "Bravo" },
  { id: "charlie", cls: "charlie", label: "Charlie" },
  { id: "delta", cls: "delta", label: "Delta" },
];

export function TopologyTopBar({
  filter, onFilter, zoomPct, onZoomIn, onZoomOut, onReset, fullscreen, onToggleFullscreen,
}: {
  filter: FilterMode;
  onFilter: (f: FilterMode) => void;
  zoomPct: number;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onReset: () => void;
  fullscreen: boolean;
  onToggleFullscreen: () => void;
}) {
  const toggle = (f: FilterMode) => onFilter(filter === f ? "all" : f);
  const isActive = (f: FilterMode) => filter === f;

  return (
    <header className="topo-topbar" onClick={(e) => e.stopPropagation()}>
      <div className="topo-brand-lock">
        <img className="topo-shield" src={logoUrl} alt="SG-X Guardian" width={28} height={28} />
        <div className="topo-brand-txt">
          <div className="topo-brand-name">SG-X GUARDIAN</div>
          <div className="topo-brand-tag">Defend · Protect · Secure</div>
        </div>
      </div>

      <div className="topo-crumb">
        <span>OPS-CENTER · TIER-1</span>
      </div>

      <div className="topo-pill-row">
        {PILLS.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`topo-pill topo-pill-filter ${p.cls}${p.cls === "threat" ? " threat" : ""}`}
            data-active={isActive(p.id) ? "true" : "false"}
            onClick={() => toggle(p.id)}
            aria-pressed={isActive(p.id)}
          >
            <span className="topo-dot" />
            <span className="topo-num">{p.num}</span>
            <span>{p.label}</span>
          </button>
        ))}
        <span className="topo-pill-divider" />
        {ZONE_PILLS.map((p) => (
          <button
            key={p.id}
            type="button"
            className={`topo-pill topo-pill-filter topo-pill-zone ${p.cls}`}
            data-active={isActive(p.id) ? "true" : "false"}
            onClick={() => toggle(p.id)}
            aria-pressed={isActive(p.id)}
          >
            <span className="topo-dot" />
            <span>{p.label}</span>
          </button>
        ))}
      </div>

      <div className="topo-controls">
        <button className="topo-icon-btn" type="button" onClick={onZoomOut} aria-label="Zoom out">
          <Minus size={14} />
        </button>
        <span className="topo-zoom-ind">{zoomPct}%</span>
        <button className="topo-icon-btn" type="button" onClick={onZoomIn} aria-label="Zoom in">
          <Plus size={14} />
        </button>
        <button
          className="topo-icon-btn topo-icon-btn-wide"
          type="button"
          onClick={onReset}
          aria-label="Reset view"
          title="Reset view"
        >
          <RotateCcw size={12} />
          <span className="topo-btn-label">Reset</span>
        </button>
        {fullscreen ? (
          <button
            className="topo-exit-btn"
            type="button"
            onClick={onToggleFullscreen}
            aria-label="Exit full view"
            title="Exit full view (Esc)"
          >
            <X size={14} />
            <span className="topo-btn-label">Exit</span>
          </button>
        ) : (
          <button
            className="topo-icon-btn"
            type="button"
            onClick={onToggleFullscreen}
            aria-label="Full view"
            title="Full view"
          >
            <Maximize2 size={14} />
          </button>
        )}
      </div>
    </header>
  );
}
