.clt-shell {
  --clt-bg: #070707;
  --clt-panel: #151617;
  --clt-panel-2: #1B1D1F;
  --clt-line: rgba(255, 255, 255, .08);
  --clt-grid: rgba(255, 255, 255, .04);
  --clt-accent: #20C7D9;
  --clt-accent-2: #18B5C8;
  --clt-healthy: #3AC569;
  --clt-warning: #F4B640;
  --clt-offline: #7A7A7A;
  --clt-critical: #E14D4D;
  --clt-text: #F2F2F2;
  --clt-text-2: #B3B3B3;
  position: relative;
  display: flex;
  min-height: 760px;
  width: 100%;
  flex: 1;
  flex-direction: column;
  overflow: hidden;
  color: var(--clt-text);
  background: var(--clt-bg);
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
  isolation: isolate;
}

.clt-shell--fullscreen {
  position: fixed;
  inset: 0;
  z-index: 100;
  min-height: 100dvh;
}

.clt-header {
  z-index: 5;
  display: grid;
  grid-template-columns: minmax(150px, 1fr) auto auto minmax(190px, 320px) minmax(118px, auto);
  align-items: center;
  min-height: 58px;
  gap: 10px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--clt-line);
  background: var(--clt-panel);
}

.clt-title, .clt-title__icon, .clt-actions, .clt-live-state,
.clt-footer, .clt-role-list, .clt-status-line, .clt-trust-line,
.clt-meter-card div, .clt-env, .clt-card__head, .clt-compact-list li,
.clt-compact-list div {
  display: flex;
  align-items: center;
}

.clt-title { min-width: 0; gap: 10px; }
.clt-title__icon {
  justify-content: center;
  width: 34px;
  height: 34px;
  flex: 0 0 auto;
  border: 1px solid rgba(32, 199, 217, .38);
  border-radius: 8px;
  color: var(--clt-accent);
  background: rgba(32, 199, 217, .08);
}
.clt-eyebrow {
  display: block;
  margin-bottom: 2px;
  color: var(--clt-text-2);
  font-size: 9px;
  font-weight: 750;
  letter-spacing: .14em;
}
.clt-title h2, .clt-details h3 {
  margin: 0;
  font-weight: 650;
  letter-spacing: 0;
}
.clt-title h2 {
  overflow: hidden;
  color: var(--clt-text);
  font-size: 16px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.clt-env {
  flex-direction: column;
  align-items: flex-start;
  gap: 1px;
  min-width: 96px;
  padding: 6px 9px;
  border: 1px solid var(--clt-line);
  border-radius: 7px;
  color: var(--clt-text-2);
  background: var(--clt-panel-2);
}
.clt-env span, .clt-live-state small, .clt-search span {
  color: var(--clt-offline);
  font-size: 9px;
}
.clt-env strong {
  color: var(--clt-accent);
  font-size: 11px;
}

.clt-live-state { gap: 8px; color: var(--clt-text-2); }
.clt-live-state > span {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  box-shadow: 0 0 0 4px rgba(58, 197, 105, .1), 0 0 12px currentColor;
}
.clt-live-state > span.is-live { color: var(--clt-healthy); background: var(--clt-healthy); animation: clt-breathe 2s ease-in-out infinite; }
.clt-live-state > span.is-fixture { color: var(--clt-warning); background: var(--clt-warning); }
.clt-live-state div { display: grid; }
.clt-live-state strong { color: var(--clt-text); font-size: 11px; font-weight: 650; }

.clt-search {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 8px;
  min-width: 0;
  padding: 4px 8px;
  border: 1px solid var(--clt-line);
  border-radius: 7px;
  background: var(--clt-panel-2);
}
.clt-search input {
  min-width: 0;
  border: 0;
  outline: 0;
  color: var(--clt-text);
  background: transparent;
  font: inherit;
  font-size: 11px;
}
.clt-search input::placeholder { color: var(--clt-offline); }

.clt-actions {
  justify-content: flex-end;
  gap: 7px;
  min-width: 118px;
  flex: 0 0 auto;
}
.clt-actions button, .clt-details__header button {
  display: grid;
  width: 34px;
  height: 34px;
  flex: 0 0 34px;
  place-items: center;
  border: 1px solid rgba(32, 199, 217, .42);
  border-radius: 7px;
  color: #D8F8FB;
  background: rgba(32, 199, 217, .1);
  cursor: pointer;
  box-shadow: inset 0 1px rgba(255, 255, 255, .08);
  transition: border-color .16s ease, color .16s ease, background .16s ease, transform .16s ease;
}
.clt-actions button:hover, .clt-details__header button:hover {
  border-color: rgba(32, 199, 217, .78);
  color: #F2F2F2;
  background: rgba(32, 199, 217, .18);
  transform: translateY(-1px);
}
.clt-actions button:last-child {
  color: #071113;
  border-color: rgba(32, 199, 217, .9);
  background: linear-gradient(180deg, #20C7D9, #18B5C8);
}
.clt-actions button:last-child:hover {
  color: #071113;
  background: linear-gradient(180deg, #5BE5F1, #20C7D9);
}

.clt-notice {
  z-index: 4;
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 6px 12px;
  color: var(--clt-warning);
  border-bottom: 1px solid rgba(244, 182, 64, .2);
  background: rgba(244, 182, 64, .08);
  font-size: 10px;
}

.clt-workspace {
  display: grid;
  grid-template-columns: minmax(0, 1fr) clamp(280px, 27vw, 390px);
  flex: 1;
  min-height: 0;
}

.clt-stage {
  position: relative;
  min-height: 0;
  overflow: hidden;
  background:
    radial-gradient(circle at 50% 45%, rgba(32, 199, 217, .12), transparent 48%),
    #070707;
  contain: layout paint;
  transform: translateZ(0);
}
.clt-grid {
  position: absolute;
  inset: 0;
  opacity: 1;
  background-image:
    linear-gradient(var(--clt-grid) 1px, transparent 1px),
    linear-gradient(90deg, var(--clt-grid) 1px, transparent 1px);
  background-size: 32px 32px;
  pointer-events: none;
}
.clt-lattice, .clt-particles, .clt-streams, .clt-glow { display: none; }
.clt-svg {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  cursor: grab;
  touch-action: none;
}
.clt-svg:active { cursor: grabbing; }

.clt-real-map rect { fill: rgba(3, 26, 30, .42); }
.clt-real-map .clt-map-contrast {
  fill: rgba(32, 199, 217, .13);
  stroke: rgba(32, 199, 217, .46);
  stroke-width: 1;
}
.clt-map-tile {
  opacity: .68;
  filter: sepia(1) hue-rotate(135deg) saturate(2.4) contrast(1.42) brightness(1.18);
  mix-blend-mode: screen;
}
.clt-real-map text {
  fill: #D8F8FB;
  font: 700 8px ui-monospace, SFMono-Regular, Menlo, monospace;
  text-anchor: end;
  paint-order: stroke;
  stroke: rgba(0, 0, 0, .92);
  stroke-width: 4px;
}
.clt-map-labels { pointer-events: none; opacity: 1; }
.clt-map-label {
  fill: #E7FBFD;
  font: 800 11px ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .12em;
  paint-order: stroke;
  stroke: rgba(0, 0, 0, .96);
  stroke-width: 6px;
  filter: drop-shadow(0 0 8px rgba(32, 199, 217, .42));
}
.clt-map-label-sub {
  fill: #BCEEF3;
  font: 700 8px ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .1em;
  paint-order: stroke;
  stroke: rgba(0, 0, 0, .96);
  stroke-width: 5px;
}

.clt-geo-zone { pointer-events: none; opacity: .92; }
.clt-geo-zone.is-disabled { opacity: .3; }
.clt-geo-zone ellipse {
  fill: color-mix(in srgb, var(--zone-color) 16%, transparent);
  stroke: var(--zone-color);
  stroke-width: 1.2;
  stroke-dasharray: 8 6;
  animation: clt-flow 4s linear infinite;
}
.clt-geo-zone.is-inside ellipse { stroke-width: 2; }
.clt-geo-zone text {
  fill: #E7FBFD;
  text-anchor: middle;
  font: 750 9px ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .1em;
  paint-order: stroke;
  stroke: rgba(0, 0, 0, .96);
  stroke-width: 4px;
  text-transform: uppercase;
}

.clt-lanes rect {
  fill: rgba(255, 255, 255, .018);
  stroke: var(--clt-line);
  stroke-width: 1;
  stroke-dasharray: 3 7;
}
.clt-lanes text {
  fill: #7A7A7A;
  text-anchor: middle;
  font: 700 9px ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .1em;
}
.clt-lanes path {
  fill: none;
  stroke: rgba(32, 199, 217, .2);
  stroke-width: 1;
  stroke-dasharray: 4 6;
  marker-end: url(#clt-flow-arrow);
}

.clt-link {
  fill: none;
  stroke-width: .9;
  opacity: .54;
  vector-effect: non-scaling-stroke;
  transition: opacity .2s ease;
}
.clt-link--mesh { stroke: url(#clt-mesh); }
.clt-link--relay {
  stroke: #18B5C8;
  stroke-width: 1.5;
  stroke-dasharray: 8 6;
  animation: clt-flow 1.8s linear infinite;
}
.clt-link--attestation {
  stroke: rgba(242, 242, 242, .72);
  stroke-width: .75;
  stroke-dasharray: 2 8;
  opacity: .38;
  animation: clt-flow 2.8s linear infinite;
}
.clt-link.is-inactive { stroke: #7A7A7A; stroke-dasharray: 5 8; opacity: .22; animation: none; }
.clt-link.is-filtered, .clt-link-group.is-filtered { opacity: .035; }
.clt-link-group { transition: opacity .2s ease; }
.clt-packet { fill: #20C7D9; stroke: rgba(32, 199, 217, .28); stroke-width: 3; pointer-events: none; }
.clt-packet--relay { fill: #18B5C8; stroke: rgba(24, 181, 200, .3); }
.clt-link-proof { pointer-events: none; opacity: .78; }
.clt-link-proof rect { fill: rgba(21, 22, 23, .94); stroke: rgba(244, 182, 64, .65); stroke-width: .7; }
.clt-link-proof path { fill: none; stroke: var(--clt-warning); stroke-width: 1; stroke-linecap: round; stroke-linejoin: round; }
.clt-link-proof text { fill: var(--clt-warning); font: 700 6px ui-monospace, monospace; letter-spacing: .08em; }

.clt-node { cursor: pointer; outline: none; transition: opacity .2s ease; }
.clt-node.is-filtered { opacity: .08; pointer-events: none; }
.clt-node__body {
  fill: url(#clt-node-online);
  stroke-width: 1.2;
  transition: stroke-width .16s ease, transform .16s ease, opacity .16s ease;
}
.clt-node--offline .clt-node__body, .clt-node--unknown .clt-node__body { fill: url(#clt-node-offline); }
.clt-node__trust {
  fill: none;
  stroke-width: .9;
  stroke-dasharray: 2 5;
  opacity: .72;
  vector-effect: non-scaling-stroke;
  transform-box: fill-box;
  transform-origin: center;
}
.clt-node__pulse {
  fill: none;
  stroke-width: 1;
  opacity: 0;
  animation: clt-pulse 3s ease-out infinite;
  vector-effect: non-scaling-stroke;
  transform-box: fill-box;
  transform-origin: center;
}
.clt-node:hover .clt-node__body, .clt-node.is-selected .clt-node__body {
  stroke-width: 2.6;
  filter: url(#clt-glow-filter);
}
.clt-node.is-selected .clt-node__trust { animation: clt-spin 5s linear infinite; }
.clt-node__body--lighthouse { fill: url(#clt-node-online); }
.clt-node__body--relay { fill: rgba(13, 32, 36, .96); }
.clt-node__body--member { fill: rgba(8, 24, 29, .96); }
.clt-node__energy {
  fill: none;
  stroke-width: 1;
  stroke-dasharray: 7 5;
  opacity: .68;
  animation: clt-spin 9s linear infinite;
  transform-box: fill-box;
  transform-origin: center;
}
.clt-node__orbit {
  fill: none;
  stroke: rgba(179, 179, 179, .34);
  stroke-width: .8;
  stroke-dasharray: 2 9;
  animation: clt-spin 17s linear infinite reverse;
  transform-box: fill-box;
  transform-origin: center;
}
.clt-glyph { color: #F2F2F2; pointer-events: none; }
.clt-glyph--lighthouse { color: #20C7D9; }
.clt-glyph--relay { color: #18B5C8; }
.clt-glyph--member { color: #B3B3B3; }
.clt-node__initials {
  fill: #F2F2F2;
  text-anchor: middle;
  font-size: 12px;
  font-weight: 750;
  letter-spacing: .02em;
  pointer-events: none;
}
.clt-node__label {
  fill: #B3B3B3;
  text-anchor: middle;
  font-size: 8px;
  font-weight: 700;
  pointer-events: none;
  paint-order: stroke;
  stroke: #070707;
  stroke-width: 3px;
  transition: opacity .16s ease;
}
.clt-node__sub {
  fill: #7A7A7A;
  text-anchor: middle;
  font-size: 6px;
  pointer-events: none;
  paint-order: stroke;
  stroke: #070707;
  stroke-width: 2px;
  transition: opacity .16s ease;
}
.clt-node__status { stroke: #070707; stroke-width: 2; transition: opacity .16s ease; }
.clt-node__map-dot {
  stroke-width: 2;
  vector-effect: non-scaling-stroke;
  filter: drop-shadow(0 0 5px currentColor);
  transition: opacity .16s ease, transform .16s ease;
}
.clt-node__map-label {
  fill: #E7FBFD;
  font: 800 9px ui-monospace, SFMono-Regular, Menlo, monospace;
  paint-order: stroke;
  stroke: rgba(0, 0, 0, .96);
  stroke-width: 5px;
  pointer-events: none;
  transition: opacity .16s ease;
  filter: drop-shadow(0 0 7px rgba(32, 199, 217, .34));
}
.clt-shell--icons .clt-node__map-dot { opacity: .2; }
.clt-shell--icons .clt-node__map-label { opacity: 0; }
.clt-shell--dots .clt-node__body,
.clt-shell--dots .clt-node__trust,
.clt-shell--dots .clt-node__pulse,
.clt-shell--dots .clt-glyph,
.clt-shell--dots .clt-node__status,
.clt-shell--dots .clt-primary-mark,
.clt-shell--dots .clt-role-mark,
.clt-shell--dots .clt-node__label,
.clt-shell--dots .clt-node__sub {
  opacity: 0;
  pointer-events: none;
}
.clt-shell--dots .clt-node__map-dot {
  opacity: 1;
  transform: scale(1.08);
}
.clt-shell--dots .clt-node__map-label { opacity: .96; }
.clt-role-mark circle, .clt-primary-mark circle { fill: #151617; stroke: #20C7D9; stroke-width: 1; }
.clt-role-mark text, .clt-primary-mark text { fill: #F2F2F2; text-anchor: middle; font-size: 7px; font-weight: 800; }
.clt-role-mark svg { color: #F2F2F2; stroke-width: 1.7; }
.clt-primary-mark circle { fill: rgba(244, 182, 64, .12); stroke: #F4B640; }
.clt-primary-mark path { fill: none; stroke: #F4B640; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
.clt-role-mark--relay circle { stroke: #18B5C8; }
.clt-role-mark--relay svg { color: #18B5C8; }

.clt-side {
  min-width: 0;
  overflow-y: auto;
  padding: clamp(8px, 1vw, 12px);
  border-left: 1px solid var(--clt-line);
  background: var(--clt-panel);
  scrollbar-color: rgba(179, 179, 179, .28) transparent;
}
.clt-card {
  margin: 0 0 clamp(8px, 1vw, 12px);
  padding: clamp(8px, 1vw, 11px);
  border: 1px solid var(--clt-line);
  border-radius: 8px;
  background: var(--clt-panel-2);
  min-width: 0;
  overflow: visible;
}
.clt-card__head {
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 9px;
  color: var(--clt-text);
  min-width: 0;
}
.clt-card__head h3 {
  margin: 0;
  font-size: 12px;
  font-weight: 700;
}
.clt-card__head span {
  color: var(--clt-offline);
  font-size: 9px;
}
.clt-card-empty {
  margin: 0;
  color: var(--clt-text-2);
  font-size: 11px;
  line-height: 1.45;
}
.clt-card-note {
  margin: 8px 0 0;
  color: var(--clt-warning);
  font-size: 10px;
}
.clt-metrics {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 7px;
}
.clt-metrics div {
  min-width: 0;
  padding: 9px;
  border: 1px solid var(--clt-line);
  border-radius: 7px;
  background: rgba(7, 7, 7, .34);
}
.clt-metrics strong,
.clt-metrics b {
  display: block;
  color: var(--clt-text);
  font: 750 18px ui-monospace, SFMono-Regular, Menlo, monospace;
}
.clt-metrics span {
  display: block;
  margin-top: 3px;
  color: var(--clt-text-2);
  font-size: 9px;
}
.clt-filterbar {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  min-width: 0;
}
.clt-filterbar button {
  flex: 1 1 92px;
  min-width: 0;
  min-height: 30px;
  padding: 6px 9px;
  border: 1px solid rgba(32, 199, 217, .24);
  border-radius: 999px;
  color: #D8F8FB;
  background: rgba(32, 199, 217, .09);
  font: inherit;
  font-size: 9px;
  font-weight: 650;
  text-align: center;
  white-space: nowrap;
  cursor: pointer;
  transition: border-color .16s ease, color .16s ease, background .16s ease;
}
.clt-filterbar button:hover { color: #F2F2F2; border-color: rgba(32, 199, 217, .55); background: rgba(32, 199, 217, .14); }
.clt-filterbar button.is-active {
  color: #071113;
  border-color: rgba(32, 199, 217, .8);
  background: linear-gradient(180deg, #20C7D9, #18B5C8);
}
.clt-trust-bars {
  display: grid;
  gap: 8px;
}
.clt-trust-bars div {
  display: grid;
  grid-template-columns: 72px minmax(0, 1fr) 24px;
  align-items: center;
  gap: 8px;
  color: var(--clt-text-2);
  font-size: 10px;
}
.clt-trust-bars i {
  height: 5px;
  overflow: hidden;
  border-radius: 999px;
  background: rgba(255, 255, 255, .07);
}
.clt-trust-bars em {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: var(--bar-color, var(--clt-accent));
}
.clt-compact-list {
  display: grid;
  gap: 6px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.clt-compact-list li,
.clt-compact-list div {
  justify-content: space-between;
  gap: 10px;
  min-width: 0;
  color: var(--clt-text-2);
  font-size: 10px;
}
.clt-compact-list strong,
.clt-compact-list b {
  min-width: 0;
  color: var(--clt-text);
  font-weight: 650;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.clt-compact-list span:last-child,
.clt-compact-list b:last-child {
  color: var(--clt-accent);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  text-align: right;
}

.clt-card .clt-details {
  position: static;
  width: 100%;
  max-height: none;
  overflow: visible;
  border: 0;
  border-radius: 0;
  background: transparent;
  box-shadow: none;
  backdrop-filter: none;
  animation: none;
}
.clt-details__header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 0 0 10px;
  border-bottom: 1px solid var(--clt-line);
}
.clt-details h3 { color: var(--clt-text); font-size: 15px; }
.clt-details__hero { display: flex; align-items: center; gap: 11px; padding: 12px 0; }
.clt-details__avatar {
  position: relative;
  display: grid;
  width: 48px;
  height: 48px;
  place-items: center;
  border: 1px solid var(--node-color);
  border-radius: 8px;
  color: var(--clt-text);
  background: color-mix(in srgb, var(--node-color) 16%, #151617);
  font-size: 13px;
  font-weight: 750;
}
.clt-details__avatar span {
  position: absolute;
  right: -3px;
  bottom: -3px;
  width: 11px;
  height: 11px;
  border: 3px solid var(--clt-panel-2);
  border-radius: 999px;
  background: var(--node-color);
}
.clt-status-line, .clt-trust-line { gap: 7px; margin: 3px 0; color: var(--clt-text-2); font-size: 11px; }
.clt-status-line i { width: 7px; height: 7px; border-radius: 999px; box-shadow: 0 0 8px currentColor; }
.clt-role-list { flex-wrap: wrap; gap: 6px; padding: 0 0 12px; }
.clt-role-list span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 7px;
  color: var(--clt-text);
  border: 1px solid rgba(32, 199, 217, .22);
  border-radius: 6px;
  background: rgba(32, 199, 217, .07);
  font-size: 9px;
  font-weight: 650;
}
.clt-kv { margin: 0; padding: 0 0 12px; }
.clt-kv div {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr);
  gap: 8px;
  padding: 7px 0;
  border-bottom: 1px solid var(--clt-line);
}
.clt-kv dt { color: var(--clt-offline); font-size: 9px; }
.clt-kv dd {
  min-width: 0;
  margin: 0;
  color: var(--clt-text-2);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 9px;
  text-align: right;
}
.clt-truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.clt-meter-card {
  margin: 0 0 12px;
  padding: 10px;
  border: 1px solid rgba(24, 181, 200, .22);
  border-radius: 7px;
  background: rgba(24, 181, 200, .06);
}
.clt-meter-card div { justify-content: space-between; gap: 6px; color: var(--clt-accent-2); font-size: 9px; }
.clt-meter-card div span { display: flex; align-items: center; gap: 5px; }
.clt-meter-card strong { color: var(--clt-text); }
.clt-meter { height: 5px; margin: 9px 0 7px; overflow: hidden; border-radius: 999px; background: rgba(255, 255, 255, .08); }
.clt-meter span { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, #18B5C8, #20C7D9); }
.clt-meter-card p { margin: 0; color: var(--clt-offline); font-size: 8px; }
.clt-security-posture { display: grid; grid-template-columns: 1fr 1fr; gap: 7px; padding: 0 0 11px; }
.clt-security-posture > div { padding: 8px; border: 1px solid var(--clt-line); border-radius: 7px; background: rgba(7, 7, 7, .28); }
.clt-security-posture span { display: block; color: var(--clt-offline); font: 700 7px ui-monospace, monospace; letter-spacing: .08em; }
.clt-security-posture strong { display: block; margin-top: 3px; color: var(--clt-text); font: 750 18px ui-monospace, monospace; }
.clt-telemetry-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 7px; padding: 0; }
.clt-telemetry-grid > div { padding: 8px; border-radius: 7px; background: rgba(255, 255, 255, .035); }
.clt-telemetry-grid span { color: var(--clt-offline); font: 650 7px ui-monospace, monospace; }
.clt-telemetry-grid b { display: block; margin-top: 3px; color: var(--clt-text-2); font: 650 9px ui-monospace, monospace; }
.clt-telemetry-grid i { display: block; height: 3px; margin-top: 6px; border-radius: 3px; background: rgba(255, 255, 255, .08); overflow: hidden; }
.clt-telemetry-grid em { display: block; height: 100%; background: linear-gradient(90deg, #18B5C8, #20C7D9); }

.clt-zoom {
  position: absolute;
  z-index: 5;
  left: 12px;
  bottom: 38px;
  display: flex;
  align-items: center;
  overflow: hidden;
  border: 1px solid var(--clt-line);
  border-radius: 7px;
  background: rgba(21, 22, 23, .9);
}
.clt-zoom button { width: 29px; height: 27px; border: 0; color: var(--clt-text-2); background: transparent; cursor: pointer; font-size: 16px; }
.clt-zoom button:hover { color: var(--clt-accent); background: rgba(32, 199, 217, .08); }
.clt-zoom span { min-width: 38px; color: var(--clt-text-2); font-size: 8px; text-align: center; }
.clt-map-status {
  position: absolute;
  z-index: 5;
  left: 12px;
  bottom: 72px;
  display: flex;
  align-items: center;
  gap: 8px;
  max-width: calc(100% - 24px);
  padding: 6px 8px;
  border: 1px solid var(--clt-line);
  border-radius: 7px;
  color: var(--clt-text-2);
  background: rgba(21, 22, 23, .9);
  font: 700 8px ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .07em;
}
.clt-map-status span { color: var(--clt-accent); }
.clt-map-status b { color: var(--clt-text); font-weight: 800; }
.clt-legend {
  position: absolute;
  z-index: 5;
  right: 12px;
  bottom: 38px;
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 9px;
  max-width: calc(100% - 130px);
  padding: 6px 8px;
  border: 1px solid var(--clt-line);
  border-radius: 7px;
  color: var(--clt-text-2);
  background: rgba(21, 22, 23, .88);
  font-size: 8px;
}
.clt-legend span { display: flex; align-items: center; gap: 4px; }
.clt-legend i { width: 6px; height: 6px; border-radius: 999px; }
.clt-legend i.online { background: var(--clt-healthy); box-shadow: 0 0 6px var(--clt-healthy); }
.clt-legend i.offline { background: var(--clt-offline); }
.clt-legend b { width: 14px; height: 2px; }
.clt-legend b.mesh { background: linear-gradient(90deg, #18B5C8, #20C7D9); }
.clt-legend b.trust { border-top: 1px dashed #F2F2F2; }
.clt-legend b.relay { background: #18B5C8; }
.clt-geofence-actions {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(34px, 1fr));
  gap: 6px;
  margin-top: 8px;
  min-width: 0;
}
.clt-geofence-actions button {
  display: grid;
  width: 100%;
  min-width: 34px;
  height: 34px;
  place-items: center;
  border: 1px solid rgba(32, 199, 217, .28);
  border-radius: 7px;
  color: #D8F8FB;
  background: rgba(32, 199, 217, .1);
  cursor: pointer;
  transition: border-color .16s ease, color .16s ease, background .16s ease, opacity .16s ease;
}
.clt-geofence-actions button:hover {
  color: #F2F2F2;
  border-color: rgba(32, 199, 217, .6);
  background: rgba(32, 199, 217, .16);
}
.clt-geofence-actions button:disabled {
  opacity: .58;
  color: #7A7A7A;
  background: rgba(122, 122, 122, .08);
  cursor: not-allowed;
}
.clt-minimap {
  position: absolute;
  z-index: 5;
  left: 12px;
  bottom: 106px;
  width: 154px;
  height: 92px;
  overflow: hidden;
  border: 1px solid var(--clt-line);
  border-radius: 8px;
  background: rgba(21, 22, 23, .9);
}
.clt-minimap > div {
  display: flex;
  align-items: center;
  gap: 5px;
  height: 21px;
  padding: 0 7px;
  border-bottom: 1px solid var(--clt-line);
  color: var(--clt-offline);
  font: 650 6px ui-monospace, monospace;
  letter-spacing: .08em;
}
.clt-minimap > div span { margin-left: auto; color: var(--clt-text-2); }
.clt-minimap svg { width: 100%; height: calc(100% - 21px); }
.clt-minimap line { stroke: rgba(32, 199, 217, .3); stroke-width: 3; }
.clt-minimap circle { fill: var(--clt-healthy); }
.clt-minimap circle.is-offline, .clt-minimap circle.is-unknown { fill: var(--clt-offline); }
.clt-minimap circle.is-stale { fill: var(--clt-warning); }
.clt-minimap rect { fill: none; stroke: rgba(32, 199, 217, .45); stroke-width: 4; }

.clt-loading, .clt-empty {
  position: absolute;
  z-index: 9;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 8px;
  color: var(--clt-text-2);
  background: rgba(7, 7, 7, .64);
  backdrop-filter: blur(3px);
  font-size: 11px;
}
.clt-loading svg { color: var(--clt-accent); animation: clt-rotate 1s linear infinite; }
.clt-empty strong { color: var(--clt-text); font-size: 13px; }
.clt-empty span { color: var(--clt-text-2); font-size: 10px; }

.clt-footer {
  z-index: 4;
  justify-content: space-between;
  gap: 10px;
  min-height: 31px;
  padding: 5px 12px;
  border-top: 1px solid var(--clt-line);
  color: var(--clt-text-2);
  background: var(--clt-panel);
  font-size: 8px;
}
.clt-footer span { display: flex; align-items: center; gap: 5px; white-space: nowrap; }

@keyframes clt-breathe { 50% { opacity: .62; transform: scale(.8); } }
@keyframes clt-pulse { 0% { opacity: .55; transform: scale(.8); } 78%, 100% { opacity: 0; transform: scale(1.18); } }
@keyframes clt-flow { to { stroke-dashoffset: -26; } }
@keyframes clt-spin { to { transform: rotate(360deg); transform-origin: center; } }
@keyframes clt-rotate { to { transform: rotate(360deg); } }

@media (max-width: 1100px) {
  .clt-shell { min-height: 720px; }
  .clt-header {
    grid-template-columns: minmax(0, 1fr) auto minmax(118px, auto);
  }
  .clt-search {
    grid-column: 1 / -1;
  }
  .clt-actions {
    grid-column: 3;
    grid-row: 1;
    min-width: 118px;
  }
  .clt-workspace {
    grid-template-columns: 1fr;
    grid-template-rows: minmax(480px, 1fr) minmax(240px, 42dvh);
  }
  .clt-side {
    display: grid;
    grid-template-columns: repeat(2, minmax(260px, 1fr));
    align-content: start;
    gap: 8px;
    overflow: auto;
    border-left: 0;
    border-top: 1px solid var(--clt-line);
  }
  .clt-card { margin: 0; }
  .clt-card:first-child,
  .clt-card:nth-child(3),
  .clt-card:last-child {
    grid-column: 1 / -1;
  }
  .clt-filterbar button {
    flex-basis: 112px;
  }
  .clt-geofence-actions {
    grid-template-columns: repeat(auto-fit, minmax(38px, 1fr));
  }
}

@media (max-width: 760px) {
  .clt-shell { min-height: 640px; }
  .clt-header {
    grid-template-columns: minmax(0, 1fr) minmax(118px, auto);
    gap: 8px;
    padding: 8px;
  }
  .clt-env, .clt-live-state { display: none; }
  .clt-actions { grid-column: 2; grid-row: 1; }
  .clt-search { grid-column: 1 / -1; }
  .clt-actions button {
    width: 34px;
    height: 34px;
    flex-basis: 34px;
  }
  .clt-workspace {
    grid-template-rows: minmax(420px, 1fr) minmax(230px, 42dvh);
  }
  .clt-side {
    grid-template-columns: 1fr;
    gap: 8px;
  }
  .clt-card:first-child,
  .clt-card:nth-child(3),
  .clt-card:last-child {
    grid-column: auto;
  }
  .clt-metrics {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .clt-metrics div {
    padding: 7px;
  }
  .clt-metrics strong {
    font-size: 15px;
  }
  .clt-filterbar button {
    flex: 1 1 calc(50% - 6px);
  }
  .clt-geofence-actions {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
  .clt-geofence-actions button {
    min-width: 0;
  }
  .clt-map-status {
    right: 8px;
    left: 8px;
    bottom: 44px;
    overflow-x: auto;
  }
  .clt-legend, .clt-minimap { display: none; }
  .clt-node__map-label { font-size: 7px; }
  .clt-footer {
    justify-content: flex-start;
    overflow-x: auto;
  }
}

@media (prefers-reduced-motion: reduce) {
  .clt-shell *, .clt-shell *::before, .clt-shell *::after {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
    scroll-behavior: auto !important;
  }
}
