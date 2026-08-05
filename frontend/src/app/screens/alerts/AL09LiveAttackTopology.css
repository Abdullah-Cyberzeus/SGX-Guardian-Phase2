.alerts-modbus-stage {
  min-height: 680px;
  --modbus-red: #ef4444;
  --modbus-blue: #38bdf8;
  --modbus-green: #22c55e;
}

.alerts-modbus-stage.is-alert-fullscreen {
  position: fixed;
  inset: 0;
  z-index: 80;
}

.alerts-modbus-stage .modbus-hud {
  position: absolute;
  left: 14px;
  top: 14px;
  z-index: 10;
  max-width: min(720px, calc(100% - 120px));
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid rgba(255,255,255,0.14);
  border-radius: 10px;
  background: rgba(8,12,18,0.78);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}

.alerts-modbus-stage .modbus-hud-title-wrap {
  display: flex;
  align-items: center;
  gap: 10px;
  color: #fecaca;
}

.alerts-modbus-stage .modbus-hud-eyebrow {
  font: 800 10px "JetBrains Mono", monospace;
  letter-spacing: .18em;
  color: #94a3b8;
}

.alerts-modbus-stage .modbus-hud-title {
  margin-top: 3px;
  font: 800 14px "Inter", sans-serif;
  color: #f8fafc;
}

.alerts-modbus-stage .modbus-hud-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  font: 800 10px "JetBrains Mono", monospace;
  color: #cbd5e1;
}

.alerts-modbus-stage .modbus-hud-stats span {
  border: 1px solid rgba(255,255,255,0.12);
  border-radius: 999px;
  padding: 4px 7px;
  background: rgba(255,255,255,0.04);
}

.alerts-modbus-stage .modbus-hud-stats .is-good {
  color: #86efac;
  border-color: rgba(34,197,94,0.34);
  background: rgba(34,197,94,0.09);
}

.alerts-modbus-stage .modbus-hud-stats .is-warn {
  color: #fbbf24;
  border-color: rgba(251,191,36,0.34);
  background: rgba(251,191,36,0.08);
}

.alerts-modbus-stage .modbus-toolbar button {
  font: 800 10px "JetBrains Mono", monospace;
}

.alerts-modbus-stage .modbus-toolbar button.is-active {
  color: #e0f2fe;
  border-color: rgba(56,189,248,0.46);
  background: rgba(56,189,248,0.14);
}

.alerts-modbus-stage .modbus-zone-labels text {
  font: 800 10px "JetBrains Mono", monospace;
  letter-spacing: .24em;
  fill: #64748b;
}

.alerts-modbus-stage .modbus-mesh-line {
  stroke: rgba(220,228,242,0.42);
  stroke-width: 1.7;
  stroke-dasharray: 8 7;
  animation: modbusMeshDash 4.2s linear infinite;
}

.alerts-modbus-stage .modbus-mesh-edge.is-sensor-mesh .modbus-mesh-line {
  stroke: rgba(56,189,248,0.24);
  stroke-width: 1.1;
}

.alerts-modbus-stage .modbus-mesh-edge.is-active .modbus-mesh-line {
  stroke: rgba(239,68,68,0.95);
  stroke-width: 2.6;
  filter: drop-shadow(0 0 8px rgba(239,68,68,0.72));
  animation-duration: 1.2s;
}

.alerts-modbus-stage .modbus-mesh-edge.is-active .mesh-label-bg {
  stroke: rgba(239,68,68,0.68);
  fill: rgba(239,68,68,0.16);
}

.alerts-modbus-stage .modbus-mesh-edge.is-active .mesh-label {
  fill: #fecaca;
}

.alerts-modbus-stage .modbus-attack-beam {
  animation: modbusBeamDash 0.9s linear infinite;
  filter: drop-shadow(0 0 9px rgba(239,68,68,0.68));
}
.alerts-modbus-stage .modbus-threat-pulse {
  fill: none;
  stroke: #ef4444;
  stroke-width: 2;
  animation: modbusThreatPulse 1.25s ease-out infinite;
  filter: drop-shadow(0 0 8px rgba(239,68,68,0.65));
}

.alerts-modbus-stage .modbus-impact-ring {
  animation: modbusImpact 1.1s ease-out infinite;
  transform-origin: center;
  transform-box: fill-box;
}

.alerts-modbus-stage .modbus-ring-spin {
  animation: modbusRingSpin 6s linear infinite;
  transform-origin: center;
  transform-box: fill-box;
}

.alerts-modbus-stage .modbus-server-halo {
  animation: modbusServerBreath 3.2s ease-in-out infinite;
  transform-origin: center;
  transform-box: fill-box;
}

.alerts-modbus-stage .modbus-red-blink,
.alerts-modbus-stage .modbus-status-dot {
  animation: modbusRedBlink 1s ease-in-out infinite;
}

.alerts-modbus-stage .modbus-scene-node {
  cursor: pointer;
}

.alerts-modbus-stage .modbus-attack-log {
  position: absolute;
  left: 14px;
  right: 14px;
  bottom: 14px;
  z-index: 10;
  max-height: 168px;
  overflow: hidden;
  border: 1px solid rgba(255,255,255,0.14);
  border-radius: 10px;
  background: rgba(8,12,18,0.82);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}

.alerts-modbus-stage .modbus-log-head {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 12px;
  border-bottom: 1px solid rgba(255,255,255,0.08);
  font: 800 10px "JetBrains Mono", monospace;
  letter-spacing: .16em;
  color: #94a3b8;
}

.alerts-modbus-stage .modbus-log-head strong {
  color: #fecaca;
  letter-spacing: .08em;
}

.alerts-modbus-stage .modbus-log-items {
  display: grid;
  gap: 1px;
  max-height: 126px;
  overflow-y: auto;
}

.alerts-modbus-stage .modbus-log-row {
  display: grid;
  grid-template-columns: 70px 42px 62px minmax(170px, 1fr) minmax(120px, 170px);
  gap: 8px;
  align-items: center;
  padding: 7px 12px;
  font: 700 10px "JetBrains Mono", monospace;
  color: #cbd5e1;
  background: rgba(255,255,255,0.025);
}

.alerts-modbus-stage .modbus-log-time { color: #94a3b8; }
.alerts-modbus-stage .modbus-log-tag { color: #bfdbfe; }
.alerts-modbus-stage .modbus-log-fc { color: #fecaca; }
.alerts-modbus-stage .modbus-log-main { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.alerts-modbus-stage .modbus-log-reg { color: #86efac; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.alerts-modbus-stage .modbus-log-empty {
  padding: 14px 12px;
  font: 700 11px "Inter", sans-serif;
  color: #94a3b8;
}

@keyframes modbusMeshDash { to { stroke-dashoffset: -140; } }
@keyframes modbusBeamDash { to { stroke-dashoffset: -90; } }
@keyframes modbusThreatPulse { 0% { r: 28; opacity: .95; } 100% { r: 92; opacity: 0; } }
@keyframes modbusImpact { 0% { opacity: .9; transform: scale(.72); } 100% { opacity: 0; transform: scale(1.65); } }
@keyframes modbusRingSpin { to { transform: rotate(360deg); } }
@keyframes modbusServerBreath { 0%,100% { opacity: .08; transform: scale(.96); } 50% { opacity: .22; transform: scale(1.08); } }
@keyframes modbusRedBlink { 0%,100% { opacity: .45; } 50% { opacity: 1; } }

@media (max-width: 900px) {
  .alerts-modbus-stage { min-height: 620px; }
  .alerts-modbus-stage .modbus-hud { max-width: calc(100% - 28px); }
  .alerts-modbus-stage .modbus-log-row { grid-template-columns: 54px 34px 48px minmax(130px, 1fr); }
  .alerts-modbus-stage .modbus-log-reg { display: none; }
}

@media (prefers-reduced-motion: reduce) {
  .alerts-modbus-stage .modbus-mesh-line,
  .alerts-modbus-stage .modbus-attack-beam,
  .alerts-modbus-stage .modbus-threat-pulse,
  .alerts-modbus-stage .modbus-impact-ring,
  .alerts-modbus-stage .modbus-ring-spin,
  .alerts-modbus-stage .modbus-server-halo,
  .alerts-modbus-stage .modbus-red-blink,
  .alerts-modbus-stage .modbus-status-dot {
    animation: none !important;
  }
}
