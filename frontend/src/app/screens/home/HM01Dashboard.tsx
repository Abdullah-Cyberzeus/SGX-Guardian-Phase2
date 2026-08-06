import { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import {
  Battery, Signal, Users, AlertTriangle, ChevronRight,
  Shield, X, ShieldCheck,
} from "lucide-react";
import { mockAlerts, mockCircles, mockThreatIntel } from "../../data/mockData";
import { SkeletonCard } from "../../components/SkeletonBlock";
import { EmptyState } from "../../components/EmptyState";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import { useGuardianInfo, useAlerts, useCircles, useThreatIntel } from "../../hooks/useApiData";
import { Card, CardHeader, CardTitle, CardDescription, CardAction, CardContent } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Progress } from "../../components/ui/progress";

type ScreenState = "loading" | "populated" | "empty" | "error";

const BANNER_KEY = "sgx_welcome_banner_dismissed";

function scoreLabel(score: number) {
  if (score > 70) return "Secure";
  if (score > 40) return "At Risk";
  return "Critical";
}
function scoreColor(score: number) {
  if (score > 70) return "var(--chart-2)";
  if (score > 40) return "var(--chart-5)";
  return "var(--destructive)";
}

// ── Types ────────────────────────────────────────────────────────────────────
interface GuardianData {
  name: string;
  connectionType: string;
  ip: string;
  battery: number;
  signal: number;
  peerCount: number;
}

interface AlertData {
  id: string;
  severity: string;
  archived: boolean;
}

interface CircleData {
  id: string;
  name: string;
  memberCount: number;
  onlineCount: number;
}

// ── Shared sub-components ────────────────────────────────────────────────────

function GuardianCard({ onClick, guardian }: { onClick: () => void; guardian: GuardianData }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left rounded-lg border border-border p-4 transition-opacity active:opacity-80"
      style={{ backgroundColor: "var(--card)", borderRadius: "var(--radius-card)" }}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: "var(--chart-2)", flexShrink: 0 }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {guardian.name}
            </span>
          </div>
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            {guardian.status ? guardian.status.charAt(0).toUpperCase() + guardian.status.slice(1) : "Online"} · {guardian.connectionType}
          </span>
        </div>
        <ChevronRight size={18} style={{ color: "var(--muted-foreground)", marginTop: "2px" }} />
      </div>
      <div className="grid grid-cols-3 gap-3">
        {[
          { icon: Battery, label: "Battery", value: `${guardian.battery}%` },
          { icon: Signal, label: "Signal", value: `${guardian.signal}%` },
          { icon: Users, label: "Peers", value: `${guardian.peerCount}` },
        ].map(({ icon: Icon, label, value }) => (
          <div key={label} className="flex flex-col items-center gap-1 py-2.5 rounded-md" style={{ backgroundColor: "var(--muted)" }}>
            <Icon size={15} style={{ color: "var(--muted-foreground)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{value}</span>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>{label}</span>
          </div>
        ))}
      </div>
    </button>
  );
}

// ── Desktop dashboard components (1280px+) ───────────────────────────────────

const sectionLabel = "text-xs font-semibold uppercase tracking-[0.1em] text-muted-foreground";

function HealthRing({ score, size, stroke }: { score: number; size: number; stroke: number }) {
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const color = scoreColor(score);
  return (
    <div className="relative flex-shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--muted)" strokeWidth={stroke} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
          strokeLinecap="round" strokeDasharray={`${(score / 100) * circ} ${circ}`}
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-bold leading-none text-foreground" style={{ fontSize: Math.round(size * 0.3) }}>{score}</span>
        <span className="mt-1 text-xs text-muted-foreground">/ 100</span>
      </div>
    </div>
  );
}

function HealthHeroCard({ score, threats24h, blocked }: { score: number; threats24h: number; blocked: number }) {
  const color = scoreColor(score);
  const message =
    score <= 40 ? "Your network needs immediate attention."
    : score <= 70 ? "A few issues need your review."
    : "Your network is secure and protected.";
  const tintBorder =
    score <= 40 ? "color-mix(in srgb, var(--destructive) 35%, var(--border))"
    : score <= 70 ? "color-mix(in srgb, var(--chart-5) 35%, var(--border))"
    : "var(--border)";
  return (
    <Card className="col-span-2 h-full gap-3" style={{ borderColor: tintBorder }}>
      <CardHeader className="px-5 pt-5">
        <CardTitle className={sectionLabel}>Security Health Score</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 items-center gap-6 px-5 [&:last-child]:pb-5">
        <HealthRing score={score} size={128} stroke={12} />
        <div className="flex min-w-0 flex-1 flex-col gap-3">
          <div>
            <p className="text-[26px] font-bold leading-none" style={{ color }}>{scoreLabel(score)}</p>
            <p className="mt-1.5 text-sm text-muted-foreground">{message}</p>
          </div>
          <div className="grid grid-cols-2 gap-2.5">
            {[
              { value: threats24h, label: "Threats · 24h" },
              { value: blocked, label: "Blocked automatically" },
            ].map(({ value, label }) => (
              <div key={label} className="rounded-lg bg-muted px-3.5 py-2.5">
                <p className="text-xl font-bold leading-none text-foreground tabular-nums">{value}</p>
                <p className="mt-1 text-xs text-muted-foreground">{label}</p>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function GuardianDeskCard({ guardian, onClick }: { guardian: GuardianData; onClick: () => void }) {
  const stats = [
    { icon: Battery, label: "Battery", value: guardian.battery, bar: true },
    { icon: Signal, label: "Signal", value: guardian.signal, bar: true },
    { icon: Users, label: "Peers", value: guardian.peerCount, bar: false },
  ];
  return (
    <Card
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } }}
      className="h-full cursor-pointer gap-3 outline-none transition-colors hover:border-primary/40 focus-visible:border-primary/60"
    >
      <CardHeader className="px-5 pt-5">
        <div className="flex items-center gap-2">
          <span className="size-2 shrink-0 rounded-full" style={{ backgroundColor: "var(--chart-2)" }} />
          <CardTitle className="truncate text-sm font-semibold text-foreground">{guardian.name}</CardTitle>
        </div>
        <CardDescription className="text-xs">{guardian.status ? guardian.status.charAt(0).toUpperCase() + guardian.status.slice(1) : "Online"} · {guardian.connectionType} · {guardian.ip}</CardDescription>
        <CardAction><ChevronRight size={16} className="text-muted-foreground" /></CardAction>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-center gap-4 px-5 [&:last-child]:pb-5">
        {stats.map(({ icon: Icon, label, value, bar }) => (
          <div key={label} className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-sm text-muted-foreground">
                <Icon size={15} />{label}
              </span>
              <span className="text-sm font-semibold text-foreground tabular-nums">{value}{bar ? "%" : ""}</span>
            </div>
            {bar && <Progress value={value} className="h-1.5" />}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function AlertsDeskCard({ alerts, navigate }: { alerts: AlertData[]; navigate: (p: string) => void }) {
  const rows = [
    { tag: "HIGH", label: "High severity", color: "var(--destructive)", count: alerts.filter((a) => a.severity === "HIGH" && !a.archived).length },
    { tag: "MED", label: "Medium severity", color: "var(--chart-5)", count: alerts.filter((a) => a.severity === "MEDIUM" && !a.archived).length },
    { tag: "LOW", label: "Low severity", color: "var(--chart-2)", count: alerts.filter((a) => a.severity === "LOW" && !a.archived).length },
  ];
  const total = rows.reduce((s, r) => s + r.count, 0) || 1;
  return (
    <Card className="col-span-3 h-full gap-3">
      <CardHeader className="px-5 pt-5">
        <CardTitle className={sectionLabel}>Active Alerts</CardTitle>
        <CardAction>
          <Button variant="link" onClick={() => navigate("/alerts")} className="h-auto gap-1 p-0 text-xs">
            View All <ChevronRight />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-center gap-2.5 px-5 [&:last-child]:pb-5">
        {rows.map((r) => (
          <button
            key={r.tag}
            onClick={() => navigate("/alerts")}
            className="flex items-center gap-4 rounded-lg border border-border bg-muted/40 px-4 py-3 text-left transition-colors hover:bg-muted"
          >
            <span className="size-2.5 shrink-0 rounded-full" style={{ backgroundColor: r.color }} />
            <div className="flex min-w-0 flex-1 flex-col gap-1.5">
              <span className="text-sm font-medium text-foreground">{r.label}</span>
              <div className="h-1.5 w-full overflow-hidden rounded-full" style={{ backgroundColor: "var(--muted)" }}>
                <div className="h-full rounded-full transition-all" style={{ width: `${(r.count / total) * 100}%`, backgroundColor: r.color }} />
              </div>
            </div>
            <span className="text-xl font-bold tabular-nums" style={{ color: r.color }}>{r.count}</span>
          </button>
        ))}
      </CardContent>
    </Card>
  );
}

function CirclesDeskGrid({ navigate, circles }: { navigate: (p: string) => void; circles: CircleData[] }) {
  return (
    <Card className="col-span-3 h-full gap-3">
      <CardHeader className="px-5 pt-5">
        <CardTitle className={sectionLabel}>Your Circles</CardTitle>
        <CardAction>
          <Button variant="link" onClick={() => navigate("/network")} className="h-auto gap-1 p-0 text-xs">
            View All <ChevronRight />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="px-5 [&:last-child]:pb-5">
        <div className="grid gap-2.5" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))" }}>
          {circles.map((circle) => {
            const ratio = circle.memberCount ? (circle.onlineCount / circle.memberCount) * 100 : 0;
            return (
              <button
                key={circle.id}
                onClick={() => navigate(`/network/${circle.id}`)}
                className="flex flex-col gap-3 rounded-lg border border-border bg-muted/40 p-3.5 text-left transition-colors hover:border-primary/40 hover:bg-muted"
              >
                <div className="flex items-center gap-2.5">
                  <span
                    className="flex size-8 shrink-0 items-center justify-center rounded-lg"
                    style={{ backgroundColor: "color-mix(in srgb, var(--primary) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 24%, transparent)" }}
                  >
                    <Users size={15} className="text-primary" />
                  </span>
                  <span className="min-w-0 flex-1 truncate text-sm font-semibold text-foreground">{circle.name}</span>
                  <ChevronRight size={14} className="shrink-0 text-muted-foreground" />
                </div>
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <span className="size-1.5 rounded-full" style={{ backgroundColor: "var(--chart-2)" }} />
                      Members online
                    </span>
                    <span className="text-xs font-medium text-foreground tabular-nums">{circle.onlineCount}/{circle.memberCount}</span>
                  </div>
                  <Progress value={ratio} className="h-1.5" />
                </div>
              </button>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function HealthScoreCard({ score, threats24h, blocked }: { score: number; threats24h: number; blocked: number }) {
  const ringColor = scoreColor(score);
  const ringR = 36;
  const ringCirc = 2 * Math.PI * ringR;
  return (
    <div
      className="rounded-lg border border-border p-4"
      style={{
        backgroundColor: "var(--card)",
        borderRadius: "var(--radius-card)",
        borderColor: score <= 40
          ? "color-mix(in srgb, var(--destructive) 30%, var(--border))"
          : score <= 70
          ? "color-mix(in srgb, var(--chart-5) 30%, var(--border))"
          : "var(--border)",
      }}
    >
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.1em", marginBottom: "12px" }}>
        Security Health Score
      </p>
      <div className="flex items-center gap-4">
        <div className="relative flex-shrink-0" style={{ width: "88px", height: "88px" }}>
          <svg width="88" height="88" viewBox="0 0 88 88" style={{ transform: "rotate(-90deg)" }}>
            <circle cx="44" cy="44" r={ringR} fill="none" stroke="var(--muted)" strokeWidth="10" />
            <circle cx="44" cy="44" r={ringR} fill="none" stroke={ringColor} strokeWidth="10"
              strokeLinecap="round" strokeDasharray={`${(score / 100) * ringCirc} ${ringCirc}`}
              style={{ transition: "stroke-dasharray 0.6s ease" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "22px", fontWeight: 700, color: "var(--foreground)", lineHeight: 1 }}>
              {score}
            </span>
          </div>
        </div>
        <div className="flex flex-col flex-1 min-w-0">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: 700, color: ringColor, lineHeight: 1.2, marginBottom: "6px" }}>
            {scoreLabel(score)}
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
            {threats24h} threats detected in last 24h.
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
            {blocked} blocked automatically.
          </p>
        </div>
      </div>
    </div>
  );
}

function ActiveAlertsCard({ navigate, alerts }: { navigate: (p: string) => void; alerts: AlertData[] }) {
  const highCount = alerts.filter((a) => a.severity === "HIGH" && !a.archived).length;
  const medCount = alerts.filter((a) => a.severity === "MEDIUM" && !a.archived).length;
  const lowCount = alerts.filter((a) => a.severity === "LOW" && !a.archived).length;
  return (
    <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)", borderRadius: "var(--radius-card)" }}>
      <div className="flex items-center justify-between mb-3">
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.1em" }}>
          Active Alerts
        </p>
        <button onClick={() => navigate("/alerts")} className="flex items-center gap-1 transition-opacity active:opacity-70" style={{ background: "none", border: "none", cursor: "pointer" }}>
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)" }}>View All</span>
          <ChevronRight size={13} style={{ color: "var(--primary)" }} />
        </button>
      </div>
      <div className="flex items-center gap-2">
        {[
          { count: highCount, label: "HIGH", color: "var(--destructive)" },
          { count: medCount, label: "MED", color: "var(--chart-5)" },
          { count: lowCount, label: "LOW", color: "var(--chart-2)" },
        ].map(({ count, label, color }) => (
          <button
            key={label}
            onClick={() => navigate("/alerts")}
            className="flex-1 flex flex-col items-center py-4 rounded-md transition-opacity active:opacity-70"
            style={{ backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${color} 22%, transparent)`, cursor: "pointer" }}
          >
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "28px", fontWeight: 700, color, lineHeight: 1 }}>{count}</span>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color, marginTop: "4px", letterSpacing: "0.05em" }}>{label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function CirclesCard({ navigate, circles }: { navigate: (p: string) => void; circles: CircleData[] }) {
  return (
    <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)", borderRadius: "var(--radius-card)" }}>
      <div className="flex items-center justify-between mb-3">
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.1em" }}>Your Circles</p>
        <button onClick={() => navigate("/network")} className="flex items-center gap-1 transition-opacity active:opacity-70" style={{ background: "none", border: "none", cursor: "pointer" }}>
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)" }}>View All</span>
          <ChevronRight size={13} style={{ color: "var(--primary)" }} />
        </button>
      </div>
      <div className="flex flex-col gap-2">
        {circles.slice(0, 3).map((circle) => (
          <button
            key={circle.id}
            onClick={() => navigate(`/network/${circle.id}`)}
            className="w-full flex items-center gap-3 rounded-md px-3 py-2.5 text-left transition-opacity active:opacity-70"
            style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", cursor: "pointer" }}
          >
            <div className="flex items-center justify-center rounded-md flex-shrink-0" style={{ width: "28px", height: "28px", backgroundColor: "color-mix(in srgb, var(--primary) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 24%, transparent)" }}>
              <Users size={13} style={{ color: "var(--primary)" }} />
            </div>
            <div className="flex flex-col flex-1 min-w-0">
              <span className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.3 }}>{circle.name}</span>
              <div className="flex items-center gap-1.5 mt-0.5">
                <div style={{ width: "5px", height: "5px", borderRadius: "50%", backgroundColor: "var(--chart-2)", flexShrink: 0 }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{circle.onlineCount}/{circle.memberCount} online</span>
              </div>
            </div>
            <ChevronRight size={13} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export function HM01Dashboard() {
  const navigate = useNavigate();
  const { name: userName } = useCurrentUser();
  const [bannerVisible, setBannerVisible] = useState(() => !localStorage.getItem(BANNER_KEY));

  // Fetch data from API with fallback to mock data
  const { data: guardianData, loading: guardianLoading, source: guardianSource } = useGuardianInfo();
  const { data: alertsData, loading: alertsLoading, source: alertsSource } = useAlerts();
  const { data: circlesData, loading: circlesLoading, source: circlesSource } = useCircles();
  const { data: threatData, loading: threatLoading } = useThreatIntel();

  // Map API data to expected format (backend: /node/status)
  const guardian = useMemo(() => {
    const defaults = { name: 'SGX Guardian', connectionType: 'Ethernet', ip: '—', battery: 100, signal: 100, peerCount: 0 };
    if (!guardianData) return defaults;
    return {
      ...defaults,
      ...guardianData,
      name: guardianData.name || defaults.name,
      connectionType: guardianData.connectionType || defaults.connectionType,
      ip: guardianData.ip || defaults.ip,
      battery: guardianData.battery ?? defaults.battery,
      signal: guardianData.signal ?? defaults.signal,
      peerCount: guardianData.peerCount ?? defaults.peerCount,
    };
  }, [guardianData]);

  // Note: alerts, circles, and threatIntel don't have backend APIs yet
  // Use mock data as placeholder until backend endpoints are built
  const alerts = useMemo(() => {
    if (!alertsData) return mockAlerts;
    const alertsList = Array.isArray(alertsData) ? alertsData : (alertsData.alerts || mockAlerts);
    return alertsList.map((alert: any) => ({
      ...alert,
      severity: alert.severity?.toUpperCase() || alert.severity,
      archived: alert.archived ?? false,
    }));
  }, [alertsData]);

  const circles = useMemo(() => {
    if (!circlesData) return mockCircles;
    const circlesList = Array.isArray(circlesData) ? circlesData : mockCircles;
    return circlesList.map((circle: any) => ({
      ...circle,
      onlineCount: circle.onlineCount ?? Math.floor((circle.memberCount || 0) * 0.6),
      memberCount: circle.memberCount || 0,
    }));
  }, [circlesData]);

  const threatIntel = useMemo(() => {
    if (!threatData) return mockThreatIntel;
    return { ...mockThreatIntel, ...threatData };
  }, [threatData]);

  const isLoading = guardianLoading || alertsLoading || circlesLoading || threatLoading;
  const screenState: ScreenState = isLoading ? "loading" : "populated";

  const dismissBanner = () => { localStorage.setItem(BANNER_KEY, "1"); setBannerVisible(false); };

  // Use threat intel from API
  const score = threatIntel.score;

  if (screenState === "loading") {
    return <div className="flex flex-col gap-4 p-4 md:p-6 lg:p-8"><SkeletonCard lines={4} /><SkeletonCard lines={2} /><SkeletonCard lines={3} /></div>;
  }
  if (screenState === "empty") {
    return <EmptyState icon={Shield} heading="No Guardian Connected" subtext="Pair a Guardian device to start monitoring." ctaLabel="Pair Device" ctaAction={() => navigate("/onboarding/pairing")} />;
  }
  if (screenState === "error") {
    return (
      <div className="flex flex-col items-center justify-center flex-1 px-6 py-20 gap-4 text-center">
        <AlertTriangle size={40} style={{ color: "var(--destructive)" }} />
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Unable to reach the Guardian.</p>
        <button className="px-6 rounded-md" style={{ height: "44px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}>
          Try Again
        </button>
      </div>
    );
  }

  const WelcomeBanner = bannerVisible && (
    <div
      className="rounded-lg border flex items-start gap-3 p-3"
      style={{ backgroundColor: "color-mix(in srgb, var(--chart-2) 8%, var(--card))", borderColor: "color-mix(in srgb, var(--chart-2) 25%, transparent)" }}
    >
      <ShieldCheck size={16} style={{ color: "var(--chart-2)", flexShrink: 0, marginTop: "1px" }} />
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", lineHeight: 1.6, flex: 1 }}>
        Guardian is active and monitoring your network.{" "}
        <button onClick={() => navigate("/alerts")} style={{ color: "var(--primary)", background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", textDecoration: "underline", padding: 0 }}>
          Review {threatIntel.threats24h} detected threats.
        </button>
      </p>
      <button onClick={dismissBanner} style={{ background: "none", border: "none", cursor: "pointer", padding: "2px", flexShrink: 0 }}>
        <X size={14} style={{ color: "var(--muted-foreground)" }} />
      </button>
    </div>
  );

  const dataSource = guardianSource === 'api' ? 'Server' : 'Offline';
  const dataSourceColor = guardianSource === 'api' ? 'var(--chart-2)' : 'var(--destructive)';

  const PageHeader = (
    <div className="flex items-center justify-between px-4 md:px-6 lg:px-8 pt-5 pb-3 md:h-[72px] md:py-0 border-b border-border flex-shrink-0" style={{ backgroundColor: "var(--background)" }}>
      <div>
        <h1 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.2 }}>Dashboard</h1>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
          {guardian.name} · Live feed
        </p>
      </div>
      <div className="flex flex-col items-end gap-1">
        <div className="flex items-center gap-2">
          <div style={{ width: "7px", height: "7px", borderRadius: "50%", backgroundColor: "var(--chart-2)", flexShrink: 0 }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)", fontWeight: "var(--font-weight-medium)" }}>Online</span>
        </div>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: dataSourceColor, fontWeight: "var(--font-weight-medium)" }}>
          {dataSource}
        </span>
      </div>
    </div>
  );

  return (
    // h-full fills the <main> container; flex-col so header is pinned and content scrolls
    <div className="flex flex-col h-full">
      {PageHeader}

      {/* ── Mobile layout ── naturally scrolling */}
      <div className="md:hidden flex flex-col gap-4 p-4 pb-8">
        {bannerVisible && WelcomeBanner}
        <GuardianCard onClick={() => navigate("/home/guardian")} guardian={guardian} />
        <HealthScoreCard score={score} threats24h={threatIntel.threats24h} blocked={threatIntel.blocked} />
        <ActiveAlertsCard navigate={navigate} alerts={alerts} />
        <CirclesCard navigate={navigate} circles={circles} />
      </div>

      {/* ── Tablet layout (768px–1279px) — 2 columns, scrollable */}
      <div className="hidden md:grid lg:hidden gap-5 p-6 pb-8 flex-1 overflow-y-auto" style={{ gridTemplateColumns: "1fr 1fr", alignContent: "start" }}>
        {bannerVisible && <div className="col-span-2">{WelcomeBanner}</div>}
        {/* Left col */}
        <div className="flex flex-col gap-5">
          <GuardianCard onClick={() => navigate("/home/guardian")} guardian={guardian} />
          <HealthScoreCard score={score} threats24h={threatIntel.threats24h} blocked={threatIntel.blocked} />
        </div>
        {/* Right col */}
        <div className="flex flex-col gap-5">
          <ActiveAlertsCard navigate={navigate} alerts={alerts} />
        </div>
        {/* Full-width circles */}
        <div className="col-span-2">
          <CirclesCard navigate={navigate} circles={circles} />
        </div>
      </div>

      {/* ── Desktop layout (1280px+) — bento grid, natural height, centered */}
      <div className="hidden lg:block flex-1 overflow-y-auto" style={{ fontFamily: "Inter, sans-serif" }}>
        <div className="flex min-h-full flex-col justify-start gap-4 p-6">
          {bannerVisible && WelcomeBanner}
          <div className="grid gap-4" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
            <HealthHeroCard score={score} threats24h={threatIntel.threats24h} blocked={threatIntel.blocked} />
            <GuardianDeskCard guardian={guardian} onClick={() => navigate("/home/guardian")} />
            <AlertsDeskCard alerts={alerts} navigate={navigate} />
            <CirclesDeskGrid navigate={navigate} circles={circles} />
          </div>
        </div>
      </div>
    </div>
  );
}
