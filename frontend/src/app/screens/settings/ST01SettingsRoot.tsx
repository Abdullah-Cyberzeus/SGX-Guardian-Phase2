import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import {
  User, Users, BarChart2, Database, Link, Shield, Settings2,
  Wifi, Bell, SlidersHorizontal, BookOpen, Info, LogOut, ChevronRight, Key, ShieldCheck, FileCheck, FileText, Radio, Fingerprint, Cable, Award, Radar, ShieldX, ClipboardCheck,
} from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";
import { useAuth } from "../../contexts/AuthContext";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import { useGuardianInfo } from "../../hooks/useApiData";
import { ThemeToggle } from "../../components/ThemeToggle";

// Import child screens for inline rendering on tablet/desktop
import { ST02GuardianInfo } from "./ST02GuardianInfo";
import { ST03Profile } from "./ST03Profile";
import { ST04DataUsage } from "./ST04DataUsage";
import { ST05BackupRestore } from "./ST05BackupRestore";
import { ST07Geofencing } from "./ST07Geofencing";
import { ST08DevicePairing } from "./ST08DevicePairing";
import { ST09ManageGuardians } from "./ST09ManageGuardians";
import { ST10DeviceSettings } from "./ST10DeviceSettings";
import { ST11Notifications } from "./ST11Notifications";
import { ST12AlertRules } from "./ST12AlertRules";
import { ST13DualWifi } from "./ST13DualWifi";
import { ST14QuickStartGuide } from "./ST14QuickStartGuide";
import { ST15AppVersion } from "./ST15AppVersion";
import { KM01KeyManagement } from "../keys/KM01KeyManagement";
import { IN01IntegrityDashboard } from "../integrity/IN01IntegrityDashboard";
import { SC01BootStatus } from "../security/SC01BootStatus";
import { SC02AttestationStatus } from "../security/SC02AttestationStatus";
import { SC03DIDStatus } from "../security/SC03DIDStatus";
import { SC04VirtualId } from "../security/SC04VirtualId";
import { SC05CRLStatus } from "../security/SC05CRLStatus";
import { PL01PolicyManagement } from "../policy/PL01PolicyManagement";
import { LG01LogsViewer } from "../logs/LG01LogsViewer";
import { NW03PeersList } from "../network/NW03PeersList";
import { NW05TransportStatus } from "../network/NW05TransportStatus";
import { NW06RelayList } from "../network/NW06RelayList";
import { NW07Discovery } from "../network/NW07Discovery";
import { VC01CredentialsList } from "../credentials/VC01CredentialsList";
import { ST16PendingApprovals } from "./ST16PendingApprovals";

const groups = [
  {
    label: "Account",
    items: [
      { icon: User, label: "Profile", path: "/settings/profile", key: "profile" },
      { icon: BarChart2, label: "Data Usage", path: "/settings/data-usage", key: "data-usage" },
      { icon: Database, label: "Backup & Restore", path: "/settings/backup", key: "backup" },
    ],
  },
  {
    label: "Network",
    items: [
      { icon: Users, label: "Peers", path: "/settings/peers", key: "peers" },
      { icon: Cable, label: "Transport Interfaces", path: "/settings/transport", key: "transport" },
      { icon: Radio, label: "Network Nodes", path: "/settings/relay", key: "relay" },
      { icon: Radar, label: "Network Discovery", path: "/settings/discovery", key: "discovery" },
    ],
  },
  {
    label: "Security & Keys",
    items: [
      { icon: ClipboardCheck, label: "Pending Approvals", path: "/settings/pending-approvals", key: "pending-approvals" },
      { icon: Key, label: "Key Management", path: "/settings/keys", key: "keys" },
      { icon: ShieldCheck, label: "Integrity", path: "/settings/integrity", key: "integrity" },
      { icon: Shield, label: "Boot Status", path: "/settings/boot-status", key: "boot-status" },
      { icon: ShieldCheck, label: "Attestation", path: "/settings/attestation", key: "attestation" },
      { icon: Fingerprint, label: "DID Status", path: "/settings/did", key: "did" },
      { icon: ShieldX, label: "CRL", path: "/settings/crl", key: "crl" },
      { icon: Fingerprint, label: "Virtual ID", path: "/settings/virtual-id", key: "virtual-id" },
      { icon: Award, label: "Credentials", path: "/settings/credentials", key: "credentials" },
      { icon: FileCheck, label: "Policy Management", path: "/settings/policy", key: "policy" },
      { icon: FileText, label: "Logs", path: "/settings/logs", key: "logs" },
    ],
  },
  {
    label: "Device",
    items: [
      { icon: Link, label: "Device Pairing", path: "/settings/device-pairing", key: "device-pairing" },
      { icon: Shield, label: "Manage Guardians", path: "/settings/guardians", key: "guardians" },
      { icon: Settings2, label: "Device Settings", path: "/settings/device-settings", key: "device-settings" },
      { icon: Shield, label: "Guardian Info", path: "/settings/guardian", key: "guardian" },
      { icon: Wifi, label: "Dual Wi-Fi Mode", path: "/settings/dual-wifi", key: "dual-wifi" },
    ],
  },
  {
    label: "Notifications",
    items: [
      { icon: Bell, label: "Notification Preferences", path: "/settings/notifications", key: "notifications" },
      { icon: SlidersHorizontal, label: "Custom Alert Rules", path: "/settings/alert-rules", key: "alert-rules" },
    ],
  },
  {
    label: "Help & Support",
    items: [
      { icon: BookOpen, label: "Quick Start Guide", path: "/settings/guide", key: "guide" },
      { icon: Info, label: "App Version", path: "/settings/version", key: "version" },
    ],
  },
];

// Inline content renderer for right panel
function SettingContent({ settingKey }: { settingKey: string }) {
  if (settingKey === "guardian") return <ST02GuardianInfo />;
  if (settingKey === "profile") return <ST03Profile />;
  if (settingKey === "data-usage") return <ST04DataUsage />;
  if (settingKey === "backup") return <ST05BackupRestore />;
  if (settingKey === "peers") return <NW03PeersList />;
  if (settingKey === "geofencing") return <ST07Geofencing />;
  if (settingKey === "device-pairing") return <ST08DevicePairing />;
  if (settingKey === "guardians") return <ST09ManageGuardians />;
  if (settingKey === "device-settings") return <ST10DeviceSettings />;
  if (settingKey === "notifications") return <ST11Notifications />;
  if (settingKey === "alert-rules") return <ST12AlertRules />;
  if (settingKey === "dual-wifi") return <ST13DualWifi />;
  if (settingKey === "guide") return <ST14QuickStartGuide />;
  if (settingKey === "version") return <ST15AppVersion />;
  if (settingKey === "keys") return <KM01KeyManagement />;
  if (settingKey === "integrity") return <IN01IntegrityDashboard />;
  if (settingKey === "boot-status") return <SC01BootStatus />;
  if (settingKey === "attestation") return <SC02AttestationStatus />;
  if (settingKey === "did") return <SC03DIDStatus />;
  if (settingKey === "crl") return <SC05CRLStatus />;
  if (settingKey === "virtual-id") return <SC04VirtualId />;
  if (settingKey === "transport") return <NW05TransportStatus />;
  if (settingKey === "relay") return <NW06RelayList />;
  if (settingKey === "discovery") return <NW07Discovery />;
  if (settingKey === "credentials") return <VC01CredentialsList />;
  if (settingKey === "pending-approvals") return <ST16PendingApprovals />;
  if (settingKey === "policy") return <PL01PolicyManagement />;
  if (settingKey === "logs") return <LG01LogsViewer />;

  // Generic placeholder for settings without inline implementations
  const allItems = groups.flatMap((g) => g.items);
  const item = allItems.find((i) => i.key === settingKey);
  return (
    <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-12">
      <div className="rounded-full flex items-center justify-center" style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}>
        {item?.icon && <item.icon size={28} style={{ color: "var(--muted-foreground)" }} />}
      </div>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{item?.label}</p>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "280px", lineHeight: 1.6 }}>
        This setting is available on the mobile app. Use the navigation to access the full feature.
      </p>
    </div>
  );
}

export function ST01SettingsRoot() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { signOut } = useAuth();
  const { name, email, initials, role } = useCurrentUser();
  const { data: guardianData } = useGuardianInfo();
  const [logoutDialogOpen, setLogoutDialogOpen] = useState(false);
  const selectedKey = searchParams.get("section");
  const openPanel = (key: string) => {
    setSearchParams({ section: key });
  };

  const GuardianCard = ({ onClick }: { onClick: () => void }) => (
      <button
        onClick={onClick}
        className="w-full flex items-center gap-3 rounded-lg border border-border p-4 text-left transition-opacity active:opacity-80"
        style={{
        backgroundColor: selectedKey === "guardian" ? "color-mix(in srgb, var(--primary) 8%, var(--card))" : "var(--card)",
        cursor: "pointer", borderRadius: "var(--radius-card)",
        borderColor: selectedKey === "guardian" ? "var(--primary)" : undefined,
      }}
    >
      <div
        className="rounded-full flex items-center justify-center flex-shrink-0"
        style={{ width: "44px", height: "44px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)" }}
      >
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)" }}>
          {initials}
        </span>
      </div>
      <div className="flex-1 min-w-0">
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>
          {name}
        </p>
        <div className="flex items-center gap-1.5">
          <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--chart-2)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{guardianData?.name || "Guardian"}</span>
        </div>
        <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}>
          {email}
        </p>
      </div>
      <ChevronRight size={18} style={{ color: "var(--muted-foreground)" }} />
    </button>
  );

  const SettingsGroups = ({ isPanel }: { isPanel?: boolean }) => (
    <div className="flex flex-col gap-5 pb-8">
      {groups.map((group) => (
        <div key={group.label}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px", paddingLeft: "4px" }}>
            {group.label}
          </p>
          <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
            {group.items.map(({ icon: Icon, label, path, key }, i) => (
              <button
                key={path}
                onClick={() => { if (isPanel) openPanel(key); else navigate(path); }}
                className="w-full flex items-center gap-3 px-4 py-4 text-left transition-colors"
                style={{
                  backgroundColor: isPanel && selectedKey === key ? "color-mix(in srgb, var(--primary) 8%, transparent)" : "transparent",
                  border: "none", cursor: "pointer",
                  borderBottom: i < group.items.length - 1 ? "1px solid var(--border)" : undefined,
                  borderLeft: isPanel && selectedKey === key ? "3px solid var(--primary)" : "3px solid transparent",
                }}
              >
                <Icon size={18} style={{ color: isPanel && selectedKey === key ? "var(--primary)" : "var(--primary)", flexShrink: 0 }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: isPanel && selectedKey === key ? "var(--primary)" : "var(--foreground)", fontWeight: isPanel && selectedKey === key ? "var(--font-weight-semibold)" : "var(--font-weight-normal)", flex: 1 }}>
                  {label}
                </span>
                <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />
              </button>
            ))}
          </div>
        </div>
      ))}

      <ThemeToggle />

      <button
        onClick={() => setLogoutDialogOpen(true)}
        className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
        style={{ height: "52px", backgroundColor: "color-mix(in srgb, var(--destructive) 12%, transparent)", color: "var(--destructive)", border: "1px solid color-mix(in srgb, var(--destructive) 30%, transparent)", cursor: "pointer", borderRadius: "var(--radius-card)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)" }}
      >
        <LogOut size={18} /> Log Out
      </button>

      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center" }}>
        SG-X Guardian v{__APP_VERSION__}
      </p>
    </div>
  );

  const LogoutDialog = (
    <Dialog.Root open={logoutDialogOpen} onOpenChange={setLogoutDialogOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
        <Dialog.Content className="fixed z-[70] rounded-xl border border-border p-6" style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "380px" }}>
          <div className="flex items-center gap-3 mb-3">
            <LogOut size={20} style={{ color: "var(--destructive)" }} />
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Log Out?</Dialog.Title>
          </div>
          <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6, marginBottom: "20px" }}>
            You will need to enter your credentials to access SG-X Guardian again.
          </Dialog.Description>
          <div className="flex gap-3">
            <Dialog.Close asChild>
              <button className="flex-1 flex items-center justify-center rounded-md" style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}>Cancel</button>
            </Dialog.Close>
            <button onClick={() => { signOut().then(() => { setLogoutDialogOpen(false); navigate("/login", { replace: true }); }); }} className="flex-1 flex items-center justify-center rounded-md" style={{ height: "44px", backgroundColor: "var(--destructive)", color: "var(--destructive-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}>Log Out</button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );

  return (
    <>
      {/* ── Mobile: full scroll list ── */}
      <div className="md:hidden flex flex-col" style={{ minHeight: "100dvh" }}>
        <div className="px-4 pt-5 pb-3">
          <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Settings</h2>
        </div>
        <div className="px-4 mb-4">
          <GuardianCard onClick={() => navigate("/settings/guardian")} />
        </div>
        <div className="px-4">
          <SettingsGroups />
        </div>
      </div>

      {/* ── Tablet: two-panel ── */}
        <div className="hidden md:flex lg:hidden" style={{ height: "100%", overflow: "hidden" }}>
        {/* Left settings menu */}
        <div style={{ width: "45%", borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div className="flex items-center flex-shrink-0 px-5 pt-5 pb-3 md:h-[72px] md:py-0 border-b border-border">
            <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Settings</h2>
          </div>
          <div className="flex-1 overflow-y-auto px-5 pt-4">
            <div className="mb-4">
              <GuardianCard onClick={() => openPanel("guardian")} />
            </div>
            <SettingsGroups isPanel />
          </div>
        </div>
        {/* Right content */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          {selectedKey ? (
            <div className="flex-1 overflow-y-auto">
              <SettingContent settingKey={selectedKey} />
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-8">
              <div className="rounded-full flex items-center justify-center" style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}>
                <Settings2 size={28} style={{ color: "var(--muted-foreground)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Select a setting</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "240px", lineHeight: 1.6 }}>
                Choose a category from the left to configure your Guardian.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Desktop: wider two-panel (settings sidebar style) ── */}
      <div className="hidden lg:flex" style={{ height: "100%", overflow: "hidden" }}>
        {/* Left: proper settings sidebar */}
        <div style={{ width: "300px", borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column", overflow: "hidden", backgroundColor: "var(--sidebar)" }}>
          {/* Settings header */}
          <div className="flex items-center flex-shrink-0 h-[72px] px-5 border-b border-border">
            <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Settings</h2>
          </div>
          <div className="flex-1 overflow-y-auto px-4 pt-4 pb-8">
            <SettingsGroups isPanel />
          </div>
        </div>

        {/* Right: content */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column", backgroundColor: "var(--background)" }}>
          {selectedKey ? (
            <div className="flex-1 overflow-y-auto">
              <SettingContent settingKey={selectedKey} />
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-12">
              <div className="rounded-full flex items-center justify-center" style={{ width: "72px", height: "72px", backgroundColor: "var(--muted)" }}>
                <Settings2 size={32} style={{ color: "var(--muted-foreground)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Settings</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "320px", lineHeight: 1.7 }}>
                Select a category from the sidebar to configure your Guardian, manage your account, or review network settings.
              </p>
            </div>
          )}
        </div>
      </div>

      {LogoutDialog}
    </>
  );
}
