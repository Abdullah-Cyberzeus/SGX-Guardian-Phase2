import { lazy } from "react";
import { createBrowserRouter, redirect } from "react-router";
import { Root } from "./Root";

// Layouts + first-paint screens are eager â€” everything else is code-split.
import { OnboardingLayout } from "./layouts/OnboardingLayout";
import { MainLayout } from "./layouts/MainLayout";
import { SYS01NotFound } from "./screens/system/SYS01NotFound";
import { SYS02SplashScreen } from "./screens/system/SYS02SplashScreen";
import { LoginScreen } from "./screens/auth/LoginScreen";
import { CyleniumCallback } from "./screens/auth/CyleniumCallback";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AuthenticatedOnboardingRoute, OnboardingEntryRoute } from "./components/OnboardingRouteGuard";

/** Lazily load a screen by its named export â€” one route chunk per screen. */
function screen(loader: () => Promise<Record<string, unknown>>, name: string) {
  return lazy(async () => ({ default: (await loader())[name] as React.ComponentType }));
}

// Onboarding
const OB01Welcome = screen(() => import("./screens/onboarding/OB01Welcome"), "OB01Welcome");
const OB02HardwarePairing = screen(() => import("./screens/onboarding/OB02HardwarePairing"), "OB02HardwarePairing");
const OB03Connecting = screen(() => import("./screens/onboarding/OB03Connecting"), "OB03Connecting");
const OB04PairingSuccess = screen(() => import("./screens/onboarding/OB04PairingSuccess"), "OB04PairingSuccess");
const OB05PairingFailed = screen(() => import("./screens/onboarding/OB05PairingFailed"), "OB05PairingFailed");
const OB06AccountSetup = screen(() => import("./screens/onboarding/OB06AccountSetup"), "OB06AccountSetup");
const OB07DIDIntroduction = screen(() => import("./screens/onboarding/OB07DIDIntroduction"), "OB07DIDIntroduction");
const OB08CreateFirstCircle = screen(() => import("./screens/onboarding/OB08CreateFirstCircle"), "OB08CreateFirstCircle");
const OB09OnboardingComplete = screen(() => import("./screens/onboarding/OB09OnboardingComplete"), "OB09OnboardingComplete");

// Home
const HM01Dashboard = screen(() => import("./screens/home/HM01Dashboard"), "HM01Dashboard");
const HM02GuardianDetail = screen(() => import("./screens/home/HM02GuardianDetail"), "HM02GuardianDetail");
const HM03NetworkTopology = screen(() => import("./screens/home/HM03NetworkTopology"), "HM03NetworkTopology");

// Alerts
const AL01AlertsList = screen(() => import("./screens/alerts/AL01AlertsList"), "AL01AlertsList");
const AL06AlertDetail = screen(() => import("./screens/alerts/AL06AlertDetail"), "AL06AlertDetail");
const AL07AIRecommendation = screen(() => import("./screens/alerts/AL07AIRecommendation"), "AL07AIRecommendation");
const AL08ThreatProtection = screen(() => import("./screens/alerts/AL08ThreatProtection"), "AL08ThreatProtection");
const NT01Notifications = screen(() => import("./screens/notifications/NT01Notifications"), "NT01Notifications");

// Network (Circles + Peers)
const NW01CirclesList = screen(() => import("./screens/network/NW01CirclesList"), "NW01CirclesList");
const NW02CreateCircle = screen(() => import("./screens/network/NW02CreateCircle"), "NW02CreateCircle");
const NW03PeersList = screen(() => import("./screens/network/NW03PeersList"), "NW03PeersList");
const NW04CircleDetail = screen(() => import("./screens/network/NW04CircleDetail"), "NW04CircleDetail");
const ChatConversationScreen = screen(() => import("./screens/network/ChatConversationScreen"), "ChatConversationScreen");
const ChatsListScreen = screen(() => import("./screens/chat/ChatsListScreen"), "ChatsListScreen");
const ContactsListScreen = screen(() => import("./screens/contacts/ContactsListScreen"), "ContactsListScreen");
const CallsHistoryScreen = screen(() => import("./screens/calls/CallsHistoryScreen"), "CallsHistoryScreen");
const CircleManagementScreen = screen(() => import("./screens/network/CircleManagementScreen"), "CircleManagementScreen");
const CircleJoinScreen = screen(() => import("./screens/network/CircleJoinScreen"), "CircleJoinScreen");

// Devices
const DV01DevicesList = screen(() => import("./screens/devices/DV01DevicesList"), "DV01DevicesList");
const DV03DeviceDetail = screen(() => import("./screens/devices/DV03DeviceDetail"), "DV03DeviceDetail");
const DV06SecurityScan = screen(() => import("./screens/devices/DV06SecurityScan"), "DV06SecurityScan");
const DV11SmartHome = screen(() => import("./screens/devices/DV11SmartHome"), "DV11SmartHome");

// Cloud Storage (All Files)
const CS01StorageOverview = screen(() => import("./screens/storage/CS01StorageOverview"), "CS01StorageOverview");
const CS02FileDetail = screen(() => import("./screens/storage/CS02FileDetail"), "CS02FileDetail");
const CS03SecureTransfers = screen(() => import("./screens/storage/CS03SecureTransfers"), "CS03SecureTransfers");

// Settings
const ST01SettingsRoot = screen(() => import("./screens/settings/ST01SettingsRoot"), "ST01SettingsRoot");
const ST02GuardianInfo = screen(() => import("./screens/settings/ST02GuardianInfo"), "ST02GuardianInfo");
const ST03Profile = screen(() => import("./screens/settings/ST03Profile"), "ST03Profile");
const ST04DataUsage = screen(() => import("./screens/settings/ST04DataUsage"), "ST04DataUsage");
const ST05BackupRestore = screen(() => import("./screens/settings/ST05BackupRestore"), "ST05BackupRestore");
const ST07Geofencing = screen(() => import("./screens/settings/ST07Geofencing"), "ST07Geofencing");
const ST08DevicePairing = screen(() => import("./screens/settings/ST08DevicePairing"), "ST08DevicePairing");
const ST09ManageGuardians = screen(() => import("./screens/settings/ST09ManageGuardians"), "ST09ManageGuardians");
const ST10DeviceSettings = screen(() => import("./screens/settings/ST10DeviceSettings"), "ST10DeviceSettings");
const ST11Notifications = screen(() => import("./screens/settings/ST11Notifications"), "ST11Notifications");
const ST12AlertRules = screen(() => import("./screens/settings/ST12AlertRules"), "ST12AlertRules");
const ST13DualWifi = screen(() => import("./screens/settings/ST13DualWifi"), "ST13DualWifi");
const ST14QuickStartGuide = screen(() => import("./screens/settings/ST14QuickStartGuide"), "ST14QuickStartGuide");
const ST15AppVersion = screen(() => import("./screens/settings/ST15AppVersion"), "ST15AppVersion");
const ST16PendingApprovals = screen(() => import("./screens/settings/ST16PendingApprovals"), "ST16PendingApprovals");
const STTopology = screen(() => import("./screens/settings/STTopology"), "STTopology");

// Key Management / Integrity / Security / Policy / Logs
const KM01KeyManagement = screen(() => import("./screens/keys/KM01KeyManagement"), "KM01KeyManagement");
const IN01IntegrityDashboard = screen(() => import("./screens/integrity/IN01IntegrityDashboard"), "IN01IntegrityDashboard");
const SC01BootStatus = screen(() => import("./screens/security/SC01BootStatus"), "SC01BootStatus");
const SC02AttestationStatus = screen(() => import("./screens/security/SC02AttestationStatus"), "SC02AttestationStatus");
const SC03DIDStatus = screen(() => import("./screens/security/SC03DIDStatus"), "SC03DIDStatus");
const SC04VirtualId = screen(() => import("./screens/security/SC04VirtualId"), "SC04VirtualId");
const SC05CRLStatus = screen(() => import("./screens/security/SC05CRLStatus"), "SC05CRLStatus");
const PL01PolicyManagement = screen(() => import("./screens/policy/PL01PolicyManagement"), "PL01PolicyManagement");
const LG01LogsViewer = screen(() => import("./screens/logs/LG01LogsViewer"), "LG01LogsViewer");

// Network: Transport + Relay + Discovery
const NW05TransportStatus = screen(() => import("./screens/network/NW05TransportStatus"), "NW05TransportStatus");
const NW06RelayList = screen(() => import("./screens/network/NW06RelayList"), "NW06RelayList");
const NW07Discovery = screen(() => import("./screens/network/NW07Discovery"), "NW07Discovery");

// Verifiable Credentials
const VC01CredentialsList = screen(() => import("./screens/credentials/VC01CredentialsList"), "VC01CredentialsList");

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Root,
    ErrorBoundary: SYS01NotFound,
    children: [
      // Root â†’ splash
      { index: true, Component: SYS02SplashScreen },

      // Login (returning users, session expired)
      { path: "login", Component: LoginScreen },
      { path: "auth/cylenium/callback", Component: CyleniumCallback },
      { path: "auth/callback", Component: CyleniumCallback },
      { path: "signup", loader: () => redirect("/onboarding") },

      // Onboarding flow
      {
        path: "onboarding",
        Component: OnboardingLayout,
        children: [
          {
            Component: OnboardingEntryRoute,
            children: [
              { index: true, Component: OB06AccountSetup },
              { path: "welcome", Component: OB01Welcome },
              { path: "account", Component: OB06AccountSetup },
            ],
          },
          {
            Component: AuthenticatedOnboardingRoute,
            children: [
              { path: "pairing", Component: OB02HardwarePairing },
              { path: "connecting", Component: OB03Connecting },
              { path: "success", Component: OB04PairingSuccess },
              { path: "failed", Component: OB05PairingFailed },
              { path: "did", Component: OB07DIDIntroduction },
              { path: "circle", Component: OB08CreateFirstCircle },
              { path: "complete", Component: OB09OnboardingComplete },
            ],
          },
        ],
      },

      // Main app (with bottom nav) â€” requires auth
      {
        Component: ProtectedRoute,
        children: [{
          Component: MainLayout,
          children: [
            // Home tab
            {
              path: "home",
              children: [
                { index: true, Component: HM01Dashboard },
                { path: "guardian", Component: HM02GuardianDetail },
                { path: "topology", Component: HM03NetworkTopology },
              ],
            },

            // Catch /dashboard â†’ /home  (QA-6)
            { path: "dashboard", loader: () => redirect("/home") },

            // Alerts tab
            {
              path: "alerts",
              children: [
                { index: true, Component: AL01AlertsList },
                { path: "threat", Component: AL08ThreatProtection },
                { path: ":id", Component: AL06AlertDetail },
                { path: ":id/ai", Component: AL07AIRecommendation },
              ],
            },

            // Full notification history
            { path: "notifications", Component: NT01Notifications },

            // Standalone peer-to-peer messaging (Circle membership is not required)
            { path: "chats", Component: ChatsListScreen },
            { path: "chats/:peerDid", Component: ChatConversationScreen },
            { path: "contacts", Component: ContactsListScreen },
            { path: "calls", Component: CallsHistoryScreen },

            // Network / Circles tab
            {
              path: "network",
              children: [
                { index: true, Component: NW01CirclesList },
                { path: "peers", Component: NW03PeersList },
                { path: "create", Component: NW02CreateCircle },
                { path: "join", Component: CircleJoinScreen },
                { path: ":circleId/manage", Component: CircleManagementScreen },
                { path: ":circleId/chat", Component: ChatConversationScreen },
                { path: ":circleId/members/:peerDid/chat", Component: ChatConversationScreen },
                { path: "transport", Component: NW05TransportStatus },
                { path: "relay", Component: NW06RelayList },
                { path: "discovery", Component: NW07Discovery },
                { path: ":circleId", Component: NW04CircleDetail },
              ],
            },

            // Devices tab
            {
              path: "devices",
              children: [
                { index: true, Component: DV01DevicesList },
                { path: "smart-home", Component: DV11SmartHome },
                { path: ":id", Component: DV03DeviceDetail },
                { path: ":id/scan", Component: DV06SecurityScan },
              ],
            },

            // Cloud Storage tab
            {
              path: "storage",
              children: [
                { index: true, Component: CS01StorageOverview },
                { path: "transfers", Component: CS03SecureTransfers },
                { path: ":fileId", Component: CS02FileDetail },
              ],
            },

            // Settings tab
            {
              path: "settings",
              children: [
                { index: true, Component: ST01SettingsRoot },
                { path: "guardian", Component: ST02GuardianInfo },
                { path: "profile", Component: ST03Profile },
                { path: "data-usage", Component: ST04DataUsage },
                { path: "backup", Component: ST05BackupRestore },
                { path: "topology", Component: STTopology },
                { path: "peers", Component: NW03PeersList },
                { path: "geofencing", Component: ST07Geofencing },
                { path: "device-pairing", Component: ST08DevicePairing },
                { path: "guardians", Component: ST09ManageGuardians },
                { path: "device-settings", Component: ST10DeviceSettings },
                { path: "notifications", Component: ST11Notifications },
                { path: "pending-approvals", Component: ST16PendingApprovals },
                { path: "alert-rules", Component: ST12AlertRules },
                { path: "dual-wifi", Component: ST13DualWifi },
                { path: "guide", Component: ST14QuickStartGuide },
                { path: "version", Component: ST15AppVersion },
                { path: "keys", Component: KM01KeyManagement },
                { path: "integrity", Component: IN01IntegrityDashboard },
                { path: "boot-status", Component: SC01BootStatus },
                { path: "attestation", Component: SC02AttestationStatus },
                { path: "did", Component: SC03DIDStatus },
                { path: "crl", Component: SC05CRLStatus },
                { path: "virtual-id", Component: SC04VirtualId },
                { path: "transport", Component: NW05TransportStatus },
                { path: "relay", Component: NW06RelayList },
                { path: "discovery", Component: NW07Discovery },
                { path: "policy", Component: PL01PolicyManagement },
                { path: "logs", Component: LG01LogsViewer },
                { path: "credentials", Component: VC01CredentialsList },
              ],
            },

            // Key Management (standalone route)
            {
              path: "keys",
              children: [
                { index: true, Component: KM01KeyManagement },
              ],
            },

            // Integrity (standalone route)
            {
              path: "integrity",
              children: [
                { index: true, Component: IN01IntegrityDashboard },
              ],
            },

            // Boot Status (standalone route)
            {
              path: "boot-status",
              children: [
                { index: true, Component: SC01BootStatus },
              ],
            },

            // Peers (standalone route)
            {
              path: "peers",
              children: [
                { index: true, Component: NW03PeersList },
              ],
            },

            // Attestation (standalone route)
            {
              path: "attestation",
              children: [
                { index: true, Component: SC02AttestationStatus },
              ],
            },

            // Policy Management (standalone route)
            {
              path: "policy",
              children: [
                { index: true, Component: PL01PolicyManagement },
              ],
            },

            // Logs (standalone route)
            {
              path: "logs",
              children: [
                { index: true, Component: LG01LogsViewer },
              ],
            },

            // DID (standalone route)
            {
              path: "did",
              children: [
                { index: true, Component: SC03DIDStatus },
              ],
            },

            // Virtual ID (standalone route)
            {
              path: "virtual-id",
              children: [
                { index: true, Component: SC04VirtualId },
              ],
            },

            // Transport (standalone route)
            {
              path: "transport",
              children: [
                { index: true, Component: NW05TransportStatus },
              ],
            },

            // Relay (standalone route)
            {
              path: "relay",
              children: [
                { index: true, Component: NW06RelayList },
              ],
            },

            // Network Discovery (standalone route)
            {
              path: "discovery",
              children: [
                { index: true, Component: NW07Discovery },
              ],
            },

          ],
        }]
      },

      // Catch-all â†’ 404
      { path: "*", Component: SYS01NotFound },
    ],
  },
]);
