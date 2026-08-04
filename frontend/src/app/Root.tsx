import { Outlet } from "react-router";
import type { ReactNode } from "react";
import { ThemeProvider } from "./contexts/ThemeContext";
import { AuthProvider } from "./contexts/AuthContext";
import { VaultProvider } from "./contexts/VaultContext";
import { DaemonRestartProvider } from "./contexts/DaemonRestartContext";
import { NotificationProvider, useNotifications } from "./contexts/NotificationContext";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { DaemonRestartBanner } from "./components/DaemonRestartBanner";
import { NotificationToastStack } from "./components/notifications/NotificationToastStack";
import { CallProvider, useCall } from "../features/calls/CallContext";
import { GroupCallProvider } from "../features/calls/GroupCallContext";
import { CallingScreen } from "../features/calls/CallingScreen";
import { IncomingCallDialog } from "../features/calls/IncomingCallDialog";
import { GroupCallingScreen } from "../features/calls/GroupCallingScreen";
import { IncomingGroupCallDialog } from "../features/calls/IncomingGroupCallDialog";
import { CertificateRequestProvider } from "../features/certificates/CertificateRequestContext";
import { IncomingCertificateRequestDialog } from "../features/certificates/IncomingCertificateRequestDialog";

function CallingRuntime({ children }: { children: ReactNode }) {
  const { currentDevice, call, error } = useCall();
  const { prefs } = useNotifications();
  const showIncomingCalls = prefs?.circles.incoming_call !== false;
  const showPendingApprovals = prefs?.devices.pending_approval !== false;
  return (
    <GroupCallProvider localDevice={currentDevice}>
      <CertificateRequestProvider>
        {children}
        {showPendingApprovals && <IncomingCertificateRequestDialog />}
        {showIncomingCalls && <IncomingCallDialog />}
        <CallingScreen />
        {showIncomingCalls && <IncomingGroupCallDialog />}
        <GroupCallingScreen localDevice={currentDevice} />
        {!call && error && <div className="call-runtime-notice" role="alert">{error}</div>}
      </CertificateRequestProvider>
    </GroupCallProvider>
  );
}

export function Root() {
  return (
    <ThemeProvider>
      <div style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <AuthProvider>
          <NotificationProvider>
            <CallProvider>
              <CallingRuntime>
                <VaultProvider>
                  <DaemonRestartProvider>
                    <ErrorBoundary>
                      <DaemonRestartBanner />
                      <NotificationToastStack />
                      <Outlet />
                    </ErrorBoundary>
                  </DaemonRestartProvider>
                </VaultProvider>
              </CallingRuntime>
            </CallProvider>
          </NotificationProvider>
        </AuthProvider>
      </div>
    </ThemeProvider>
  );
}
