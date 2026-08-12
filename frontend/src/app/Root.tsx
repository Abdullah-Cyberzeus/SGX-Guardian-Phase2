import { Outlet, useLocation } from "react-router";
import type { ReactNode } from "react";
import { ThemeProvider } from "./contexts/ThemeContext";
import { AuthProvider } from "./contexts/AuthContext";
import { VaultProvider } from "./contexts/VaultContext";
import { DaemonRestartProvider } from "./contexts/DaemonRestartContext";
import { NotificationProvider, useNotifications } from "./contexts/NotificationContext";
import { ChatUnreadProvider } from "./contexts/ChatUnreadContext";
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
import { useAuth } from "./contexts/AuthContext";
import { isAdminRole } from "./utils/authorization";

function CallSurfaces({ children }: { children: ReactNode }) {
  const { currentDevice, call, error } = useCall();
  const { prefs } = useNotifications();
  const showIncomingCalls = prefs?.circles.incoming_call !== false;

  return (
    <GroupCallProvider localDevice={currentDevice}>
      {children}
      {showIncomingCalls && <IncomingCallDialog />}
      <CallingScreen />
      {showIncomingCalls && <IncomingGroupCallDialog />}
      <GroupCallingScreen localDevice={currentDevice} />
      {!call && error && <div className="call-runtime-notice" role="alert">{error}</div>}
    </GroupCallProvider>
  );
}

function CallingRuntime({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const { prefs } = useNotifications();
  const showPendingApprovals = prefs?.devices.pending_approval !== false;

  // Certificate approval is an administrative Guardian operation. Keeping the
  // provider out of a member runtime also prevents its polling/socket clients
  // from touching certificate APIs in the background.
  if (!isAdminRole(session?.user.role)) {
    return <CallSurfaces>{children}</CallSurfaces>;
  }

  return (
    <CertificateRequestProvider>
      <CallSurfaces>
        {children}
        {showPendingApprovals && <IncomingCertificateRequestDialog />}
      </CallSurfaces>
    </CertificateRequestProvider>
  );
}

function RoleRuntime({ children }: { children: ReactNode }) {
  const { session } = useAuth();

  if (!isAdminRole(session?.user.role)) {
    return <ErrorBoundary>{children}</ErrorBoundary>;
  }

  return (
    <DaemonRestartProvider>
      <ErrorBoundary>
        <DaemonRestartBanner />
        {children}
      </ErrorBoundary>
    </DaemonRestartProvider>
  );
}

function AuthenticatedRuntime() {
  const { session, loading } = useAuth();
  const { pathname } = useLocation();
  const isPublicFlow = pathname === "/login"
    || pathname === "/join"
    || pathname === "/signup"
    || pathname.startsWith("/onboarding")
    || pathname.startsWith("/auth/");

  // Login, signup, and onboarding render without notification/call/certificate
  // streams. ProtectedRoute handles redirecting unauthenticated main routes.
  if (loading || !session || isPublicFlow) {
    return <ErrorBoundary><Outlet /></ErrorBoundary>;
  }

  return (
    <NotificationProvider>
      <ChatUnreadProvider>
        <CallProvider>
          <CallingRuntime>
            <VaultProvider>
              <RoleRuntime>
                  <NotificationToastStack />
                  <Outlet />
              </RoleRuntime>
            </VaultProvider>
          </CallingRuntime>
        </CallProvider>
      </ChatUnreadProvider>
    </NotificationProvider>
  );
}

export function Root() {
  return (
    <ThemeProvider>
      <div style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <AuthProvider>
          <AuthenticatedRuntime />
        </AuthProvider>
      </div>
    </ThemeProvider>
  );
}
