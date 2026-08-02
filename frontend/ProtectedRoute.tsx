import { Outlet } from "react-router";
import type { ReactNode } from "react";
import { ThemeProvider } from "./contexts/ThemeContext";
import { AuthProvider } from "./contexts/AuthContext";
import { VaultProvider } from "./contexts/VaultContext";
import { DaemonRestartProvider } from "./contexts/DaemonRestartContext";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { DaemonRestartBanner } from "./components/DaemonRestartBanner";
import { CallProvider, useCall } from "../features/calls/CallContext";
import { GroupCallProvider } from "../features/calls/GroupCallContext";
import { CallingScreen } from "../features/calls/CallingScreen";
import { IncomingCallDialog } from "../features/calls/IncomingCallDialog";
import { GroupCallingScreen } from "../features/calls/GroupCallingScreen";
import { IncomingGroupCallDialog } from "../features/calls/IncomingGroupCallDialog";

function CallingRuntime({ children }: { children: ReactNode }) {
  const { currentDevice, call, error } = useCall();
  return (
    <GroupCallProvider localDevice={currentDevice}>
      {children}
      <IncomingCallDialog />
      <CallingScreen />
      <IncomingGroupCallDialog />
      <GroupCallingScreen localDevice={currentDevice} />
      {!call && error && <div className="call-runtime-notice" role="alert">{error}</div>}
    </GroupCallProvider>
  );
}

export function Root() {
  return (
    <ThemeProvider>
      <div style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <AuthProvider>
          <CallProvider>
            <CallingRuntime>
              <VaultProvider>
                <DaemonRestartProvider>
                  <ErrorBoundary>
                    <DaemonRestartBanner />
                    <Outlet />
                  </ErrorBoundary>
                </DaemonRestartProvider>
              </VaultProvider>
            </CallingRuntime>
          </CallProvider>
        </AuthProvider>
      </div>
    </ThemeProvider>
  );
}
