import { useNavigate } from "react-router";
import { BookOpen, ChevronRight, Fingerprint } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { NotificationDeliverySettings } from "../../components/settings/NotificationDeliverySettings";
import { PwaStorageControls } from "../../components/PwaStorageControls";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import { useAuth } from "../../contexts/AuthContext";

export function ST10DeviceSettings() {
  const navigate = useNavigate();
  const currentUser = useCurrentUser();
  const { session } = useAuth();

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Device Settings" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-6 pb-8">
          <NotificationDeliverySettings />

          <div>
            <p className="mb-2 pl-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Local data
            </p>
            <PwaStorageControls />
          </div>

          <div>
            <p className="mb-2 pl-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Support
            </p>
            <div className="rounded-lg border border-border overflow-hidden divide-y divide-border" style={{ backgroundColor: "var(--card)" }}>
              <button
                type="button"
                onClick={() => navigate("/settings/guide")}
                className="w-full flex items-center gap-3 px-4 py-4 text-left"
              >
                <BookOpen size={18} className="text-primary flex-shrink-0" />
                <span className="flex-1 text-sm text-foreground">Quick Start Guide</span>
                <ChevronRight size={16} className="text-muted-foreground" />
              </button>
              <div className="flex items-start gap-3 px-4 py-4">
                <Fingerprint size={18} className="mt-0.5 text-primary flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-sm text-foreground">Guardian fingerprint</p>
                  <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">
                    {session?.guardianFingerprint || "Unavailable"}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Have this ready when reaching out about this Guardian — it works without an
                    internet connection.
                  </p>
                </div>
              </div>
            </div>
          </div>
          <p className="pl-1 text-xs text-muted-foreground">
            Signed in as {currentUser.name} ({currentUser.role})
          </p>
        </div>
      </div>
    </div>
  );
}
