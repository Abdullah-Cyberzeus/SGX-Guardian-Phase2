import { useNavigate } from "react-router";
import { BookOpen, ChevronRight, Fingerprint, Info } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { NotificationDeliverySettings } from "../../components/settings/NotificationDeliverySettings";
import { PwaStorageControls } from "../../components/PwaStorageControls";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import { useAuth } from "../../contexts/AuthContext";

function InfoTooltip({ label, placement = "bottom", children }: { label: string; placement?: "top" | "bottom"; children: React.ReactNode }) {
  return (
    <span className="group relative inline-flex">
      <button
        type="button"
        className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition hover:bg-muted hover:text-foreground focus:bg-muted focus:text-foreground focus:outline-none focus:ring-2 focus:ring-primary/20"
        aria-label={label}
      >
        <Info size={15} />
      </button>
      <span className={`pointer-events-none absolute left-0 z-30 hidden w-[min(20rem,calc(100vw-2rem))] rounded-md border border-border bg-popover px-3 py-2 text-left text-xs leading-5 text-popover-foreground shadow-lg group-hover:block group-focus-within:block ${placement === "top" ? "bottom-8" : "top-8"}`}>
        {children}
      </span>
    </span>
  );
}

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
            <div className="rounded-lg border border-border overflow-visible divide-y divide-border" style={{ backgroundColor: "var(--card)" }}>
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
                  <div className="flex items-center gap-1.5">
                    <p className="text-sm text-foreground">Guardian fingerprint</p>
                    <InfoTooltip label="About Guardian fingerprint" placement="top">
                      This is a short ID for this Guardian. Support may ask for it to confirm which device you are using, even when the Guardian is offline.
                    </InfoTooltip>
                  </div>
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
