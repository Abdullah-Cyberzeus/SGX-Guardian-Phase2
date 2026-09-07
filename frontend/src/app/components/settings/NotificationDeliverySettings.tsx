import { useEffect, useState } from "react";
import * as Switch from "@radix-ui/react-switch";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../ui/alert-dialog";
import {
  loadLocalNotificationPrefs,
  saveLocalNotificationPref,
  type LocalNotificationPrefs,
} from "../../lib/notificationLocalPrefs";
import { useNotifications } from "../../contexts/NotificationContext";
import { useAuth } from "../../contexts/AuthContext";

interface ToggleRowProps {
  label: string;
  description?: string;
  checked: boolean;
  disabled?: boolean;
  onCheckedChange: () => void;
}

function ToggleRow({ label, description, checked, disabled, onCheckedChange }: ToggleRowProps) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-4">
      <div className="flex-1">
        <p className="text-sm font-medium text-foreground">{label}</p>
        {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
      </div>
      <Switch.Root
        checked={checked}
        disabled={disabled}
        onCheckedChange={onCheckedChange}
        style={{
          width: "44px", height: "24px", borderRadius: "12px",
          backgroundColor: checked ? "var(--primary)" : "var(--muted)",
          border: "none", cursor: disabled ? "wait" : "pointer",
          opacity: disabled ? 0.6 : 1, position: "relative", flexShrink: 0,
          transition: "background-color 0.2s",
        }}
      >
        <Switch.Thumb
          style={{
            display: "block", width: "18px", height: "18px", borderRadius: "50%",
            backgroundColor: "white", transform: checked ? "translateX(22px)" : "translateX(3px)",
            transition: "transform 0.2s",
          }}
        />
      </Switch.Root>
    </div>
  );
}

/**
 * Local-only notification behavior: master on/off, sound, vibration, and a
 * Do Not Disturb window. None of this is synced to the backend — each
 * browser decides for itself (contrast with the Guardian-enforced category
 * preferences in ST11Notifications, or the privacy toggles in
 * PrivacySettings). Shared between admin (ST10DeviceSettings) and member
 * (MemberSettingsScreen) settings.
 */
export function NotificationDeliverySettings() {
  const { requestPermission, permission } = useNotifications();
  const { session } = useAuth();
  const scope = session?.browserMemberDid || session?.guardianDid;
  const [prefs, setPrefs] = useState<LocalNotificationPrefs | null>(null);
  const [permissionDialogOpen, setPermissionDialogOpen] = useState(false);

  useEffect(() => {
    void loadLocalNotificationPrefs(scope).then(setPrefs);
  }, [scope]);

  const update = async <K extends keyof LocalNotificationPrefs>(key: K, value: LocalNotificationPrefs[K]) => {
    setPrefs((current) => (current ? { ...current, [key]: value } : current));
    await saveLocalNotificationPref(scope, key, value);
  };

  const toggleMaster = async (next: boolean) => {
    if (next && permission === "default") {
      setPermissionDialogOpen(true);
      return;
    }
    await update("masterEnabled", next);
  };

  const confirmPermissionRequest = async () => {
    setPermissionDialogOpen(false);
    await requestPermission();
    await update("masterEnabled", true);
  };

  if (!prefs) return null;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <p className="mb-2 pl-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Notifications
        </p>
        <div className="rounded-lg border border-border overflow-hidden divide-y divide-border" style={{ backgroundColor: "var(--card)" }}>
          <ToggleRow
            label="Enable notifications"
            description="Turns all in-app and browser notifications on or off for this device."
            checked={prefs.masterEnabled}
            onCheckedChange={() => void toggleMaster(!prefs.masterEnabled)}
          />
        </div>
      </div>

      <div>
        <p className="mb-2 pl-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Do Not Disturb
        </p>
        <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
          <p className="mb-3 text-xs text-muted-foreground">
            Silences sound and vibration during this window. Notifications still arrive and are counted — they're just quiet.
          </p>
          <div className="flex items-center gap-3">
            <label className="flex-1">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">From</span>
              <input
                type="time"
                value={prefs.dndStart}
                onChange={(event) => void update("dndStart", event.target.value)}
                className="w-full rounded-md border border-border bg-transparent px-3 py-2 text-sm"
              />
            </label>
            <label className="flex-1">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">To</span>
              <input
                type="time"
                value={prefs.dndEnd}
                onChange={(event) => void update("dndEnd", event.target.value)}
                className="w-full rounded-md border border-border bg-transparent px-3 py-2 text-sm"
              />
            </label>
            {(prefs.dndStart || prefs.dndEnd) && (
              <button
                type="button"
                onClick={() => { void update("dndStart", ""); void update("dndEnd", ""); }}
                className="mt-5 text-xs text-muted-foreground underline"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      <p className="pl-1 text-xs text-muted-foreground">
        Notifications only arrive live while this browser tab is open and connected to your
        Guardian. When offline or closed, missed notifications appear as soon as you reconnect.
      </p>

      <AlertDialog open={permissionDialogOpen} onOpenChange={setPermissionDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Allow browser notifications?</AlertDialogTitle>
            <AlertDialogDescription>
              Guardian will ask your browser for permission to show notifications — for new
              messages, calls, and alerts — while this tab is open. You can turn this off again
              at any time.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Not now</AlertDialogCancel>
            <AlertDialogAction onClick={() => void confirmPermissionRequest()}>
              Continue
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
