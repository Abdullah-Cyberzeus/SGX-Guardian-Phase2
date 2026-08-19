import { useState } from "react";
import { Check, Pencil } from "lucide-react";
import { toast } from "sonner";
import * as Switch from "@radix-ui/react-switch";
import { Card } from "../ui/card";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { useAuth } from "../../contexts/AuthContext";

interface ToggleRowProps {
  label: string;
  description: string;
  checked: boolean;
  disabled: boolean;
  onCheckedChange: () => void;
}

function ToggleRow({ label, description, checked, disabled, onCheckedChange }: ToggleRowProps) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-4">
      <div className="flex-1">
        <p className="text-sm font-medium text-foreground">{label}</p>
        <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>
      </div>
      <Switch.Root
        checked={checked}
        disabled={disabled}
        onCheckedChange={onCheckedChange}
        style={{
          width: "44px",
          height: "24px",
          borderRadius: "12px",
          backgroundColor: checked ? "var(--primary)" : "var(--muted)",
          border: "none",
          cursor: disabled ? "wait" : "pointer",
          opacity: disabled ? 0.6 : 1,
          position: "relative",
          flexShrink: 0,
          transition: "background-color 0.2s",
        }}
      >
        <Switch.Thumb
          style={{
            display: "block",
            width: "18px",
            height: "18px",
            borderRadius: "50%",
            backgroundColor: "white",
            transform: checked ? "translateX(22px)" : "translateX(3px)",
            transition: "transform 0.2s",
          }}
        />
      </Switch.Root>
    </div>
  );
}

interface PrivacySettingsProps {
  /** ST03Profile already has its own name editor wired to the same
   * endpoint — set false there to avoid a second, duplicate one. */
  showNameEditor?: boolean;
}

/**
 * Display name + Guardian-enforced privacy toggles (hide presence / read
 * receipts / typing). Shared between the admin (`ST03Profile`) and member
 * (`MemberSettingsScreen`) settings surfaces — both PATCH the same
 * self-service `/auth/profile` endpoint.
 */
export function PrivacySettings({ showNameEditor = true }: PrivacySettingsProps) {
  const { session, updateProfile } = useAuth();
  const user = session?.user;
  const [editingName, setEditingName] = useState(false);
  const [name, setName] = useState(user?.name ?? "");
  const [savingName, setSavingName] = useState(false);
  const [savingKey, setSavingKey] = useState<string | null>(null);

  const saveName = async () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    setSavingName(true);
    try {
      const { error } = await updateProfile({ name: trimmed });
      if (error) throw new Error(error);
      toast.success("Display name updated");
      setEditingName(false);
    } catch (cause) {
      toast.error("Could not update display name", {
        description: cause instanceof Error ? cause.message : undefined,
      });
      setName(user?.name ?? "");
    } finally {
      setSavingName(false);
    }
  };

  const toggle = async (key: "hidePresence" | "hideReadReceipts" | "hideTyping", current: boolean) => {
    setSavingKey(key);
    try {
      const { error } = await updateProfile({ [key]: !current });
      if (error) throw new Error(error);
    } catch (cause) {
      toast.error("Could not update privacy setting", {
        description: cause instanceof Error ? cause.message : undefined,
      });
    } finally {
      setSavingKey(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {showNameEditor && (
        <div>
          <p className="mb-2 pl-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Display name
          </p>
          <Card className="flex-row items-center gap-3 p-4">
            {editingName ? (
              <>
                <Input
                  autoFocus
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  className="flex-1"
                  maxLength={80}
                />
                <Button size="sm" onClick={() => void saveName()} disabled={savingName || !name.trim()}>
                  <Check size={14} /> Save
                </Button>
              </>
            ) : (
              <>
                <p className="flex-1 text-sm font-medium text-foreground">{user?.name || "Unnamed"}</p>
                <Button size="sm" variant="outline" onClick={() => { setName(user?.name ?? ""); setEditingName(true); }}>
                  <Pencil size={13} /> Edit
                </Button>
              </>
            )}
          </Card>
          <p className="mt-1.5 pl-1 text-xs text-muted-foreground">
            Visible to other members and the administrator on this Guardian.
          </p>
        </div>
      )}

      <div>
        <p className="mb-2 pl-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Privacy
        </p>
        <div className="rounded-lg border border-border overflow-hidden divide-y divide-border" style={{ backgroundColor: "var(--card)" }}>
          <ToggleRow
            label="Hide online status"
            description="Other members and the administrator won't see when you're online or your last-seen time."
            checked={Boolean(user?.hidePresence)}
            disabled={savingKey === "hidePresence"}
            onCheckedChange={() => void toggle("hidePresence", Boolean(user?.hidePresence))}
          />
          <ToggleRow
            label="Hide read receipts"
            description="Others won't see when you've read their messages — and you won't see theirs either."
            checked={Boolean(user?.hideReadReceipts)}
            disabled={savingKey === "hideReadReceipts"}
            onCheckedChange={() => void toggle("hideReadReceipts", Boolean(user?.hideReadReceipts))}
          />
          <ToggleRow
            label="Hide typing indicator"
            description="Others won't see a typing indicator while you're composing a message."
            checked={Boolean(user?.hideTyping)}
            disabled={savingKey === "hideTyping"}
            onCheckedChange={() => void toggle("hideTyping", Boolean(user?.hideTyping))}
          />
        </div>
      </div>
    </div>
  );
}
