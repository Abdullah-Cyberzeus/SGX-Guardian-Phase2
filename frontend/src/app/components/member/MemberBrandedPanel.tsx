import { Cloud, Phone, ShieldCheck, Settings, UsersRound } from "lucide-react";
import logoSrc from "@/assets/sgx-guardian-logo.png";

export type MemberBrandedPanelContext = "calls" | "contacts" | "files" | "settings";

const COPY: Record<MemberBrandedPanelContext, { icon: typeof Phone; title: string; description: string }> = {
  calls: {
    icon: Phone,
    title: "Calls",
    description: "Audio and video calls are relayed directly between Guardians and never touch a third-party server. Call a trusted contact any time.",
  },
  contacts: {
    icon: UsersRound,
    title: "Contacts",
    description: "Every contact here shares a Circle with you and has been attested by your Guardian. Message or call anyone from your roster in one tap.",
  },
  files: {
    icon: Cloud,
    title: "Files",
    description: "Files you upload or receive stay encrypted at rest and in transit — only Guardians you trust can decrypt what you share.",
  },
  settings: {
    icon: Settings,
    title: "Settings",
    description: "Manage your profile, privacy, and notification preferences for this Guardian session.",
  },
};

export function MemberBrandedPanel({ context }: { context: MemberBrandedPanelContext }) {
  const { icon: Icon, description } = COPY[context];
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-12 text-center" style={{ backgroundColor: "var(--muted)" }}>
      <div className="relative">
        <img src={logoSrc} alt="" draggable={false} style={{ width: "88px", height: "auto", opacity: 0.35 }} />
        <div
          className="absolute -bottom-1 -right-1 grid h-9 w-9 place-items-center rounded-full"
          style={{ backgroundColor: "var(--card)", border: "1px solid var(--border)" }}
        >
          <Icon size={16} style={{ color: "var(--primary)" }} />
        </div>
      </div>
      <div>
        <p className="text-lg font-semibold" style={{ color: "var(--foreground)" }}>SG-X Guardian</p>
        <p className="mt-1 text-xs font-medium uppercase tracking-wide" style={{ color: "var(--primary)" }}>Defend. Protect. Secure.</p>
      </div>
      <p className="max-w-xs text-sm leading-6" style={{ color: "var(--muted-foreground)" }}>{description}</p>
      <div className="mt-2 flex items-center gap-2 text-xs" style={{ color: "var(--muted-foreground)" }}>
        <ShieldCheck size={14} style={{ color: "var(--primary)" }} />
        End-to-end encrypted
      </div>
    </div>
  );
}
