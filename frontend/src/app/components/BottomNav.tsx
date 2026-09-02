import { useLocation, useNavigate } from "react-router";
import { Home, Bell, Cpu, Cloud, Settings, MessageSquare, Phone, Users, Link2 } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { isMemberRole } from "../utils/authorization";

// Custom Network-as-circles icon
function NetworkCirclesIcon({ size = 20, color = "currentColor", strokeWidth = 1.75 }: { size?: number; color?: string; strokeWidth?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
      {/* Centre node */}
      <circle cx="12" cy="12" r="3" />
      {/* Top node */}
      <circle cx="12" cy="4" r="2" />
      {/* Bottom-left node */}
      <circle cx="4.5" cy="18" r="2" />
      {/* Bottom-right node */}
      <circle cx="19.5" cy="18" r="2" />
      {/* Edges */}
      <line x1="12" y1="9" x2="12" y2="6" />
      <line x1="10.3" y1="14.2" x2="6.1" y2="16.5" />
      <line x1="13.7" y1="14.2" x2="17.9" y2="16.5" />
    </svg>
  );
}

const adminTabs = [
  { label: "Home", icon: Home, path: "/home", custom: false },
  { label: "Alerts", icon: Bell, path: "/alerts", custom: false },
  { label: "Chats", icon: MessageSquare, path: "/chats", custom: false },
  { label: "Circles", icon: null, path: "/network", custom: true },
  { label: "Devices", icon: Cpu, path: "/devices", custom: false },
  { label: "All Files", icon: Cloud, path: "/storage", custom: false },
  { label: "Settings", icon: Settings, path: "/settings", custom: false },
];

const memberTabs = [
  { label: "Messages", icon: MessageSquare, path: "/chats", custom: false },
  { label: "Calls", icon: Phone, path: "/calls", custom: false },
  { label: "Contacts", icon: Users, path: "/contacts", custom: false },
  { label: "Files", icon: Cloud, path: "/storage", custom: false },
  { label: "Settings", icon: Settings, path: "/member-settings", custom: false },
];

const pendingMemberTabs = [
  { label: "Join", icon: Link2, path: "/join-circle", custom: false },
  { label: "Settings", icon: Settings, path: "/member-settings", custom: false },
];

export function BottomNav() {
  const location = useLocation();
  const navigate = useNavigate();
  const { session } = useAuth();
  const memberSession = isMemberRole(session?.user.role);
  const tabs = memberSession && (session?.circleIds.length || 0) === 0
    ? pendingMemberTabs
    : memberSession ? memberTabs : adminTabs;

  const isActive = (path: string) => location.pathname.startsWith(path);

  return (
    <nav
      className="border-t border-border"
      style={{
        backgroundColor: "var(--sidebar)",
        paddingBottom: "env(safe-area-inset-bottom, 0px)",
      }}
    >
      <div className="flex items-stretch" style={{ height: "60px" }}>
        {tabs.map(({ label, icon: Icon, path, custom }) => {
          const active = isActive(path);
          const iconColor = active ? "var(--primary)" : "var(--sidebar-foreground)";
          const sw = active ? 2.5 : 1.75;
          return (
            <button
              key={path}
              onClick={() => navigate(path)}
              className="flex-1 flex flex-col items-center justify-center gap-0.5"
              style={{
                minHeight: "44px",
                transition: `color var(--duration-base) var(--ease-out), opacity var(--duration-base) var(--ease-out), transform var(--duration-instant) var(--ease-out)`,
              }}
            >
              {custom ? (
                <NetworkCirclesIcon size={20} color={iconColor} strokeWidth={sw} />
              ) : (
                Icon && (
                  <Icon
                    size={20}
                    style={{ color: iconColor, strokeWidth: sw }}
                  />
                )
              )}
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "10px",
                  fontWeight: active ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                  color: iconColor,
                  lineHeight: 1.2,
                  transition: `color var(--duration-base) var(--ease-out), font-weight var(--duration-base) var(--ease-out)`,
                }}
              >
                {label}
              </span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
