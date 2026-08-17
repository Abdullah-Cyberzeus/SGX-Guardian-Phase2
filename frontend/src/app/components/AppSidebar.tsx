import { useEffect, useMemo } from "react";
import { useLocation, useNavigate } from "react-router";
import { Home, Bell, BellRing, Cpu, Cloud, Settings, MessageSquare, Phone } from "lucide-react";
import { mockGuardian, mockAlerts, mockDevices } from "../data/mockData";
import { useCurrentUser } from "../hooks/useCurrentUser";
import { useChatUnread } from "../contexts/ChatUnreadContext";
import { useCircleInviteInbox } from "../hooks/useApiData";
import { toast } from "sonner";
import logoSrc from "@/assets/sgx-guardian-logo.png";

const announcedCircleInviteIds = new Set<string>();

function NetworkCirclesIcon({ size = 20, color = "currentColor", strokeWidth = 1.75 }: {
  size?: number; color?: string; strokeWidth?: number;
}) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color}
      strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <circle cx="12" cy="4" r="2" />
      <circle cx="4.5" cy="18" r="2" />
      <circle cx="19.5" cy="18" r="2" />
      <line x1="12" y1="9" x2="12" y2="6" />
      <line x1="10.3" y1="14.2" x2="6.1" y2="16.5" />
      <line x1="13.7" y1="14.2" x2="17.9" y2="16.5" />
    </svg>
  );
}

const alertBadgeCount = mockAlerts.filter((a) => !a.archived && a.severity === "HIGH").length;
const deviceBadgeCount = mockDevices.filter((d) => d.category === "pending").length;

interface AppSidebarProps {
  /** "collapsed" = tablet icon-only, "expanded" = desktop with labels */
  variant: "collapsed" | "expanded";
}

export function AppSidebar({ variant }: AppSidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { name, initials } = useCurrentUser();
  const { total: unreadChats } = useChatUnread();
  const { data: inviteInbox } = useCircleInviteInbox();
  const isExpanded = variant === "expanded";
  const pendingCircleInvites = useMemo(
    () => (inviteInbox || []).filter((invite: any) => String(invite.state || invite.status || "").toLowerCase() === "pending"),
    [inviteInbox],
  );
  const circlesBadgeCount = pendingCircleInvites.length;

  useEffect(() => {
    pendingCircleInvites.forEach((invite: any) => {
      const id = String(invite.id || invite.invite_id || "");
      if (!id || announcedCircleInviteIds.has(id)) return;
      announcedCircleInviteIds.add(id);
      toast.info("New Circle Invitation", {
        description: invite.circleName ? `Circle: ${invite.circleName}` : undefined,
      });
    });
  }, [pendingCircleInvites]);

  const isActive = (path: string) => location.pathname.startsWith(path);

  const navItems = [
    { label: "Home", icon: Home, path: "/home", custom: false, badge: 0 },
    { label: "Alerts", icon: Bell, path: "/alerts", custom: false, badge: alertBadgeCount },
    { label: "Notifications", icon: BellRing, path: "/notifications", custom: false, badge: 0 },
    { label: "Chats", icon: MessageSquare, path: "/chats", custom: false, badge: unreadChats },
    { label: "Calls", icon: Phone, path: "/calls", custom: false, badge: 0 },
    { label: "Circles", icon: null, path: "/network", custom: true, badge: circlesBadgeCount },
    { label: "Devices", icon: Cpu, path: "/devices", custom: false, badge: deviceBadgeCount },
    { label: "All Files", icon: Cloud, path: "/storage", custom: false, badge: 0 },
    { label: "Settings", icon: Settings, path: "/settings", custom: false, badge: 0 },
  ];

  return (
    <aside
      className="flex flex-col border-r border-border flex-shrink-0 h-full"
      style={{
        width: isExpanded ? "240px" : "64px",
        backgroundColor: "var(--sidebar)",
        transition: "width 200ms var(--ease-out)",
      }}
    >
      {/* ── Logo / wordmark ── */}
      <div
        className="flex items-center border-b border-border flex-shrink-0"
        style={{
          height: "72px",
          padding: isExpanded ? "0 16px" : "0",
          justifyContent: isExpanded ? "flex-start" : "center",
          gap: isExpanded ? "10px" : "0",
        }}
      >
        <img
          src={logoSrc}
          alt="SG-X Guardian"
          style={{
            width: isExpanded ? "38px" : "34px",
            height: "auto",
            flexShrink: 0,
          }}
          draggable={false}
        />
        {isExpanded && (
          <div>
            <p style={{
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)", color: "var(--sidebar-foreground)",
              lineHeight: 1.2,
            }}>
              SG-X Guardian
            </p>
            <p style={{
              fontFamily: "Inter, sans-serif", fontSize: "10px",
              color: "var(--primary)", fontWeight: "var(--font-weight-medium)",
              letterSpacing: "0.06em", textTransform: "uppercase",
            }}>
              DEFEND. PROTECT. SECURE.
            </p>
          </div>
        )}
      </div>

      {/* ── Nav items ── */}
      <nav className="flex flex-col gap-1 flex-1 py-3" style={{ padding: isExpanded ? "12px 8px" : "12px 6px" }}>
        {navItems.map(({ label, icon: Icon, path, custom, badge }) => {
          const active = isActive(path);
          const iconColor = active ? "var(--primary)" : "var(--sidebar-foreground)";
          const sw = active ? 2.5 : 1.75;

          return (
            <div key={path} className="relative group">
              <button
                onClick={() => navigate(path)}
                className="w-full flex items-center rounded-lg transition-colors"
                style={{
                  height: "44px",
                  gap: isExpanded ? "12px" : "0",
                  padding: isExpanded ? "0 12px" : "0",
                  justifyContent: isExpanded ? "flex-start" : "center",
                  backgroundColor: active
                    ? "color-mix(in srgb, var(--primary) 15%, transparent)"
                    : "transparent",
                  border: "none",
                  cursor: "pointer",
                  borderLeft: active && isExpanded
                    ? "3px solid var(--primary)"
                    : "3px solid transparent",
                  borderRadius: "var(--radius)",
                }}
              >
                {/* Active accent bar for collapsed — left edge of sidebar */}
                {active && !isExpanded && (
                  <div
                    className="absolute left-0 top-1/2 -translate-y-1/2 rounded-r-full"
                    style={{ width: "4px", height: "26px", backgroundColor: "var(--primary)" }}
                  />
                )}

                <div className="relative flex-shrink-0">
                  {custom ? (
                    <NetworkCirclesIcon size={20} color={iconColor} strokeWidth={sw} />
                  ) : (
                    Icon && <Icon size={20} style={{ color: iconColor, strokeWidth: sw }} />
                  )}
                  {badge > 0 && (
                    <div
                      className="absolute flex items-center justify-center rounded-full"
                      style={{
                        top: "-5px", right: "-5px",
                        minWidth: "16px", height: "16px", padding: "0 3px",
                        backgroundColor: "var(--destructive)",
                        fontFamily: "Inter, sans-serif", fontSize: "9px",
                        fontWeight: "var(--font-weight-semibold)",
                        color: "var(--destructive-foreground)",
                      }}
                    >
                      {badge}
                    </div>
                  )}
                </div>

                {isExpanded && (
                  <span style={{
                    fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
                    fontWeight: active ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                    color: active ? "var(--primary)" : "var(--sidebar-foreground)",
                    flex: 1, textAlign: "left",
                  }}>
                    {label}
                  </span>
                )}

                {isExpanded && badge > 0 && (
                  <span
                    className="flex items-center justify-center rounded-full flex-shrink-0"
                    style={{
                      minWidth: "20px", height: "20px", padding: "0 5px",
                      backgroundColor: "var(--destructive)",
                      fontFamily: "Inter, sans-serif", fontSize: "10px",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--destructive-foreground)",
                    }}
                  >
                    {badge}
                  </span>
                )}
              </button>

              {/* Tooltip for collapsed */}
              {!isExpanded && (
                <div
                  className="absolute left-full top-1/2 -translate-y-1/2 ml-3 px-2 py-1 rounded pointer-events-none z-50
                    opacity-0 group-hover:opacity-100 transition-opacity"
                  style={{
                    backgroundColor: "var(--popover)",
                    border: "1px solid var(--border)",
                    boxShadow: "var(--elevation-sm)",
                    whiteSpace: "nowrap",
                  }}
                >
                  <span style={{
                    fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)", color: "var(--popover-foreground)",
                  }}>
                    {label}
                    {badge > 0 && ` (${badge})`}
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* ── Bottom: user + guardian status ── */}
      <div
        className="border-t border-border flex-shrink-0"
        style={{
          padding: isExpanded ? "12px 12px" : "12px 6px",
        }}
      >
        <div
          className="flex items-center rounded-lg"
          style={{
            gap: isExpanded ? "10px" : "0",
            justifyContent: isExpanded ? "flex-start" : "center",
            padding: "8px",
            backgroundColor: "color-mix(in srgb, var(--sidebar-accent) 60%, transparent)",
            borderRadius: "var(--radius)",
          }}
        >
          {/* Avatar — initials circle */}
          <div
            className="flex items-center justify-center rounded-full flex-shrink-0"
            style={{
              width: "34px", height: "34px",
              backgroundColor: "color-mix(in srgb, var(--primary) 18%, transparent)",
              border: "1.5px solid color-mix(in srgb, var(--primary) 30%, transparent)",
              position: "relative",
            }}
          >
            <span style={{
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)", color: "var(--primary)",
            }}>
              {initials}
            </span>
            {/* Guardian status dot */}
            <div
              className="absolute rounded-full"
              style={{
                bottom: "-1px", right: "-1px",
                width: "9px", height: "9px",
                backgroundColor: mockGuardian.status === "online" ? "var(--chart-2)" : "var(--destructive)",
                border: "1.5px solid var(--sidebar)",
              }}
            />
          </div>

          {isExpanded && (
            <div className="flex flex-col flex-1 min-w-0">
              <p className="truncate" style={{
                fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-semibold)", color: "var(--sidebar-foreground)",
                lineHeight: 1.3,
              }}>
                {name}
              </p>
              <p className="truncate" style={{
                fontFamily: "Inter, sans-serif", fontSize: "10px",
                color: mockGuardian.status === "online" ? "var(--chart-2)" : "var(--destructive)",
                lineHeight: 1.3,
              }}>
                {mockGuardian.name} · {mockGuardian.status === "online" ? "Online" : "Offline"}
              </p>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
