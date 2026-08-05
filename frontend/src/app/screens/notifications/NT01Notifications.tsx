import { Bell, CheckCheck, Loader2, RefreshCw, Settings } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import type { NotificationItem } from "../../../api/notifications";
import { PageHeader } from "../../components/PageHeader";
import { notificationIcon, notificationRoute, relativeTime, severityColor } from "../../components/notifications/notificationVisuals";
import { useNotifications } from "../../contexts/NotificationContext";

type Filter = "all" | "unread" | "read";

export function NT01Notifications() {
  const navigate = useNavigate();
  const { items, unreadCount, connected, refresh, markRead, markAllRead } = useNotifications();
  const [filter, setFilter] = useState<Filter>("all");
  const [refreshing, setRefreshing] = useState(false);
  const visibleItems = useMemo(
    () => items.filter((item) => filter === "all" || (filter === "read" ? item.read : !item.read)),
    [filter, items],
  );

  const openNotification = async (item: NotificationItem) => {
    if (!item.read) await markRead(item.id);
    const route = notificationRoute(item.kind, item.refId);
    if (route) navigate(route);
  };

  const reload = async () => {
    setRefreshing(true);
    try { await refresh(); }
    catch (cause) { toast.error(cause instanceof Error ? cause.message : "Notifications could not be refreshed"); }
    finally { setRefreshing(false); }
  };

  const markEverythingRead = async () => {
    await markAllRead();
    toast.success("All notifications marked as read");
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="Notifications"
        subtitle={`${unreadCount} unread · ${connected ? "Live updates connected" : "Reconnecting to live updates"}`}
        showBack={false}
        large
        right={
          <button onClick={() => navigate("/settings/notifications")} className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm" style={{ color: "var(--foreground)", background: "var(--card)" }}>
            <Settings size={16} /><span className="hidden sm:inline">Preferences</span>
          </button>
        }
      />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-4xl p-4 md:p-6 pb-24">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex rounded-lg border border-border overflow-hidden" style={{ background: "var(--card)" }}>
              {(["all", "unread", "read"] as Filter[]).map((value) => (
                <button key={value} onClick={() => setFilter(value)} className="px-3.5 py-2 text-sm capitalize" style={{ border: 0, borderRight: value !== "read" ? "1px solid var(--border)" : undefined, background: filter === value ? "color-mix(in srgb, var(--primary) 12%, transparent)" : "transparent", color: filter === value ? "var(--primary)" : "var(--muted-foreground)", fontWeight: filter === value ? 600 : 400 }}>
                  {value}{value === "unread" && unreadCount > 0 ? ` (${unreadCount})` : ""}
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <button onClick={() => void reload()} disabled={refreshing} className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm disabled:opacity-50" style={{ background: "var(--card)", color: "var(--foreground)" }}>
                {refreshing ? <Loader2 className="animate-spin" size={15} /> : <RefreshCw size={15} />} Refresh
              </button>
              {unreadCount > 0 && <button onClick={() => void markEverythingRead()} className="flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium" style={{ border: 0, background: "var(--primary)", color: "var(--primary-foreground)" }}><CheckCheck size={15} /> Mark all read</button>}
            </div>
          </div>

          <div className="rounded-xl border border-border overflow-hidden" style={{ background: "var(--card)" }}>
            {visibleItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center text-center p-12 gap-3">
                <Bell size={30} style={{ color: "var(--muted-foreground)" }} />
                <p className="font-semibold" style={{ color: "var(--foreground)" }}>{filter === "all" ? "No notifications yet" : `No ${filter} notifications`}</p>
                <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>New notifications will appear here automatically.</p>
              </div>
            ) : visibleItems.map((item, index) => {
              const Icon = notificationIcon(item.kind);
              const color = severityColor(item.severity);
              const route = notificationRoute(item.kind, item.refId);
              return (
                <button key={item.id} onClick={() => void openNotification(item)} className="relative w-full flex items-start gap-3 p-4 md:p-5 text-left transition-colors hover:bg-muted/40" style={{ border: 0, borderBottom: index < visibleItems.length - 1 ? "1px solid var(--border)" : undefined, background: item.read ? "transparent" : "color-mix(in srgb, var(--primary) 6%, transparent)", cursor: "pointer" }}>
                  <div className="shrink-0 w-10 h-10 rounded-xl grid place-items-center" style={{ color, background: `color-mix(in srgb, ${color} 16%, transparent)` }}><Icon size={19} /></div>
                  <div className="min-w-0 flex-1 pr-4">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <strong className="text-sm" style={{ color: "var(--foreground)" }}>{item.title}</strong>
                      <span className="text-[10px] uppercase rounded-full px-2 py-0.5" style={{ color, background: `color-mix(in srgb, ${color} 12%, transparent)` }}>{item.severity}</span>
                    </div>
                    {item.body && <p className="text-sm mt-1 leading-relaxed" style={{ color: "var(--muted-foreground)" }}>{item.body}</p>}
                    <p className="text-xs mt-2" style={{ color: "var(--muted-foreground)" }}>{relativeTime(item.createdAt)} · {new Date(item.createdAt).toLocaleString()}{route ? " · Open details" : ""}</p>
                  </div>
                  {!item.read && <span className="absolute top-5 right-4 w-2 h-2 rounded-full" style={{ background: "var(--primary)" }} aria-label="Unread" />}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
