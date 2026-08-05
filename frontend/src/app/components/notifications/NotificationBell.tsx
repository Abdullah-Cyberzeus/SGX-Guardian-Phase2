import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { Bell, Check, Settings } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { useNotifications } from "../../contexts/NotificationContext";
import type { NotificationItem } from "../../../api/notifications";
import { notificationIcon, severityColor, notificationRoute, relativeTime } from "./notificationVisuals";

export function NotificationBell() {
  const { session } = useAuth();
  const { items, unreadCount, connected, markRead, markAllRead } = useNotifications();
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  if (!session) return null;

  const handleItemClick = (item: NotificationItem) => {
    if (!item.read) markRead(item.id).catch(() => undefined);
    const route = notificationRoute(item.kind, item.refId);
    setOpen(false);
    if (route) navigate(route);
  };

  return (
    <div className="notify-bell-wrap" ref={wrapRef}>
      <button className="notify-bell-btn" onClick={() => setOpen((v) => !v)} aria-label="Notifications">
        <Bell size={19} />
        {unreadCount > 0 && <span className="notify-bell-badge">{unreadCount > 99 ? "99+" : unreadCount}</span>}
        <span className={`notify-bell-dot${connected ? " is-live" : ""}`} title={connected ? "Live" : "Reconnecting…"} />
      </button>

      {open && (
        <div className="notify-panel" role="dialog" aria-label="Notifications">
          <div className="notify-panel-header">
            <span>Notifications</span>
            <div className="notify-panel-actions">
              {unreadCount > 0 && (
                <button onClick={() => markAllRead()}>
                  <Check size={13} /> Mark all read
                </button>
              )}
              <button aria-label="Notification settings" onClick={() => { setOpen(false); navigate("/settings/notifications"); }}>
                <Settings size={14} />
              </button>
            </div>
          </div>
          <div className="notify-panel-list">
            {items.length === 0 && <div className="notify-panel-empty">No notifications yet</div>}
            {items.map((item) => {
              const Icon = notificationIcon(item.kind);
              const color = severityColor(item.severity);
              return (
                <button
                  key={item.id}
                  className={`notify-panel-item${item.read ? "" : " is-unread"}`}
                  onClick={() => handleItemClick(item)}
                >
                  <div className="notify-panel-item-icon" style={{ color, backgroundColor: `color-mix(in srgb, ${color} 16%, transparent)` }}>
                    <Icon size={15} />
                  </div>
                  <div className="notify-panel-item-body">
                    <strong>{item.title}</strong>
                    {item.body && <span>{item.body}</span>}
                    <small>{relativeTime(item.createdAt)}</small>
                  </div>
                  {!item.read && <span className="notify-panel-item-dot" />}
                </button>
              );
            })}
          </div>
          <button className="notify-panel-view-all" onClick={() => { setOpen(false); navigate("/notifications"); }}>
            View all notifications
          </button>
        </div>
      )}
    </div>
  );
}
