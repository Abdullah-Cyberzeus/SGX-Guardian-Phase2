import { useEffect } from "react";
import { useNavigate } from "react-router";
import { X } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { useNotifications, type NotificationToast } from "../../contexts/NotificationContext";
import { notificationIcon, severityColor, notificationRoute } from "./notificationVisuals";

const AUTO_DISMISS_MS: Record<string, number> = {
  critical: 12000,
  high: 10000,
  medium: 7000,
  low: 6000,
  info: 6000,
};

function ToastCard({ toast, onClose }: { toast: NotificationToast; onClose: () => void }) {
  const navigate = useNavigate();
  const { markRead } = useNotifications();
  const Icon = notificationIcon(toast.kind);
  const color = severityColor(toast.severity);

  useEffect(() => {
    const ms = AUTO_DISMISS_MS[toast.severity] ?? 6000;
    const timer = window.setTimeout(onClose, ms);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toast.toastId]);

  const handleClick = () => {
    if (!toast.read) markRead(toast.id).catch(() => undefined);
    const route = notificationRoute(toast.kind, toast.refId);
    onClose();
    if (route) navigate(route);
  };

  return (
    <div className="notify-toast" role="alert" onClick={handleClick}>
      <div className="notify-toast-icon" style={{ color, backgroundColor: `color-mix(in srgb, ${color} 16%, transparent)` }}>
        <Icon size={18} />
      </div>
      <div className="notify-toast-body">
        <strong>{toast.title}</strong>
        {toast.body && <span>{toast.body}</span>}
      </div>
      <button className="notify-toast-close" aria-label="Dismiss notification" onClick={(e) => { e.stopPropagation(); onClose(); }}>
        <X size={14} />
      </button>
    </div>
  );
}

export function NotificationToastStack() {
  const { session } = useAuth();
  const { toasts, dismissToast } = useNotifications();
  if (!session || toasts.length === 0) return null;
  return (
    <div className="notify-toast-stack">
      {toasts.map((toast) => (
        <ToastCard key={toast.toastId} toast={toast} onClose={() => dismissToast(toast.toastId)} />
      ))}
    </div>
  );
}
