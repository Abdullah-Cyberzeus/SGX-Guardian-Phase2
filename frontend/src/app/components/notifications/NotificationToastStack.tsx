import { useEffect } from "react";
import { useNavigate } from "react-router";
import { MessageCircle, X } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { useNotifications, type NotificationToast } from "../../contexts/NotificationContext";
import { useChatUnread, type MessageToast } from "../../contexts/ChatUnreadContext";
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

function MessageToastCard({ toast, onClose }: { toast: MessageToast; onClose: () => void }) {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = window.setTimeout(onClose, 5_000);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toast.toastId]);

  const openConversation = () => {
    onClose();
    navigate(toast.mode === "group"
      ? `/network/${encodeURIComponent(toast.conversationId)}/chat`
      : `/chats/${encodeURIComponent(toast.conversationId)}`);
  };

  return (
    <div className="notify-toast chat-message-toast" role="alert" onClick={openConversation}>
      <div className="notify-toast-icon chat-message-toast__icon"><MessageCircle size={18} /></div>
      <div className="notify-toast-body">
        <strong>{toast.title}</strong>
        {toast.mode === "group" && <small>{toast.sender}</small>}
        <span>{toast.text}</span>
      </div>
      <button className="notify-toast-close" aria-label="Dismiss message" onClick={(event) => { event.stopPropagation(); onClose(); }}><X size={14} /></button>
    </div>
  );
}

export function NotificationToastStack() {
  const { session } = useAuth();
  const { toasts, dismissToast } = useNotifications();
  const { messageToasts, dismissMessageToast } = useChatUnread();
  if (!session || (toasts.length === 0 && messageToasts.length === 0)) return null;
  return (
    <div className="notify-toast-stack">
      {messageToasts.map((toast) => <MessageToastCard key={toast.toastId} toast={toast} onClose={() => dismissMessageToast(toast.toastId)} />)}
      {toasts.map((toast) => (
        <ToastCard key={toast.toastId} toast={toast} onClose={() => dismissToast(toast.toastId)} />
      ))}
    </div>
  );
}
