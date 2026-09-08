import { useEffect } from "react";
import { useNavigate } from "react-router";
import { MessageCircle, X } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { useChatUnread, type MessageToast } from "../../contexts/ChatUnreadContext";
import { isMemberRole } from "../../utils/authorization";

function MessageToastCard({ toast, onClose }: { toast: MessageToast; onClose: () => void }) {
  const navigate = useNavigate();
  const { session } = useAuth();

  useEffect(() => {
    const timer = window.setTimeout(onClose, 5_000);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toast.toastId]);

  const openConversation = () => {
    onClose();
    navigate(toast.mode === "group"
      ? isMemberRole(session?.user.role)
        ? `/chats/circle/${encodeURIComponent(toast.conversationId)}`
        : `/network/${encodeURIComponent(toast.conversationId)}/chat`
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
  const { messageToasts, dismissMessageToast } = useChatUnread();
  if (!session || messageToasts.length === 0) return null;
  return (
    <div className="notify-toast-stack">
      {messageToasts.map((toast) => <MessageToastCard key={toast.toastId} toast={toast} onClose={() => dismissMessageToast(toast.toastId)} />)}
    </div>
  );
}
