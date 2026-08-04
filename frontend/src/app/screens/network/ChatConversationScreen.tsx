import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FileText, Loader2, MessageSquare, Phone, RefreshCw, Send, Video } from "lucide-react";
import { useNavigate, useParams, useSearchParams } from "react-router";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { AttachmentMenu } from "../../components/circle/AttachmentMenu";
import { FilesTab } from "../../components/circle/FilesTab";
import { MessageAttachment } from "../../components/circle/MessageAttachment";
import type { SharedFile } from "../../components/circle/types";
import { useCircles, usePeers } from "../../hooks/useApiData";
import { didService } from "../../services/didService";
import chatService, { parseChatPayload, type ChatMessageRecord } from "../../services/chatService";
import { useCall } from "../../../features/calls/CallContext";
import { useGroupCall } from "../../../features/calls/GroupCallContext";
import type { MediaType } from "../../../features/calls/call.types";

type View = "chat" | "files";

function timeLabel(timestamp: number) {
  const date = new Date(timestamp > 10_000_000_000 ? timestamp : timestamp * 1000);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function ChatConversationScreen() {
  const { circleId, peerDid } = useParams<{ circleId: string; peerDid?: string }>();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: circlesData, loading: circlesLoading } = useCircles();
  const { data: peersData, loading: peersLoading } = usePeers();
  const circle = (Array.isArray(circlesData) ? circlesData : []).find((item: any) => item.id === circleId);
  const member = circle?.members?.find((item: any) => item.did === peerDid);
  const peer = (Array.isArray(peersData) ? peersData : []).find((item: any) => item.did === peerDid);
  const isGroup = Boolean(circleId && !peerDid);
  const { startCall, call, currentDevice } = useCall();
  const { group } = useGroupCall();
  const [records, setRecords] = useState<ChatMessageRecord[]>([]);
  const [localDid, setLocalDid] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [startingCall, setStartingCall] = useState<"audio" | "video" | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const view: View = searchParams.get("view") === "files" ? "files" : "chat";

  const loadHistory = useCallback(async () => {
    if ((isGroup && !circleId) || (!isGroup && !peerDid)) return;
    setLoading(true);
    try {
      const response = isGroup
        ? await chatService.groupHistory(circleId)
        : await chatService.directHistory(peerDid!);
      setRecords([...response.messages].sort((a, b) => a.seq_no - b.seq_no || a.timestamp - b.timestamp));
    } catch (cause) {
      toast.error("Conversation could not be loaded", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setLoading(false);
    }
  }, [circleId, isGroup, peerDid]);

  useEffect(() => { void didService.getStatus().then((status) => setLocalDid(status.did)).catch(() => {}); }, []);
  useEffect(() => { void chatService.sync().catch(() => {}).finally(() => void loadHistory()); }, [loadHistory]);
  useEffect(() => { if (view === "chat") bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [records, view]);

  useEffect(() => {
    if (!localDid) return;
    records
      .filter((record) => record.sender_did !== localDid && record.status !== "read" && !record.read_by.includes(localDid))
      .forEach((record) => {
        void chatService.markRead(record.message_id, record.sender_did, isGroup ? circleId : undefined).catch(() => {});
      });
  }, [records, localDid, isGroup, circleId]);

  const send = async (content: string | null, attachmentId: string | null = null) => {
    if (!circleId || (!isGroup && !peerDid) || (!content?.trim() && !attachmentId)) return;
    setSending(true);
    try {
      if (isGroup) await chatService.sendGroup(circleId!, content?.trim() || null, attachmentId);
      else await chatService.sendDirect(peerDid!, content?.trim() || null, attachmentId);
      setMessage("");
      await loadHistory();
    } catch (cause) {
      toast.error("Message was not sent", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setSending(false);
    }
  };

  const attach = async (file: File) => {
    setSending(true);
    setUploadProgress(0);
    try {
      const uploaded = await chatService.upload(file, (loaded, total) => setUploadProgress(total ? Math.round((loaded / total) * 100) : 0));
      await send(file.name, uploaded.attachment_id);
      toast.success("File shared securely");
    } catch (cause) {
      toast.error("File could not be shared", { description: cause instanceof Error ? cause.message : undefined });
    } finally {
      setSending(false);
      setUploadProgress(null);
    }
  };

  const callPeer = async (media: MediaType[]) => {
    if (isGroup || !peer) return;
    if (call || group) {
      toast.error("Guardian is busy", { description: "End or leave the current call before starting another." });
      return;
    }
    if (!peer.callAvailable || !peer.online) {
      toast.error("Peer is unavailable for calls", { description: peer.callUnavailableReason || "The peer is currently offline." });
      return;
    }
    if (peer.peerId === currentDevice) {
      toast.info("This is the current Guardian");
      return;
    }
    const mode = media.includes("video") ? "video" : "audio";
    setStartingCall(mode);
    try {
      await startCall(peer.peerId, media);
    } catch (cause) {
      toast.error("Call could not start", { description: cause instanceof Error ? cause.message : "The peer may be unavailable." });
    } finally {
      setStartingCall(null);
    }
  };

  const messages = useMemo(() => records.map((record) => {
    const payload = parseChatPayload(record);
    const isMe = localDid ? record.sender_did === localDid : (isGroup ? false : record.sender_did !== peerDid);
    const senderMember = circle?.members?.find((item: any) => item.did === record.sender_did);
    const attachment = payload.attachment_id ? {
      name: payload.content || `Attachment ${payload.attachment_id.slice(0, 8)}`,
      sizeBytes: 0,
      mime: "application/octet-stream",
      kind: "file" as const,
      url: chatService.downloadUrl(payload.attachment_id),
    } : undefined;
    return {
      id: record.message_id,
      sender: isMe ? "You" : (senderMember?.name || member?.name || record.sender_did),
      content: attachment ? "" : (payload.content || ""),
      timestamp: timeLabel(record.timestamp),
      isMe,
      read: record.status === "read" || record.read_by.length > 0,
      attachment,
    };
  }), [records, localDid, isGroup, peerDid, circle, member]);

  const files = useMemo<SharedFile[]>(() => messages.filter((item) => item.attachment).map((item) => ({
    id: item.id,
    ...item.attachment!,
    sharedBy: item.sender,
    sharedAt: item.timestamp,
  })).reverse(), [messages]);

  if ((isGroup && circlesLoading) || (!isGroup && peersLoading)) return <div className="grid h-full place-items-center"><Loader2 className="animate-spin" /></div>;
  if ((isGroup && !circle) || (!isGroup && !peer && !member)) return <div className="grid h-full place-items-center p-6 text-sm text-muted-foreground">Conversation not found.</div>;

  const title = isGroup ? circle.name : (member?.name || peer?.peerId || peerDid);
  const subtitle = isGroup ? `Secure group chat · ${circle.members?.length || 0} members` : "Private peer-to-peer chat";
  return (
    <div className="flex h-full flex-col">
      <PageHeader title={title} subtitle={subtitle} onBack={() => navigate(isGroup ? `/network/${circleId}?tab=members` : "/chats")} right={
        <div className="flex items-center gap-1">
          {!isGroup && <>
            <button aria-label={`Voice call ${title}`} title="Voice call" disabled={startingCall !== null || !peer?.callAvailable || !peer?.online} onClick={() => void callPeer(["audio"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "audio" ? <Loader2 size={18} className="animate-spin" /> : <Phone size={18} />}</button>
            <button aria-label={`Video call ${title}`} title="Video call" disabled={startingCall !== null || !peer?.callAvailable || !peer?.online} onClick={() => void callPeer(["audio", "video"])} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted disabled:cursor-not-allowed disabled:opacity-35">{startingCall === "video" ? <Loader2 size={18} className="animate-spin" /> : <Video size={18} />}</button>
          </>}
          <button aria-label="Refresh messages" onClick={() => void loadHistory()} className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted"><RefreshCw size={18} /></button>
        </div>
      } />
      <div className="flex shrink-0 border-b border-border bg-card">
        {(["chat", "files"] as View[]).map((item) => (
          <button key={item} onClick={() => setSearchParams(item === "files" ? { view: "files" } : {})} className="flex flex-1 items-center justify-center gap-2 py-3 text-sm font-medium capitalize" style={{ color: view === item ? "var(--primary)" : "var(--muted-foreground)", borderBottom: view === item ? "2px solid var(--primary)" : "2px solid transparent" }}>
            {item === "chat" ? <MessageSquare size={16} /> : <FileText size={16} />}{item}
          </button>
        ))}
      </div>
      {view === "files" ? <FilesTab files={files} /> : <>
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col gap-3 p-4 md:p-6">
            {loading && <div className="flex flex-1 items-center justify-center gap-2 text-sm text-muted-foreground"><Loader2 size={18} className="animate-spin" /> Loading secure conversation…</div>}
            {!loading && messages.length === 0 && <div className="flex flex-1 flex-col items-center justify-center gap-3 text-center text-muted-foreground"><MessageSquare size={36} /><p className="text-sm font-medium text-foreground">No messages yet</p><p className="max-w-xs text-xs">Start this secure {isGroup ? "Circle conversation" : "peer-to-peer conversation"}.</p></div>}
            {messages.map((item) => <div key={item.id} className={`flex flex-col ${item.isMe ? "items-end" : "items-start"}`}>
              {!item.isMe && <span className="mb-1 ml-1 max-w-[78%] truncate text-xs text-muted-foreground">{item.sender}</span>}
              <div className="max-w-[78%] overflow-hidden rounded-2xl border border-border px-4 py-2.5" style={{ background: item.isMe ? "var(--primary)" : "var(--card)", borderColor: item.isMe ? "transparent" : undefined }}>
                {item.attachment ? <MessageAttachment attachment={item.attachment} isMe={item.isMe} /> : <p className="text-sm leading-6" style={{ color: item.isMe ? "var(--primary-foreground)" : "var(--foreground)" }}>{item.content}</p>}
              </div>
              <span className="mx-1 mt-1 text-[10px] text-muted-foreground">{item.timestamp}{item.isMe ? item.read ? " · Read" : " · Sent" : ""}</span>
            </div>)}
            <div ref={bottomRef} />
          </div>
        </div>
        <div className="shrink-0 border-t border-border bg-card px-3 py-3 md:px-6">
          {uploadProgress !== null && <div className="mx-auto mb-2 max-w-2xl text-xs text-muted-foreground">Uploading file… {uploadProgress}%</div>}
          <div className="mx-auto flex max-w-2xl items-center gap-2">
            <AttachmentMenu onPick={(file) => void attach(file)} disabled={sending} />
            <input value={message} onChange={(event) => setMessage(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void send(message); }} disabled={sending} placeholder={isGroup ? "Secure Circle message…" : `Message ${member?.name || peer?.peerId || "peer"}…`} className="h-11 flex-1 rounded-full border border-border bg-input-background px-4 text-sm outline-none" />
            <button aria-label="Send message" onClick={() => void send(message)} disabled={sending || !message.trim()} className="grid h-11 w-11 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground disabled:opacity-40">{sending ? <Loader2 size={18} className="animate-spin" /> : <Send size={18} />}</button>
          </div>
        </div>
      </>}
    </div>
  );
}
