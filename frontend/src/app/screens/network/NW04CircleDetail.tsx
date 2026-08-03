import { useState, useMemo } from "react";
import { useParams, useSearchParams, useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { mockCircles, mockUser } from "../../data/mockData";
import { useCircles } from "../../hooks/useApiData";
import {
  Send, Phone, Video, UserPlus, Copy, Check, X, ChevronRight,
  Link, QrCode, Search, MessageSquare, Users, PhoneCall,
  Trash2, AlertTriangle, FolderOpen, Settings
} from "lucide-react";
import { StatusBadge } from "../../components/SeverityBadge";
import * as Dialog from "@radix-ui/react-dialog";
import { CallScreen } from "../../components/circle/CallScreen";
import { AttachmentMenu } from "../../components/circle/AttachmentMenu";
import { MessageAttachment } from "../../components/circle/MessageAttachment";
import { FilesTab } from "../../components/circle/FilesTab";
import { collectSharedFiles } from "../../components/circle/types";
import type { CallMode, CallRecord } from "../../components/circle/types";
import { useVault } from "../../contexts/VaultContext";

type Tab = "chat" | "calls" | "files" | "members";

const circleDetailTabs: Tab[] = ["chat", "calls", "files", "members"];

export function NW04CircleDetail() {
  const { circleId } = useParams<{ circleId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const vault = useVault();
  const requestedTab = searchParams.get("tab") as Tab | null;
  const activeTab: Tab = requestedTab && circleDetailTabs.includes(requestedTab) ? requestedTab : "chat";

  // Fetch circles from API with fallback to mock data
  const { data: circlesData } = useCircles();

  const circles = useMemo(() => {
    if (!circlesData) return mockCircles;
    return Array.isArray(circlesData) ? circlesData : mockCircles;
  }, [circlesData]);

  const circle = useMemo(() => {
    return circles.find((c: any) => c.id === circleId) || circles[0];
  }, [circles, circleId]);

  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState(circle?.messages || []);
  const [sheetTab, setSheetTab] = useState<"link" | "qr" | "search">("link");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [memberDetailOpen, setMemberDetailOpen] = useState<string | null>(null);
  const [removeDialogOpen, setRemoveDialogOpen] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [activeCall, setActiveCall] = useState<
    { mode: CallMode; title: string; participants: { id: string; name: string }[]; group: boolean } | null
  >(null);

  const members = circle?.members || [];
  const [calls, setCalls] = useState(circle?.calls || []);
  const selectedMember = members.find((m) => m.id === memberDetailOpen);
  const memberToRemove = members.find((m) => m.id === removeDialogOpen);

  const setTab = (tab: Tab) => setSearchParams({ tab });

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const sendMessage = () => {
    if (!message.trim()) return;
    setMessages((prev) => [...prev, {
      id: `msg_${Date.now()}`, sender: "Me", initials: "MR",
      content: message.trim(), timestamp: "Now", isMe: true, read: false,
    }]);
    setMessage("");
  };

  // Online members (excluding the current user) become the call participants.
  const callParticipants = useMemo(() => {
    const others = members.filter((m: any) => m.name !== mockUser.name);
    const online = others.filter((m: any) => m.status === "online");
    return online.map((m: any) => ({ id: m.id, name: m.name }));
  }, [members]);

  // Files tab content = whatever was shared in the chat.
  const sharedFiles = useMemo(() => collectSharedFiles(messages), [messages]);

  const startGroupCall = (mode: CallMode) =>
    setActiveCall({ mode, title: circle.name, participants: callParticipants, group: true });

  const startMemberCall = (mode: CallMode, member: { id: string; name: string }) =>
    setActiveCall({ mode, title: member.name, participants: [{ id: member.id, name: member.name }], group: false });

  const handleCallEnd = (record: CallRecord) => {
    setCalls((prev) => [
      {
        id: `call_${Date.now()}`,
        type: record.type,
        participant: record.participant,
        duration: record.duration,
        timestamp: "Just now",
      },
      ...prev,
    ]);
    setActiveCall(null);
  };

  // Picked file → an attachment chat message (object URL, session-only).
  // Also mirrored into All Files so it syncs to the device storage.
  const handleAttach = (file: File) => {
    const isImage = file.type.startsWith("image/");
    const url = URL.createObjectURL(file);
    const mime = file.type || "application/octet-stream";
    setMessages((prev) => [
      ...prev,
      {
        id: `msg_${Date.now()}`,
        sender: "Me",
        initials: "MR",
        content: "",
        timestamp: "Now",
        isMe: true,
        read: false,
        attachment: {
          name: file.name,
          sizeBytes: file.size,
          mime,
          kind: isImage ? "image" : "file",
          url,
        },
      } as any,
    ]);
    const circleFolder = vault.folders.find((folder) => folder.circleId === circle.id);
    void vault.uploadFile(file, circleFolder?.id).catch((cause) => {
      console.error("Vault attachment upload failed", cause);
    });
  };

  const tabs = [
    { id: "chat", label: "Chat", icon: MessageSquare },
    { id: "calls", label: "Calls", icon: PhoneCall },
    { id: "files", label: "Files", icon: FolderOpen },
    { id: "members", label: "Members", icon: Users },
  ];

  return (
    <>
      <div className="flex flex-col h-full">
        <PageHeader
          title={circle.name}
          subtitle={`${circle.onlineCount} of ${circle.memberCount} online`}
          onBack={() => navigate(`/network?circle=${encodeURIComponent(circle.id)}`, { replace: true })}
          right={
            <div className="flex items-center gap-1">
              <button
                onClick={() => navigate(`/network/${circle.id}/manage`)}
                aria-label="Manage Circle"
                className="flex items-center justify-center rounded-full transition-opacity active:opacity-60"
                style={{ width: "40px", height: "40px", background: "none", border: "none", cursor: "pointer" }}
              >
                <Settings size={20} style={{ color: "var(--foreground)" }} />
              </button>
              <button
                onClick={() => startGroupCall("voice")}
                aria-label="Start voice call"
                className="flex items-center justify-center rounded-full transition-opacity active:opacity-60"
                style={{ width: "40px", height: "40px", background: "none", border: "none", cursor: "pointer" }}
              >
                <Phone size={20} style={{ color: "var(--foreground)" }} />
              </button>
              <button
                onClick={() => startGroupCall("video")}
                aria-label="Start video call"
                className="flex items-center justify-center rounded-full transition-opacity active:opacity-60"
                style={{ width: "40px", height: "40px", background: "none", border: "none", cursor: "pointer" }}
              >
                <Video size={20} style={{ color: "var(--foreground)" }} />
              </button>
            </div>
          }
        />

        {/* Tabs */}
        <div className="flex border-b border-border" style={{ backgroundColor: "var(--card)", flexShrink: 0 }}>
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id as Tab)}
              className="flex-1 flex flex-col items-center gap-0.5 py-2.5 transition-opacity active:opacity-70"
              style={{
                backgroundColor: "transparent", border: "none", cursor: "pointer",
                borderBottom: activeTab === id ? "2px solid var(--primary)" : "2px solid transparent",
              }}
            >
              <Icon size={16} style={{ color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: activeTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)", color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }}>
                {label}
              </span>
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="flex-1 overflow-hidden flex flex-col">
          {/* CHAT TAB */}
          {activeTab === "chat" && (
            <>
              <div className="flex-1 overflow-y-auto">
                <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col gap-3 p-4 md:p-6">
                {messages.length === 0 && (
                  <div className="flex flex-col items-center justify-center flex-1 py-12 gap-3 text-center">
                    <MessageSquare size={36} style={{ color: "var(--muted-foreground)" }} />
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>No messages yet</p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", maxWidth: "220px", lineHeight: 1.6, textAlign: "center" }}>
                      Send a secure message to coordinate with your team. Messages are end-to-end encrypted.
                    </p>
                  </div>
                )}
                {messages.map((msg) => (
                  <div key={msg.id} className={`flex flex-col ${msg.isMe ? "items-end" : "items-start"}`}>
                    {!msg.isMe && (
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "3px", marginLeft: "4px" }}>{msg.sender}</span>
                    )}
                    <div
                      className="rounded-2xl max-w-[78%] overflow-hidden"
                      style={{
                        backgroundColor:
                          (msg as any).attachment?.kind === "image"
                            ? "transparent"
                            : msg.isMe ? "var(--primary)" : "var(--card)",
                        border:
                          (msg as any).attachment?.kind === "image" || msg.isMe
                            ? "none"
                            : "1px solid var(--border)",
                        borderRadius: msg.isMe ? "18px 18px 4px 18px" : "18px 18px 18px 4px",
                        padding: (msg as any).attachment
                          ? (msg as any).attachment.kind === "image" ? "0" : "10px 12px"
                          : "10px 16px",
                      }}
                    >
                      {(msg as any).attachment ? (
                        <MessageAttachment attachment={(msg as any).attachment} isMe={msg.isMe} />
                      ) : (
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: msg.isMe ? "var(--primary-foreground)" : "var(--foreground)", lineHeight: 1.5 }}>
                          {msg.content}
                        </p>
                      )}
                    </div>
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "3px", marginLeft: "4px", marginRight: "4px" }}>
                      {msg.timestamp} {msg.isMe && (msg.read ? "· Read" : "· Delivered")}
                    </span>
                  </div>
                ))}
                </div>
              </div>
              <div className="px-3 md:px-6 py-3 border-t border-border" style={{ backgroundColor: "var(--card)", flexShrink: 0 }}>
                <div className="mx-auto flex w-full max-w-2xl items-center gap-2">
                <AttachmentMenu onPick={handleAttach} />
                <input
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                  placeholder="Secure message..."
                  className="flex-1 px-4 outline-none"
                  style={{
                    height: "44px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)",
                    borderRadius: "22px", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
                  }}
                />
                <button
                  onClick={sendMessage}
                  className="flex items-center justify-center rounded-full transition-opacity active:opacity-70"
                  style={{ width: "44px", height: "44px", backgroundColor: "var(--primary)", border: "none", cursor: "pointer", flexShrink: 0 }}
                >
                  <Send size={18} style={{ color: "var(--primary-foreground)" }} />
                </button>
                </div>
              </div>
            </>
          )}

          {/* CALLS TAB */}
          {activeTab === "calls" && (
            <div className="flex-1 overflow-y-auto">
              <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col gap-4 p-4 md:p-6">
              {calls.length === 0 ? (
                <div className="flex flex-col items-center justify-center flex-1 py-12 gap-3 text-center">
                  <PhoneCall size={36} style={{ color: "var(--muted-foreground)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>No call history</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", maxWidth: "240px", lineHeight: 1.6, textAlign: "center" }}>
                    Use the call icons in the header to call the whole Circle, or open the Members tab to call someone directly.
                  </p>
                </div>
              ) : (
                <div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>Call History</p>
                  <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                    {calls.map((call, i) => (
                      <div key={call.id} className="flex items-center gap-3 px-4 py-3.5" style={{ borderBottom: i < calls.length - 1 ? "1px solid var(--border)" : undefined }}>
                        {call.type === "voice" ? <Phone size={16} style={{ color: "var(--chart-2)" }} /> : <Video size={16} style={{ color: "var(--primary)" }} />}
                        <div className="flex-1">
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{call.participant}</p>
                          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{call.duration} · {call.timestamp}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              </div>
            </div>
          )}

          {/* FILES TAB */}
          {activeTab === "files" && <FilesTab files={sharedFiles} />}

          {/* MEMBERS TAB */}
          {activeTab === "members" && (
            <div className="flex-1 overflow-y-auto">
              <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col gap-4 p-4 md:p-6">
              <button
                onClick={() => setInviteOpen(true)}
                className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}
              >
                <UserPlus size={16} /> Invite Member
              </button>

              <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                {members.map((member, i) => (
                  <button
                    key={member.id}
                    onClick={() => setMemberDetailOpen(member.id)}
                    className="w-full flex items-center gap-3 px-4 py-3.5 text-left transition-opacity active:opacity-70"
                    style={{ backgroundColor: "transparent", border: "none", borderBottom: i < members.length - 1 ? "1px solid var(--border)" : undefined, cursor: "pointer" }}
                  >
                    <div
                      className="rounded-full flex items-center justify-center flex-shrink-0"
                      style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 20%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 30%, transparent)" }}
                    >
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)" }}>{member.name.split(" ").map((n) => n[0]).join("")}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{member.name}</p>
                        {(member as any).pending && <StatusBadge status="Pending" variant="warning" />}
                        {member.role.toLowerCase() === "owner" && <StatusBadge status="Admin" variant="info" />}
                      </div>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{member.email}</p>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: member.status === "online" ? "var(--chart-2)" : "var(--muted-foreground)" }} />
                        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
                          {member.status === "online" ? "online" : `offline · ${member.lastSeen}`}
                        </span>
                      </div>
                    </div>
                    <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                ))}
              </div>
              </div>
            </div>
          )}

        </div>
      </div>

      {/* Invite Sheet */}
      {inviteOpen && (
        <div className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer" style={{ backgroundColor: "rgba(0,0,0,0.6)" }} onClick={() => setInviteOpen(false)}>
          <div className="w-full rounded-t-xl md:rounded-xl border-t md:border border-border" style={{ backgroundColor: "var(--card)", maxWidth: "440px", maxHeight: "80dvh", display: "flex", flexDirection: "column" }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 pt-5 pb-2 flex-shrink-0">
              <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Invite to {circle.name}</h3>
              <button onClick={() => setInviteOpen(false)} style={{ background: "none", border: "none", cursor: "pointer" }}>
                <X size={20} style={{ color: "var(--muted-foreground)" }} />
              </button>
            </div>
            {/* Invite tabs */}
            <div className="flex gap-0 border-b border-border flex-shrink-0">
              {[{ id: "link", label: "Share Link" }, { id: "qr", label: "QR Code" }, { id: "search", label: "Search DIDs" }].map(({ id, label }) => (
                <button key={id} onClick={() => setSheetTab(id as any)}
                  className="flex-1 py-3 transition-opacity active:opacity-70"
                  style={{ backgroundColor: "transparent", border: "none", cursor: "pointer", borderBottom: sheetTab === id ? "2px solid var(--primary)" : "2px solid transparent", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: sheetTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)", color: sheetTab === id ? "var(--primary)" : "var(--muted-foreground)" }}>
                  {label}
                </button>
              ))}
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {sheetTab === "link" && (
                <div className="flex flex-col gap-4">
                  <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--background)" }}>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", marginBottom: "4px" }}>Share your invite link</p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Anyone with this link can request to join your Circle.</p>
                  </div>

                  {/* UX-03: Bank-style 2FA invite code display */}
                  <div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "12px" }}>Invite Code</p>
                    <div className="flex items-center justify-center gap-2 flex-wrap mb-3">
                      {circle.inviteCode.split("-").map((segment, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-center rounded-lg"
                          style={{
                            minWidth: "64px",
                            height: "52px",
                            backgroundColor: "var(--muted)",
                            border: "1px solid var(--border)",
                            padding: "0 10px",
                          }}
                        >
                          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", letterSpacing: "0.15em" }}>
                            {segment}
                          </span>
                        </div>
                      ))}
                    </div>
                    <button
                      onClick={() => handleCopy(circle.inviteCode, "code")}
                      className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                      style={{ height: "44px", backgroundColor: copiedField === "code" ? "color-mix(in srgb, var(--chart-2) 15%, var(--secondary))" : "var(--secondary)", color: copiedField === "code" ? "var(--chart-2)" : "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
                    >
                      {copiedField === "code" ? <Check size={15} style={{ color: "var(--chart-2)" }} /> : <Copy size={15} />}
                      {copiedField === "code" ? "Copied!" : "Copy Code"}
                    </button>
                  </div>

                  <div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "6px" }}>Shareable Link</p>
                    <div className="flex items-center gap-2 rounded-lg border border-border px-4 py-3" style={{ backgroundColor: "var(--card)" }}>
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", flex: 1, wordBreak: "break-all" }}>{circle.inviteLink}</span>
                      <button onClick={() => handleCopy(circle.inviteLink, "link")} style={{ background: "none", border: "none", cursor: "pointer", flexShrink: 0 }}>
                        {copiedField === "link" ? <Check size={16} style={{ color: "var(--chart-2)" }} /> : <Copy size={16} style={{ color: "var(--muted-foreground)" }} />}
                      </button>
                    </div>
                  </div>
                  <button className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80" style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}>
                    <Link size={16} /> Share Invite
                  </button>
                  <div className="h-px" style={{ backgroundColor: "var(--border)" }} />
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Or record an invitation</p>
                  <div className="flex gap-2">
                    <input placeholder="teammate@company.com" className="flex-1 px-3 outline-none" style={{ height: "40px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }} />
                    <button className="px-4 rounded-md transition-opacity active:opacity-80" style={{ height: "40px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }}>Record</button>
                  </div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textAlign: "center" }}>Users need to have SG-X Guardian installed to join.</p>
                </div>
              )}
              {sheetTab === "qr" && (
                <div className="flex flex-col items-center gap-4">
                  {/* QA-14: Larger, clearer QR code */}
                  <div className="rounded-lg border border-border p-5" style={{ backgroundColor: "var(--card)" }}>
                    <svg width="240" height="240" viewBox="0 0 240 240">
                      {Array.from({ length: 9 }, (_, row) =>
                        Array.from({ length: 9 }, (_, col) => {
                          const dark = (row + col) % 2 === 0 || (row < 3 && col < 3) || (row < 3 && col > 5) || (row > 5 && col < 3);
                          return <rect key={`${row}-${col}`} x={col * 24 + 12} y={row * 24 + 12} width={20} height={20} rx={3} fill={dark ? "var(--foreground)" : "transparent"} />;
                        })
                      )}
                    </svg>
                  </div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", textAlign: "center" }}>Share this QR code for quick access</p>
                  <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)", letterSpacing: "0.12em" }}>{circle.inviteCode}</p>
                  <button className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80" style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}>
                    <QrCode size={16} /> Share QR Code
                  </button>
                </div>
              )}
              {sheetTab === "search" && (
                <div className="flex flex-col gap-4">
                  <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "4px" }}>DID-Based Discovery</p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>Find team members by their Decentralized Identifier. The user must have their DID registered on the Cervais network.</p>
                  </div>
                  <div className="flex gap-2">
                    <input placeholder="Search by DID or user ID..." className="flex-1 px-3 outline-none" style={{ height: "44px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }} />
                    <button className="flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ width: "44px", height: "44px", backgroundColor: "var(--primary)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}>
                      <Search size={18} style={{ color: "var(--primary-foreground)" }} />
                    </button>
                  </div>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", textAlign: "center", marginTop: "24px" }}>Search results will appear here</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Member Detail Sheet */}
      {memberDetailOpen && selectedMember && (
        <div className="fixed inset-0 z-50 flex items-end md:items-center justify-center cursor-pointer" style={{ backgroundColor: "rgba(0,0,0,0.6)" }} onClick={() => setMemberDetailOpen(null)}>
          <div className="w-full rounded-t-xl md:rounded-xl border-t md:border border-border" style={{ backgroundColor: "var(--card)", maxWidth: "440px" }} onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 pt-5 pb-4 border-b border-border">
              <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{selectedMember.name}</h3>
              <button onClick={() => setMemberDetailOpen(null)} style={{ background: "none", border: "none", cursor: "pointer" }}>
                <X size={20} style={{ color: "var(--muted-foreground)" }} />
              </button>
            </div>
            <div className="p-5 flex flex-col gap-4">
              <div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>DID</p>
                <div className="rounded-lg border border-border p-3 flex items-start justify-between gap-2" style={{ backgroundColor: "var(--background)" }}>
                  <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--foreground)", wordBreak: "break-all", lineHeight: 1.7, flex: 1 }}>{selectedMember.did}</span>
                  <button onClick={() => handleCopy(selectedMember.did, "member-did")} style={{ background: "none", border: "none", cursor: "pointer", flexShrink: 0 }}>
                    {copiedField === "member-did" ? <Check size={15} style={{ color: "var(--chart-2)" }} /> : <Copy size={15} style={{ color: "var(--muted-foreground)" }} />}
                  </button>
                </div>
              </div>
              {[
                { label: "Connection Type", value: "WiFi" },
                { label: "Last Seen", value: selectedMember.lastSeen },
                { label: "Role", value: selectedMember.role.toLowerCase() === "owner" ? "Admin" : selectedMember.role },
                { label: "Guardian Health", value: "Score: 88" },
              ].map(({ label, value }) => (
                <div key={label} className="flex items-center justify-between">
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{label}</span>
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{value}</span>
                </div>
              ))}
              <div className="flex gap-2 mt-1">
                <button
                  onClick={() => { startMemberCall("voice", { id: selectedMember.id, name: selectedMember.name }); setMemberDetailOpen(null); }}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                  style={{ height: "48px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", color: "var(--primary)", border: "1.5px solid color-mix(in srgb, var(--primary) 30%, transparent)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
                >
                  <Phone size={16} /> Voice Call
                </button>
                <button
                  onClick={() => { startMemberCall("video", { id: selectedMember.id, name: selectedMember.name }); setMemberDetailOpen(null); }}
                  className="flex-1 flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                  style={{ height: "48px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", color: "var(--primary)", border: "1.5px solid color-mix(in srgb, var(--primary) 30%, transparent)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
                >
                  <Video size={16} /> Video Call
                </button>
              </div>
              {selectedMember.role.toLowerCase() !== "owner" && (
                <button
                  onClick={() => { setMemberDetailOpen(null); setRemoveDialogOpen(selectedMember.id); }}
                  className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80 mt-2"
                  style={{ height: "48px", backgroundColor: "color-mix(in srgb, var(--destructive) 12%, transparent)", color: "var(--destructive)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", border: "1px solid color-mix(in srgb, var(--destructive) 30%, transparent)", cursor: "pointer", borderRadius: "var(--radius)" }}
                >
                  <Trash2 size={16} /> Remove from Circle
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Remove Confirmation Dialog */}
      <Dialog.Root open={!!removeDialogOpen} onOpenChange={(open) => !open && setRemoveDialogOpen(null)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-[60]" style={{ backgroundColor: "rgba(0,0,0,0.7)" }} />
          <Dialog.Content
            className="fixed z-[70] rounded-xl border border-border p-6"
            style={{ backgroundColor: "var(--card)", left: "50%", top: "50%", transform: "translate(-50%, -50%)", width: "calc(100% - 48px)", maxWidth: "380px" }}
          >
            <div className="flex items-center gap-3 mb-3">
              <AlertTriangle size={20} style={{ color: "var(--destructive)" }} />
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Remove {memberToRemove?.name}?
              </Dialog.Title>
            </div>
            <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6, marginBottom: "20px" }}>
              They will lose access to this Circle's chat, calls, and shared security data. This cannot be undone.
            </Dialog.Description>
            <div className="flex gap-3">
              <Dialog.Close asChild>
                <button className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80" style={{ height: "44px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}>
                  Cancel
                </button>
              </Dialog.Close>
              <button
                onClick={() => setRemoveDialogOpen(null)}
                className="flex-1 flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                style={{ height: "44px", backgroundColor: "var(--destructive)", color: "var(--destructive-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                Remove
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      {/* Active call overlay */}
      {activeCall && (
        <CallScreen
          mode={activeCall.mode}
          title={activeCall.title}
          participants={activeCall.participants}
          group={activeCall.group}
          onEnd={handleCallEnd}
        />
      )}
    </>
  );
}
