import { useState, useMemo } from "react";
import { useNavigate } from "react-router";
import { Plus, MessageSquare, Users, Shield, Network, Send, X, ChevronRight, Loader2, Phone, Video, PhoneCall, FolderOpen, Copy, Check, Link } from "lucide-react";
import { mockCircles, mockUser } from "../../data/mockData";
import { useCircles } from "../../hooks/useApiData";
import { EmptyState } from "../../components/EmptyState";
import { CircleLiveTopology } from "../../components/circle-topology/CircleLiveTopology";
import { CallScreen } from "../../components/circle/CallScreen";
import { AttachmentMenu } from "../../components/circle/AttachmentMenu";
import { MessageAttachment } from "../../components/circle/MessageAttachment";
import { FilesTab } from "../../components/circle/FilesTab";
import { collectSharedFiles } from "../../components/circle/types";
import type { CallMode, CallRecord } from "../../components/circle/types";
import { useVault } from "../../contexts/VaultContext";

// ── Circle list item row ──────────────────────────────────────────────────────
function CircleRow({
  circle, onSelect, isSelected,
}: {
  circle: typeof mockCircles[0];
  onSelect: () => void;
  isSelected: boolean;
}) {
  return (
    <button
      onClick={onSelect}
      className="w-full text-left transition-colors"
      style={{
        display: "block",
        width: "100%",
        padding: "16px 20px",
        backgroundColor: isSelected ? "color-mix(in srgb, var(--primary) 8%, transparent)" : "transparent",
        cursor: "pointer",
        // Only longhand border properties — no shorthand mixing
        borderTopWidth: 0,
        borderTopStyle: "solid",
        borderTopColor: "transparent",
        borderRightWidth: 0,
        borderRightStyle: "solid",
        borderRightColor: "transparent",
        borderBottomWidth: "1px",
        borderBottomStyle: "solid",
        borderBottomColor: "var(--border)",
        borderLeftWidth: "3px",
        borderLeftStyle: "solid",
        borderLeftColor: isSelected ? "var(--primary)" : "transparent",
      }}
    >
      <div className="flex items-start justify-between mb-1">
        <div className="flex-1 min-w-0">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: isSelected ? "var(--primary)" : "var(--foreground)", marginBottom: "2px" }}>
            {circle.name}
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            {circle.memberCount} members
          </p>
        </div>
        <div className="flex items-center gap-1.5 ml-2 flex-shrink-0">
          <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--chart-2)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)" }}>{circle.onlineCount} online</span>
          <ChevronRight size={13} style={{ color: "var(--muted-foreground)" }} />
        </div>
      </div>
      {circle.description && (
        <p className="line-clamp-2" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
          {circle.description}
        </p>
      )}
    </button>
  );
}

// ── Circle detail panel (inline for tablet/desktop) ───────────────────────────
function CircleDetailPanel({ circle }: { circle: typeof mockCircles[0] }) {
  // Mock seed for this circle — the API omits chat attachments & call history.
  const seed = mockCircles.find((c) => c.id === circle.id) || mockCircles[0];
  const vault = useVault();

  const [activeTab, setActiveTab] =
    useState<"chat" | "calls" | "files" | "members" | "topology">("chat");
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<any[]>(seed.messages || circle.messages || []);
  const [calls, setCalls] = useState<any[]>(seed.calls || circle.calls || []);
  const [activeCall, setActiveCall] = useState<
    { mode: CallMode; title: string; participants: { id: string; name: string }[]; group: boolean } | null
  >(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const members = circle.members || [];

  const tabs = [
    { id: "chat" as const, label: "Chat", icon: MessageSquare },
    { id: "calls" as const, label: "Calls", icon: PhoneCall },
    { id: "files" as const, label: "Files", icon: FolderOpen },
    { id: "members" as const, label: "Members", icon: Users },
    { id: "topology" as const, label: "Network", icon: Network },
  ];

  const sendMessage = () => {
    if (!message.trim()) return;
    setMessages((prev) => [
      ...prev,
      { id: `msg_${Date.now()}`, sender: "Me", initials: "MR", content: message.trim(), timestamp: "Now", isMe: true, read: false },
    ]);
    setMessage("");
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
        id: `msg_${Date.now()}`, sender: "Me", initials: "MR", content: "",
        timestamp: "Now", isMe: true, read: false,
        attachment: {
          name: file.name, sizeBytes: file.size,
          mime, kind: isImage ? "image" : "file", url,
        },
      },
    ]);
    const circleFolder = vault.folders.find((folder) => folder.circleId === circle.id);
    void vault.uploadFile(file, circleFolder?.id).catch((cause) => {
      console.error("Vault attachment upload failed", cause);
    });
  };

  // Files tab content = whatever was shared in the chat.
  const sharedFiles = useMemo(() => collectSharedFiles(messages), [messages]);

  // Online members (excluding the current user) become the call participants.
  const callParticipants = useMemo(() => {
    const others = members.filter((m: any) => m.name !== mockUser.name);
    const online = others.filter((m: any) => m.status === "online");
    return online.map((m: any) => ({ id: m.id, name: m.name }));
  }, [members]);

  const startGroupCall = (mode: CallMode) =>
    setActiveCall({ mode, title: circle.name, participants: callParticipants, group: true });

  const startMemberCall = (mode: CallMode, member: { id: string; name: string }) =>
    setActiveCall({ mode, title: member.name, participants: [{ id: member.id, name: member.name }], group: false });

  const handleCallEnd = (record: CallRecord) => {
    setCalls((prev) => [
      { id: `call_${Date.now()}`, type: record.type, participant: record.participant, duration: record.duration, timestamp: "Just now" },
      ...prev,
    ]);
    setActiveCall(null);
  };

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Circle header */}
      <div className="flex items-center justify-between px-5 py-4 md:h-[72px] md:py-0 border-b border-border flex-shrink-0">
        <div>
          <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            {circle.name}
          </h3>
          <div className="flex items-center gap-1.5 mt-0.5">
            <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--chart-2)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              {circle.onlineCount} of {circle.memberCount} online
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => startGroupCall("voice")}
            aria-label="Start voice call"
            className="flex items-center justify-center rounded-md transition-opacity active:opacity-70"
            style={{ width: "36px", height: "36px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)" }}
          >
            <Phone size={16} style={{ color: "var(--foreground)" }} />
          </button>
          <button
            onClick={() => startGroupCall("video")}
            aria-label="Start video call"
            className="flex items-center justify-center rounded-md transition-opacity active:opacity-70"
            style={{ width: "36px", height: "36px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)" }}
          >
            <Video size={16} style={{ color: "var(--foreground)" }} />
          </button>
          <button
            onClick={() => setInviteOpen(true)}
            className="flex items-center gap-1.5 px-3 rounded-md transition-opacity active:opacity-70"
            style={{ height: "36px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", borderRadius: "var(--radius)" }}
          >
            <Plus size={13} />
            Invite
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-border flex-shrink-0" style={{ backgroundColor: "var(--card)" }}>
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className="flex-1 flex items-center justify-center gap-1.5 py-2.5"
            style={{
              backgroundColor: "transparent", border: "none", cursor: "pointer",
              borderBottom: activeTab === id ? "2px solid var(--primary)" : "2px solid transparent",
            }}
          >
            <Icon size={14} style={{ color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: activeTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)", color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }}>
              {label}
            </span>
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden flex flex-col">
        {/* ── Chat ── */}
        {activeTab === "chat" && (
          <>
            <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
              {messages.map((msg) => (
                <div key={msg.id} className={`flex items-end gap-2 ${msg.isMe ? "flex-row-reverse" : "flex-row"}`}>
                  {!msg.isMe && (
                    <div className="flex items-center justify-center rounded-full flex-shrink-0" style={{ width: "28px", height: "28px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}>
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)" }}>{msg.initials}</span>
                    </div>
                  )}
                  <div style={{ maxWidth: "75%" }}>
                    {!msg.isMe && (
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginBottom: "3px", paddingLeft: "2px" }}>
                        {msg.sender}
                      </p>
                    )}
                    <div
                      className="rounded-lg overflow-hidden"
                      style={{
                        backgroundColor:
                          msg.attachment?.kind === "image"
                            ? "transparent"
                            : msg.isMe ? "var(--primary)" : "var(--card)",
                        border:
                          msg.attachment?.kind === "image" || msg.isMe
                            ? "none"
                            : "1px solid var(--border)",
                        borderRadius: msg.isMe ? "12px 12px 4px 12px" : "12px 12px 12px 4px",
                        padding: msg.attachment
                          ? msg.attachment.kind === "image" ? "0" : "8px 10px"
                          : "8px 12px",
                      }}
                    >
                      {msg.attachment ? (
                        <MessageAttachment attachment={msg.attachment} isMe={msg.isMe} />
                      ) : (
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: msg.isMe ? "var(--primary-foreground)" : "var(--foreground)", lineHeight: 1.5 }}>
                          {msg.content}
                        </p>
                      )}
                    </div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "3px", textAlign: msg.isMe ? "right" : "left" }}>
                      {msg.timestamp}
                    </p>
                  </div>
                </div>
              ))}
            </div>
            {/* Compose */}
            <div className="flex items-center gap-2 px-4 py-3 border-t border-border flex-shrink-0">
              <AttachmentMenu onPick={handleAttach} />
              <input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                placeholder="Type a message…"
                className="flex-1 px-3 outline-none"
                style={{ height: "40px", backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}
              />
              <button
                onClick={sendMessage}
                disabled={!message.trim()}
                className="flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                style={{ width: "40px", height: "40px", backgroundColor: message.trim() ? "var(--primary)" : "var(--muted)", color: message.trim() ? "var(--primary-foreground)" : "var(--muted-foreground)", border: "none", cursor: message.trim() ? "pointer" : "default", borderRadius: "var(--radius)", flexShrink: 0 }}
              >
                <Send size={16} />
              </button>
            </div>
          </>
        )}

        {/* ── Calls ── */}
        {activeTab === "calls" && (
          <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
            {calls.length === 0 ? (
              <div className="flex flex-col items-center justify-center flex-1 py-12 gap-3 text-center">
                <PhoneCall size={36} style={{ color: "var(--muted-foreground)" }} />
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>No call history</p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", maxWidth: "240px", lineHeight: 1.6 }}>
                  Use the call icons in the header to call the whole Circle, or open the Members tab to call someone directly.
                </p>
              </div>
            ) : (
              <div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>Call History</p>
                <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
                  {calls.map((call: any, i: number) => (
                    <div key={call.id} className="flex items-center gap-3 px-4 py-3" style={{ borderBottom: i < calls.length - 1 ? "1px solid var(--border)" : undefined }}>
                      {call.type === "voice" ? <Phone size={15} style={{ color: "var(--chart-2)" }} /> : <Video size={15} style={{ color: "var(--primary)" }} />}
                      <div className="flex-1 min-w-0">
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{call.participant}</p>
                        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{call.duration} · {call.timestamp}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Files ── */}
        {activeTab === "files" && <FilesTab files={sharedFiles} />}

        {/* ── Members ── */}
        {activeTab === "members" && (
          <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
            {members.map((member: any) => (
              <div key={member.id} className="flex items-center gap-3 p-3 rounded-lg border border-border" style={{ backgroundColor: "var(--card)" }}>
                <div className="flex items-center justify-center rounded-full flex-shrink-0" style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "1.5px solid color-mix(in srgb, var(--primary) 25%, transparent)", position: "relative" }}>
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)" }}>
                    {member.initials || member.name.split(" ").map((n: string) => n[0]).join("")}
                  </span>
                  <div style={{ position: "absolute", bottom: "1px", right: "1px", width: "8px", height: "8px", borderRadius: "50%", backgroundColor: member.status === "online" ? "var(--chart-2)" : "var(--muted-foreground)", border: "1.5px solid var(--card)" }} />
                </div>
                <div className="flex-1 min-w-0">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{member.name}</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{member.role} · {member.status}</p>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button
                    onClick={() => startMemberCall("voice", { id: member.id, name: member.name })}
                    aria-label={`Voice call ${member.name}`}
                    className="flex items-center justify-center rounded-full transition-opacity active:opacity-70"
                    style={{ width: "34px", height: "34px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)", cursor: "pointer" }}
                  >
                    <Phone size={15} style={{ color: "var(--primary)" }} />
                  </button>
                  <button
                    onClick={() => startMemberCall("video", { id: member.id, name: member.name })}
                    aria-label={`Video call ${member.name}`}
                    className="flex items-center justify-center rounded-full transition-opacity active:opacity-70"
                    style={{ width: "34px", height: "34px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)", cursor: "pointer" }}
                  >
                    <Video size={15} style={{ color: "var(--primary)" }} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Topology ── */}
        {activeTab === "topology" && (
          <div className="flex-1 overflow-hidden">
            <CircleLiveTopology circle={circle} />
          </div>
        )}
      </div>

      {/* Invite sheet */}
      {inviteOpen && (
        <div
          className="fixed inset-0 z-[80] flex items-end md:items-center justify-center"
          style={{ backgroundColor: "rgba(0,0,0,0.6)" }}
          onClick={() => setInviteOpen(false)}
        >
          <div
            className="w-full rounded-t-xl md:rounded-xl border-t md:border border-border"
            style={{ backgroundColor: "var(--card)", maxWidth: "440px" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 pt-5 pb-3 border-b border-border">
              <h3 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Invite to {circle.name}
              </h3>
              <button onClick={() => setInviteOpen(false)} aria-label="Close" style={{ background: "none", border: "none", cursor: "pointer" }}>
                <X size={20} style={{ color: "var(--muted-foreground)" }} />
              </button>
            </div>
            <div className="p-5 flex flex-col gap-4">
              <div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "8px" }}>
                  Invite code
                </p>
                <div className="flex items-center justify-between gap-2 rounded-lg border border-border px-4 py-3" style={{ backgroundColor: "var(--background)" }}>
                  <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", letterSpacing: "0.12em" }}>
                    {circle.inviteCode}
                  </span>
                  <button onClick={() => copyText(circle.inviteCode)} aria-label="Copy code" style={{ background: "none", border: "none", cursor: "pointer", flexShrink: 0 }}>
                    {copied ? <Check size={16} style={{ color: "var(--chart-2)" }} /> : <Copy size={16} style={{ color: "var(--muted-foreground)" }} />}
                  </button>
                </div>
              </div>
              <button
                onClick={() => copyText(circle.inviteLink)}
                className="w-full flex items-center justify-center gap-2 rounded-lg transition-opacity active:opacity-80"
                style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
              >
                <Link size={16} /> {copied ? "Copied!" : "Copy invite link"}
              </button>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", color: "var(--muted-foreground)", textAlign: "center" }}>
                Anyone with this code can request to join the Circle.
              </p>
            </div>
          </div>
        </div>
      )}

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
    </div>
  );
}

// ── Main exported component ───────────────────────────────────────────────────
export function NW01CirclesList() {
  const navigate = useNavigate();
  const [selectedCircleId, setSelectedCircleId] = useState<string | null>(null);

  // Fetch circles from API with fallback to mock data
  const { data: circlesData, loading } = useCircles();

  const circles = useMemo(() => {
    if (!circlesData) return mockCircles;
    return Array.isArray(circlesData) ? circlesData : mockCircles;
  }, [circlesData]);

  const selectedCircle = useMemo(() => {
    return selectedCircleId ? circles.find((c: any) => c.id === selectedCircleId) : null;
  }, [selectedCircleId, circles]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full p-8">
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: "var(--primary)" }} />
      </div>
    );
  }

  const ListContent = (
    <>
      <div className="flex items-center justify-between px-5 pt-5 pb-4 md:h-[72px] md:py-0 border-b border-border flex-shrink-0">
        <div>
          <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Your Circles
          </h2>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            {circles.length} {circles.length === 1 ? "circle" : "circles"}
          </p>
        </div>
        <button
          onClick={() => navigate("/network/create")}
          className="flex items-center justify-center rounded-lg transition-opacity active:opacity-70"
          style={{ width: "44px", height: "44px", backgroundColor: "var(--primary)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}
        >
          <Plus size={20} style={{ color: "var(--primary-foreground)" }} />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {circles.length === 0 ? (
          <EmptyState icon={Users} heading="No circles yet"
            subtext="Create a Circle to build your trusted team."
            ctaLabel="Create your first Circle"
            ctaAction={() => navigate("/network/create")}
          />
        ) : (
          circles.map((circle: any) => (
            <CircleRow
              key={circle.id}
              circle={circle}
              isSelected={selectedCircleId === circle.id}
              onSelect={() => setSelectedCircleId(circle.id)}
            />
          ))
        )}
      </div>
    </>
  );

  return (
    <>
      {/* ── Mobile: single column, navigate to detail ── */}
      <div className="md:hidden flex flex-col" style={{ minHeight: "100dvh" }}>
        <div className="flex items-center justify-between px-4 pt-5 pb-3">
          <div>
            <h2 style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Your Circles</h2>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>{circles.length} circles</p>
          </div>
          <button onClick={() => navigate("/network/create")} className="flex items-center justify-center rounded-lg" style={{ width: "44px", height: "44px", backgroundColor: "var(--primary)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}>
            <Plus size={20} style={{ color: "var(--primary-foreground)" }} />
          </button>
        </div>
        {circles.length === 0 ? (
          <EmptyState icon={Users} heading="No circles yet" subtext="Create a Circle to build your trusted team." ctaLabel="Create your first Circle" ctaAction={() => navigate("/network/create")} />
        ) : (
          <div className="flex flex-col gap-3 px-4 pb-6">
            {circles.map((circle: any) => (
              <div key={circle.id} className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)", borderRadius: "var(--radius-card)" }}>
                <div className="flex items-start justify-between mb-1">
                  <div className="flex-1 min-w-0">
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>{circle.name}</p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{circle.memberCount} members</p>
                  </div>
                  <div className="flex items-center gap-1.5 ml-2 flex-shrink-0">
                    <div style={{ width: "7px", height: "7px", borderRadius: "50%", backgroundColor: "var(--chart-2)" }} />
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)" }}>{circle.onlineCount} online</span>
                  </div>
                </div>
                {circle.description && <p className="mb-4" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>{circle.description}</p>}
                <div className="flex items-center gap-2 mt-3">
                  <button onClick={() => navigate(`/network/${circle.id}?tab=chat`)} className="flex-1 flex items-center justify-center gap-2 rounded-md" style={{ height: "40px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", border: "none", cursor: "pointer", borderRadius: "var(--radius)" }}>
                    <MessageSquare size={15} />Chat
                  </button>
                  <button onClick={() => navigate(`/network/${circle.id}?tab=members`)} className="flex-1 flex items-center justify-center gap-2 rounded-md" style={{ height: "40px", backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", border: "1px solid var(--border)", cursor: "pointer", borderRadius: "var(--radius)" }}>
                    <Users size={15} />Members
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Tablet: 40/60 two-panel ── */}
      <div className="hidden md:flex lg:hidden" style={{ height: "100%", overflow: "hidden" }}>
        <div style={{ width: "40%", borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {ListContent}
        </div>
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          {selectedCircle ? (
            <CircleDetailPanel key={selectedCircle.id} circle={selectedCircle} />
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-8">
              <div className="rounded-full flex items-center justify-center" style={{ width: "64px", height: "64px", backgroundColor: "var(--muted)" }}>
                <Users size={28} style={{ color: "var(--muted-foreground)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Select a Circle</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "240px", lineHeight: 1.6 }}>
                Choose a Circle from the list to see chat, members, and network topology.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Desktop: 25% list / 45% detail / 30% topology ── */}
      <div className="hidden lg:flex" style={{ height: "100%", overflow: "hidden" }}>
        {/* Circles list */}
        <div style={{ width: "25%", borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {ListContent}
        </div>
        {/* Center: detail tabs */}
        <div style={{ width: "45%", borderRight: "1px solid var(--border)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {selectedCircle ? (
            <CircleDetailPanel key={selectedCircle.id} circle={selectedCircle} />
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-12">
              <div className="rounded-full flex items-center justify-center" style={{ width: "72px", height: "72px", backgroundColor: "var(--muted)" }}>
                <Users size={32} style={{ color: "var(--muted-foreground)" }} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>Select a Circle</p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "280px", lineHeight: 1.6 }}>
                Choose a Circle to view chat, members, and live network topology.
              </p>
            </div>
          )}
        </div>
        {/* Right: topology — only visible after a Circle is selected */}
        <div style={{ width: "30%", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div className="flex items-center px-4 pt-4 pb-3 md:h-[72px] md:py-0 border-b border-border flex-shrink-0">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
              {selectedCircle ? `${selectedCircle.name} · Topology` : "Network Topology"}
            </p>
          </div>
          <div className="flex-1 overflow-y-auto">
            {selectedCircle ? (
              <CircleLiveTopology circle={selectedCircle} />
            ) : (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-center p-8">
                <div className="rounded-full flex items-center justify-center" style={{ width: "56px", height: "56px", backgroundColor: "var(--muted)" }}>
                  <Network size={24} style={{ color: "var(--muted-foreground)" }} />
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                  No Circle selected
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", maxWidth: "220px", lineHeight: 1.6 }}>
                  Choose a Circle to see its live network topology.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
