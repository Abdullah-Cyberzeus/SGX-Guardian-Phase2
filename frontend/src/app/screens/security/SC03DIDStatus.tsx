import { useState } from "react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import {
  Fingerprint,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Loader2,
  AlertTriangle,
  Key,
  Info,
  ShieldOff,
  FileJson,
  ShieldCheck,
  UploadCloud,
  Users,
  X,
  Eye,
  EyeOff,
  Globe,
  Lock,
  Link2,
  FileText,
} from "lucide-react";
import {
  useDIDStatus,
  useDIDResolve,
  useDIDDocument,
  useDIDDocumentPeers,
} from "../../hooks/useApiData";
import { useContactNames } from "../../contexts/ContactNameContext";
import { didService } from "../../services/didService";
import type { DIDDocumentRaw, DIDDocumentPeerSummary } from "../../services/didService";
import { toast } from "sonner";

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={handleCopy}
      style={{ background: "none", border: "none", cursor: "pointer", padding: "2px", color: "var(--muted-foreground)" }}
    >
      {copied ? <Check size={14} style={{ color: "var(--chart-2)" }} /> : <Copy size={14} />}
    </button>
  );
}

function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2" style={{ borderBottom: "1px solid var(--border)" }}>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", flexShrink: 0 }}>
        {label}
      </span>
      <div className="flex items-center gap-1 min-w-0">
        <span
          className="truncate"
          style={{
            fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-medium)",
            color: "var(--foreground)",
          }}
        >
          {value}
        </span>
        {mono && <CopyButton value={value} />}
      </div>
    </div>
  );
}

// Mask a DID value for the click-to-hide affordance. Preserves the method
// prefix (e.g. "did:guardian:") and the last few characters so the user can
// still distinguish two hidden DIDs at a glance, similar to how secret tokens
// are typically displayed when hidden.
function maskDID(did: string): string {
  if (!did) return did;
  const colon2 = did.indexOf(":", did.indexOf(":") + 1);
  if (colon2 > 0 && did.length > colon2 + 10) {
    return did.slice(0, colon2 + 1) + "•".repeat(12) + did.slice(-5);
  }
  if (did.length > 14) return did.slice(0, 6) + "•".repeat(8) + did.slice(-4);
  return "•".repeat(Math.max(did.length, 8));
}

// Truncated DID shown (instead of the full raw DID) once a contact name is
// already occupying the primary label for this row.
function shortDid(did: string): string {
  if (!did) return did;
  if (did.length <= 22) return did;
  return did.slice(0, 16) + "…" + did.slice(-6);
}

function HideableDID({
  value,
  hidden,
  onToggle,
  style,
}: {
  value: string;
  hidden: boolean;
  onToggle: () => void;
  style?: React.CSSProperties;
}) {
  return (
    <div className="inline-flex items-center gap-1.5 min-w-0 max-w-full">
      {/* DID text is selectable; the adjacent eye button toggles masking. */}
      <span
        className="truncate"
        style={{
          fontFamily: "JetBrains Mono, monospace",
          flexGrow: 0,
          flexShrink: 1,
          minWidth: 0,
          ...style,
        }}
      >
        {hidden ? maskDID(value) : value}
      </span>
      <button
        type="button"
        onClick={e => {
          e.stopPropagation();
          onToggle();
        }}
        aria-label={hidden ? "Show DID" : "Hide DID"}
        title={hidden ? "Click to reveal DID" : "Click to hide DID"}
        className="flex items-center justify-center rounded-md flex-shrink-0"
        style={{
          width: "26px",
          height: "26px",
          backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)",
          border: "1px solid color-mix(in srgb, var(--primary) 22%, transparent)",
          color: "var(--primary)",
          cursor: "pointer",
          padding: 0,
        }}
      >
        {hidden ? <Eye size={13} /> : <EyeOff size={13} />}
      </button>
    </div>
  );
}

export function SC03DIDStatus() {
  const navigate = useNavigate();
  const { contactNameForDid } = useContactNames();
  const [deactivating, setDeactivating] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const { data: didStatus, loading: statusLoading, error: statusError, refetch: refetchStatus } = useDIDStatus();
  const { data: resolveData, loading: resolveLoading } = useDIDResolve();
  const { data: didDocument, loading: docLoading, refetch: refetchDoc } = useDIDDocument();
  const { data: peersData, loading: peersLoading, refetch: refetchPeers } = useDIDDocumentPeers();

  const [showRaw, setShowRaw] = useState(false);
  const [rawDoc, setRawDoc] = useState<DIDDocumentRaw | null>(null);
  const [rawDocTitle, setRawDocTitle] = useState<string>("");
  const [rawInitialView, setRawInitialView] = useState<"structured" | "raw">("structured");
  const [loadingRaw, setLoadingRaw] = useState(false);

  const [verifying, setVerifying] = useState(false);
  const [showPublish, setShowPublish] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [publishHost, setPublishHost] = useState("127.0.0.1");
  const [publishNodeName, setPublishNodeName] = useState("");

  // Per-DID visibility toggle. Defaults to visible; clicking the DID adds it
  // here so it renders masked until clicked again.
  const [hiddenDIDs, setHiddenDIDs] = useState<Set<string>>(new Set());
  const toggleDIDVisibility = (did: string) => {
    setHiddenDIDs(prev => {
      const next = new Set(prev);
      if (next.has(did)) next.delete(did);
      else next.add(did);
      return next;
    });
  };

  const loading = statusLoading || resolveLoading;

  const handleViewRaw = async () => {
    setLoadingRaw(true);
    try {
      const raw = await didService.getDocumentRaw();
      setRawDoc(raw);
      setRawDocTitle("Local DID Document");
      // The "Raw" button opens straight to the Raw JSON tab.
      setRawInitialView("raw");
      setShowRaw(true);
    } catch (err) {
      toast.error("Failed to load DID Document", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setLoadingRaw(false);
    }
  };

  const handleViewPeer = async (peer: DIDDocumentPeerSummary) => {
    setLoadingRaw(true);
    try {
      const raw = await didService.getDocumentPeer(peer.did);
      setRawDoc(raw);
      setRawDocTitle(`Peer: ${peer.node_name}`);
      // Peer rows open the structured summary first.
      setRawInitialView("structured");
      setShowRaw(true);
    } catch (err) {
      toast.error("Failed to load peer DID Document", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setLoadingRaw(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const result = await didService.verifyDocument();
      if (result.valid) {
        toast.success("DID Document verified", {
          description: `${result.message} (v${result.version})`,
        });
      } else {
        toast.error("DID Document invalid", { description: result.message });
      }
    } catch (err) {
      toast.error("Verification failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setVerifying(false);
    }
  };

  const openPublish = () => {
    setPublishNodeName(didDocument?.node_name ?? "");
    setShowPublish(true);
  };

  const handlePublish = async () => {
    if (!publishHost.trim() || !publishNodeName.trim()) {
      toast.error("ca_host and node_name are required");
      return;
    }
    setPublishing(true);
    try {
      const result = await didService.publishDocument(
        publishHost.trim(),
        publishNodeName.trim(),
      );
      if (result.success) {
        toast.success("DID Document published", {
          description: `${result.message} (v${result.version})`,
        });
        setShowPublish(false);
        await Promise.all([refetchDoc(), refetchPeers()]);
      } else {
        toast.error("Publish failed", { description: result.message });
      }
    } catch (err) {
      toast.error("Publish failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setPublishing(false);
    }
  };

  const handleDeactivate = async () => {
    setDeactivating(true);
    try {
      const result = await didService.deactivate(undefined, true);
      if (result.ok) {
        toast.success("DID deactivated", { description: result.message });
        refetchStatus();
      } else {
        toast.error("Deactivation failed", { description: result.message });
      }
    } catch {
      toast.error("Failed to deactivate DID");
    } finally {
      setDeactivating(false);
      setShowConfirm(false);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "—";
    return new Date(dateStr).toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center" style={{ minHeight: "100dvh" }}>
        <Loader2 className="animate-spin" size={32} style={{ color: "var(--primary)" }} />
        <span style={{ marginTop: 16, color: "var(--muted-foreground)" }}>Loading...</span>
      </div>
    );
  }

  // Only active when record exists AND not deactivated
  const isActive = !!didStatus && didStatus.status === "active" && !didStatus.deactivatedAt;
  const noRecord = !didStatus && !!statusError;

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="DID Status" subtitle="Decentralized Identifier" onBack={() => navigate("/settings")} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
        {/* No record state */}
        {noRecord && (
          <div
            className="flex items-center gap-3 p-4 rounded-lg"
            style={{
              backgroundColor: "color-mix(in srgb, var(--muted-foreground) 10%, transparent)",
              border: "1px solid var(--border)",
            }}
          >
            <Fingerprint size={28} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)" }}>
                No DID Record Found
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
                DID has not been provisioned on this node yet.
              </p>
            </div>
          </div>
        )}

        {/* Status Banner — only when record exists */}
        {didStatus && <div
          className="flex items-center gap-3 p-4 rounded-lg"
          style={{
            backgroundColor: isActive
              ? "color-mix(in srgb, var(--chart-2) 10%, transparent)"
              : "color-mix(in srgb, var(--destructive) 10%, transparent)",
            border: `1px solid ${isActive
              ? "color-mix(in srgb, var(--chart-2) 25%, transparent)"
              : "color-mix(in srgb, var(--destructive) 25%, transparent)"}`,
          }}
        >
          <Fingerprint size={28} style={{ color: isActive ? "var(--chart-2)" : "var(--destructive)", flexShrink: 0 }} />
          <div className="flex-1 min-w-0">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: isActive ? "var(--chart-2)" : "var(--destructive)" }}>
              {isActive ? "DID Active" : "DID Deactivated"}
            </p>
            {didStatus?.did && contactNameForDid(didStatus.did) ? (
              <p title={didStatus.did} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                {contactNameForDid(didStatus.did)}
              </p>
            ) : didStatus?.did ? (
              <HideableDID
                value={didStatus.did}
                hidden={hiddenDIDs.has(didStatus.did)}
                onToggle={() => toggleDIDVisibility(didStatus.did)}
                style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}
              />
            ) : (
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>—</p>
            )}
          </div>
          <span
            className="flex items-center gap-1"
            style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: isActive ? "var(--chart-2)" : "var(--destructive)" }}
          >
            {isActive ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
            {isActive ? "Active" : "Inactive"}
          </span>
        </div>}

        {/* DID Details */}
        {didStatus && (
          <div className="rounded-lg border p-4 flex flex-col" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>
              DID DETAILS
            </p>
            <InfoRow label="Method" value={`${didStatus.method} v${didStatus.methodVersion}`} />
            <InfoRow label="DKP Version" value={String(didStatus.currentDkpVersion)} />
            <InfoRow label="SE050 UID Source" value={didStatus.se050UidSource} />
            <InfoRow label="Created" value={formatDate(didStatus.createdAt)} />
            {didStatus.deactivatedAt && (
              <InfoRow label="Deactivated" value={formatDate(didStatus.deactivatedAt)} />
            )}
            <InfoRow label="Public Key Hash" value={didStatus.dikPubkeySha256B16} mono />
          </div>
        )}

        {/* Resolved Public Key */}
        {resolveData && (
          <div className="rounded-lg border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <div className="flex items-center gap-2">
              <Key size={16} style={{ color: "var(--primary)" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                RESOLVED PUBLIC KEY
              </p>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Preview</span>
              <div className="flex items-center gap-1">
                <code style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                  {resolveData.publicKeyPreview}
                </code>
                <CopyButton value={resolveData.publicKeyPreview} />
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Size</span>
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                {resolveData.publicKeyBytes} bytes
              </span>
            </div>
          </div>
        )}

        {/* DID Document Summary */}
        {docLoading ? (
          <div className="rounded-lg border p-4 flex items-center justify-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <Loader2 size={16} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
            <span style={{ marginLeft: 8, fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Loading DID Document…
            </span>
          </div>
        ) : didDocument ? (
          <div className="rounded-lg border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <div className="flex items-center gap-2">
              <FileJson size={16} style={{ color: "var(--primary)" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                DID DOCUMENT
              </p>
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginLeft: "auto" }}>
                v{didDocument.version}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <div className="rounded-md p-2 text-center" style={{ backgroundColor: "var(--muted)" }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-bold)", color: "var(--chart-2)" }}>
                  {didDocument.active_vms}
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Active VMs</p>
              </div>
              <div className="rounded-md p-2 text-center" style={{ backgroundColor: "var(--muted)" }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-bold)", color: "var(--destructive)" }}>
                  {didDocument.revoked_vms}
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Revoked</p>
              </div>
              <div className="rounded-md p-2 text-center" style={{ backgroundColor: "var(--muted)" }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-bold)", color: "var(--foreground)" }}>
                  {didDocument.services}
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Services</p>
              </div>
            </div>

            <InfoRow label="Node" value={didDocument.node_name} />
            <InfoRow label="Status" value={didDocument.status} />
            <InfoRow label="Proof VM" value={didDocument.proof_vm} mono />

            <div className="grid grid-cols-3 gap-2 pt-1">
              <button
                onClick={handleViewRaw}
                disabled={loadingRaw}
                className="flex items-center justify-center gap-1.5 py-2 rounded-lg"
                style={{
                  backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
                  color: "var(--primary)",
                  cursor: loadingRaw ? "not-allowed" : "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                {loadingRaw ? <Loader2 size={12} className="animate-spin" /> : <FileJson size={12} />}
                Raw
              </button>
              <button
                onClick={handleVerify}
                disabled={verifying}
                className="flex items-center justify-center gap-1.5 py-2 rounded-lg"
                style={{
                  backgroundColor: "color-mix(in srgb, var(--chart-2) 10%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)",
                  color: "var(--chart-2)",
                  cursor: verifying ? "not-allowed" : "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                {verifying ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
                Verify
              </button>
              <button
                onClick={openPublish}
                className="flex items-center justify-center gap-1.5 py-2 rounded-lg"
                style={{
                  backgroundColor: "color-mix(in srgb, var(--chart-4) 10%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--chart-4) 25%, transparent)",
                  color: "var(--chart-4)",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                <UploadCloud size={12} />
                Publish
              </button>
            </div>
          </div>
        ) : null}

        {/* Peer DID Documents */}
        <div className="rounded-lg border p-4 flex flex-col gap-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
          <div className="flex items-center gap-2">
            <Users size={16} style={{ color: "var(--primary)" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
              PEER DID DOCUMENTS
            </p>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginLeft: "auto" }}>
              {peersData ? `${peersData.count}` : "—"}
            </span>
          </div>
          {peersLoading ? (
            <div className="flex items-center gap-2" style={{ color: "var(--muted-foreground)" }}>
              <Loader2 size={14} className="animate-spin" />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}>Loading peers…</span>
            </div>
          ) : !peersData || peersData.peers.length === 0 ? (
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center", padding: "8px 0" }}>
              No cached peer documents
            </p>
          ) : (
            <div className="flex flex-col gap-2">
              {peersData.peers.map(peer => {
                const isLoadingThis = loadingRaw && rawDocTitle === `Peer: ${peer.node_name}`;
                const isHidden = hiddenDIDs.has(peer.did);
                const contactName = contactNameForDid(peer.did);
                const peerDisplayName = contactName || peer.node_name;
                return (
                  // Whole row opens the peer document; the eye button only
                  // toggles DID masking and must not trigger the row click.
                  <div
                    key={peer.did}
                    role="button"
                    tabIndex={0}
                    onClick={() => {
                      if (!loadingRaw) handleViewPeer(peer);
                    }}
                    onKeyDown={e => {
                      if ((e.key === "Enter" || e.key === " ") && !loadingRaw) {
                        e.preventDefault();
                        handleViewPeer(peer);
                      }
                    }}
                    aria-label={`View DID Document for ${peerDisplayName}`}
                    title={`View DID Document for ${peerDisplayName}`}
                    className="flex items-center gap-3 p-2.5 rounded-md"
                    style={{
                      backgroundColor: "var(--muted)",
                      border: "1px solid var(--border)",
                      cursor: loadingRaw ? "wait" : "pointer",
                    }}
                  >
                    {isLoadingThis ? (
                      <Loader2 size={14} className="animate-spin" style={{ color: "var(--primary)", flexShrink: 0 }} />
                    ) : (
                      <Fingerprint size={14} style={{ color: peer.status === "active" ? "var(--chart-2)" : "var(--muted-foreground)", flexShrink: 0 }} />
                    )}
                    <div className="flex-1 min-w-0">
                      <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                        {peerDisplayName}
                      </p>
                      <p
                        className="truncate"
                        style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}
                      >
                        {contactName
                          ? (isHidden ? contactName : shortDid(peer.did))
                          : (isHidden ? maskDID(peer.did) : peer.did)}
                      </p>
                    </div>
                    <div className="flex flex-col items-end gap-0.5">
                      <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}>
                        v{peer.version}
                      </span>
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: peer.status === "active" ? "var(--chart-2)" : "var(--muted-foreground)" }}>
                        {peer.status}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={e => {
                        e.stopPropagation();
                        toggleDIDVisibility(peer.did);
                      }}
                      aria-label={isHidden ? `Show DID for ${peerDisplayName}` : `Hide DID for ${peerDisplayName}`}
                      title={isHidden ? "Show DID" : "Hide DID"}
                      className="flex items-center justify-center rounded-md flex-shrink-0"
                      style={{
                        width: "30px",
                        height: "30px",
                        backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)",
                        border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
                        color: "var(--primary)",
                        cursor: "pointer",
                      }}
                    >
                      {isHidden ? <Eye size={14} /> : <EyeOff size={14} />}
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Info Box */}
        <div
          className="flex items-start gap-3 p-4 rounded-lg"
          style={{
            backgroundColor: "color-mix(in srgb, var(--primary) 8%, transparent)",
            border: "1px solid color-mix(in srgb, var(--primary) 20%, transparent)",
          }}
        >
          <Info size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "2px" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)", lineHeight: 1.5 }}>
            The Decentralized Identifier (DID) uniquely identifies this Guardian node using the SE050 secure element UID and the active DKP key.
          </p>
        </div>

        {/* Deactivate Section */}
        {isActive && !showConfirm && (
          <button
            onClick={() => setShowConfirm(true)}
            className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg"
            style={{
              backgroundColor: "color-mix(in srgb, var(--destructive) 12%, transparent)",
              border: "1px solid color-mix(in srgb, var(--destructive) 30%, transparent)",
              color: "var(--destructive)",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
            }}
          >
            <ShieldOff size={16} />
            Deactivate DID
          </button>
        )}

        {showConfirm && (
          <div
            className="rounded-lg border p-4 flex flex-col gap-3"
            style={{
              backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)",
              borderColor: "color-mix(in srgb, var(--destructive) 30%, transparent)",
            }}
          >
            <div className="flex items-start gap-2">
              <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0, marginTop: "2px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)", lineHeight: 1.5 }}>
                This will permanently deactivate this Guardian's DID. This action cannot be undone and requires a restart.
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={() => setShowConfirm(false)}
                className="flex-1 py-2 rounded-lg"
                style={{
                  backgroundColor: "var(--muted)",
                  border: "1px solid var(--border)",
                  color: "var(--foreground)",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleDeactivate}
                disabled={deactivating}
                className="flex-1 py-2 rounded-lg flex items-center justify-center gap-2"
                style={{
                  backgroundColor: "var(--destructive)",
                  border: "none",
                  color: "white",
                  cursor: deactivating ? "not-allowed" : "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                  opacity: deactivating ? 0.7 : 1,
                }}
              >
                {deactivating && <Loader2 size={14} className="animate-spin" />}
                {deactivating ? "Deactivating..." : "Confirm Deactivate"}
              </button>
            </div>
          </div>
        )}
        </div>
      </div>

      {showRaw && rawDoc && (
        <RawDocumentModal title={rawDocTitle} doc={rawDoc} initialView={rawInitialView} onClose={() => setShowRaw(false)} />
      )}

      {showPublish && (
        <PublishModal
          host={publishHost}
          nodeName={publishNodeName}
          onHostChange={setPublishHost}
          onNodeNameChange={setPublishNodeName}
          publishing={publishing}
          onClose={() => setShowPublish(false)}
          onPublish={handlePublish}
        />
      )}

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

function DocSection({
  icon: Icon,
  title,
  count,
  children,
}: {
  icon: typeof Key;
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <div
      className="rounded-lg border p-3 flex flex-col gap-2"
      style={{ backgroundColor: "var(--muted)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center gap-2">
        <Icon size={14} style={{ color: "var(--primary)" }} />
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-semibold)",
            color: "var(--muted-foreground)",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          {title}
        </p>
        {typeof count === "number" && (
          <span
            style={{
              marginLeft: "auto",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            {count}
          </span>
        )}
      </div>
      <div className="flex flex-col gap-1.5">{children}</div>
    </div>
  );
}

function DocRow({
  label,
  value,
  mono = false,
  monoBlock = false,
}: {
  label: string;
  value: string | number | null | undefined;
  mono?: boolean;
  monoBlock?: boolean;
}) {
  const display = value === null || value === undefined || value === "" ? "—" : String(value);
  const copyable = (mono || monoBlock) && display !== "—";
  return (
    <div className={monoBlock ? "flex flex-col gap-1" : "flex items-start justify-between gap-3"}>
      <span
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          color: "var(--muted-foreground)",
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      {monoBlock ? (
        <div
          className="flex items-start gap-1 rounded-md p-2"
          style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}
        >
          <code
            style={{
              flex: 1,
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "10px",
              color: "var(--foreground)",
              wordBreak: "break-all",
              lineHeight: 1.5,
            }}
          >
            {display}
          </code>
          {copyable && <CopyButton value={display} />}
        </div>
      ) : (
        <div className="flex items-center gap-1 min-w-0">
          <span
            className="truncate"
            style={{
              fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--foreground)",
            }}
            title={display}
          >
            {display}
          </span>
          {copyable && <CopyButton value={display} />}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const isActive = status.toLowerCase() === "active";
  const color = isActive ? "var(--chart-2)" : "var(--muted-foreground)";
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full"
      style={{
        padding: "2px 8px",
        backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        color,
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-medium)",
      }}
    >
      {isActive ? <CheckCircle2 size={10} /> : <XCircle size={10} />}
      {status}
    </span>
  );
}

function formatDocDate(iso: string | undefined) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function RawDocumentModal({
  title,
  doc,
  onClose,
  initialView = "structured",
}: {
  title: string;
  doc: DIDDocumentRaw;
  onClose: () => void;
  initialView?: "structured" | "raw";
}) {
  const json = JSON.stringify(doc, null, 2);
  const [copied, setCopied] = useState(false);
  const [view, setView] = useState<"structured" | "raw">(initialView);
  const handleCopy = () => {
    navigator.clipboard.writeText(json);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const revoked = doc["sgx:revokedVerificationMethod"] ?? [];

  return (
    <div
      className="fixed inset-0 flex items-center justify-center z-50 p-4"
      style={{ backgroundColor: "rgba(0,0,0,0.6)", backdropFilter: "blur(2px)" }}
      onClick={onClose}
    >
      <div
        className="w-full flex flex-col rounded-2xl shadow-2xl"
        style={{
          backgroundColor: "var(--card)",
          border: "1px solid var(--border)",
          maxWidth: "680px",
          maxHeight: "85vh",
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-3 p-5 pb-3">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="flex items-center justify-center rounded-xl flex-shrink-0"
              style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)" }}
            >
              <Fingerprint size={18} style={{ color: "var(--primary)" }} />
            </div>
            <div className="min-w-0">
              <p className="truncate" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {title}
              </p>
              <div className="flex items-center gap-2 mt-1">
                <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  v{doc["sgx:versionId"]}
                </span>
                <span style={{ color: "var(--muted-foreground)" }}>·</span>
                <StatusPill status={doc["sgx:status"]} />
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="flex items-center justify-center rounded-lg flex-shrink-0"
            style={{ width: "32px", height: "32px", background: "none", border: "1px solid var(--border)", cursor: "pointer", color: "var(--muted-foreground)" }}
          >
            <X size={16} />
          </button>
        </div>

        {/* View switcher */}
        <div className="px-5 pb-3">
          <div className="flex p-1 rounded-lg" style={{ backgroundColor: "var(--muted)" }}>
            {([
              { id: "structured" as const, label: "Document", icon: FileText },
              { id: "raw" as const, label: "Raw JSON", icon: FileJson },
            ]).map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setView(id)}
                className="flex-1 flex items-center justify-center gap-1.5"
                style={{
                  padding: "6px 10px",
                  borderRadius: "6px",
                  backgroundColor: view === id ? "var(--card)" : "transparent",
                  color: view === id ? "var(--foreground)" : "var(--muted-foreground)",
                  border: view === id ? "1px solid var(--border)" : "none",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: view === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                  cursor: "pointer",
                }}
              >
                <Icon size={12} />
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Body */}
        <div className="overflow-auto px-5 pb-3" style={{ flex: 1, minHeight: 0 }}>
          {view === "structured" ? (
            <div className="flex flex-col gap-3">
              <DocSection icon={Fingerprint} title="Identity">
                <DocRow label="DID" value={doc.id} monoBlock />
                <DocRow label="Controller" value={doc.controller} monoBlock />
                <DocRow label="Node" value={doc["sgx:nodeName"]} />
                <DocRow label="Method Spec" value={`v${doc["sgx:methodSpecVersion"]}`} />
                <DocRow label="Created" value={formatDocDate(doc["sgx:created"])} />
                <DocRow label="Updated" value={formatDocDate(doc["sgx:updated"])} />
              </DocSection>

              {doc["@context"]?.length > 0 && (
                <DocSection icon={Link2} title="Context" count={doc["@context"].length}>
                  <div className="flex flex-wrap gap-1.5">
                    {doc["@context"].map((ctx, i) => (
                      <span
                        key={`${ctx}-${i}`}
                        style={{
                          padding: "3px 8px",
                          borderRadius: "999px",
                          backgroundColor: "var(--background)",
                          border: "1px solid var(--border)",
                          fontFamily: "JetBrains Mono, monospace",
                          fontSize: "10px",
                          color: "var(--foreground)",
                          wordBreak: "break-all",
                        }}
                      >
                        {ctx}
                      </span>
                    ))}
                  </div>
                </DocSection>
              )}

              <DocSection icon={Key} title="Verification Methods" count={doc.verificationMethod?.length ?? 0}>
                {(doc.verificationMethod ?? []).map(vm => (
                  <div
                    key={vm.id}
                    className="rounded-md p-2 flex flex-col gap-1"
                    style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}
                  >
                    <DocRow label="ID" value={vm.id} mono />
                    <DocRow label="Type" value={vm.type} />
                    <DocRow label="Curve" value={`${vm.publicKeyJwk.kty} / ${vm.publicKeyJwk.crv}`} />
                    <DocRow label="Key ID" value={vm.publicKeyJwk.kid} mono />
                  </div>
                ))}
              </DocSection>

              {revoked.length > 0 && (
                <DocSection icon={ShieldOff} title="Revoked Verification Methods" count={revoked.length}>
                  {revoked.map(rv => (
                    <div
                      key={rv.id}
                      className="rounded-md p-2 flex flex-col gap-1"
                      style={{
                        backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)",
                        border: "1px solid color-mix(in srgb, var(--destructive) 20%, transparent)",
                      }}
                    >
                      <DocRow label="ID" value={rv.id} mono />
                      <DocRow label="Reason" value={rv.reason} />
                      <DocRow label="Revoked At" value={formatDocDate(rv.revokedAt)} />
                    </div>
                  ))}
                </DocSection>
              )}

              {(doc.authentication?.length > 0 || doc.assertionMethod?.length > 0) && (
                <DocSection icon={ShieldCheck} title="Key Purposes">
                  {doc.authentication?.length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                        Authentication
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {doc.authentication.map(ref => (
                          <span
                            key={`auth-${ref}`}
                            style={{
                              padding: "3px 8px",
                              borderRadius: "6px",
                              backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)",
                              border: "1px solid color-mix(in srgb, var(--primary) 22%, transparent)",
                              color: "var(--primary)",
                              fontFamily: "JetBrains Mono, monospace",
                              fontSize: "10px",
                              wordBreak: "break-all",
                            }}
                          >
                            {ref}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {doc.assertionMethod?.length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                        Assertion
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {doc.assertionMethod.map(ref => (
                          <span
                            key={`asrt-${ref}`}
                            style={{
                              padding: "3px 8px",
                              borderRadius: "6px",
                              backgroundColor: "color-mix(in srgb, var(--chart-2) 10%, transparent)",
                              border: "1px solid color-mix(in srgb, var(--chart-2) 22%, transparent)",
                              color: "var(--chart-2)",
                              fontFamily: "JetBrains Mono, monospace",
                              fontSize: "10px",
                              wordBreak: "break-all",
                            }}
                          >
                            {ref}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </DocSection>
              )}

              {(doc.service?.length ?? 0) > 0 && (
                <DocSection icon={Globe} title="Services" count={doc.service.length}>
                  {doc.service.map(svc => (
                    <div
                      key={svc.id}
                      className="rounded-md p-2 flex flex-col gap-1"
                      style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)" }}
                    >
                      <DocRow label="ID" value={svc.id} mono />
                      <DocRow label="Type" value={svc.type} />
                      <DocRow label="Endpoint" value={svc.serviceEndpoint} mono />
                    </div>
                  ))}
                </DocSection>
              )}

              {doc.proof && (
                <DocSection icon={Lock} title="Proof">
                  <DocRow label="Type" value={doc.proof.type} />
                  <DocRow label="Cryptosuite" value={doc.proof.cryptosuite} />
                  <DocRow label="Purpose" value={doc.proof.proofPurpose} />
                  <DocRow label="Created" value={formatDocDate(doc.proof.created)} />
                  <DocRow label="Verification Method" value={doc.proof.verificationMethod} monoBlock />
                  <DocRow label="Proof Value" value={doc.proof.proofValue} monoBlock />
                </DocSection>
              )}
            </div>
          ) : (
            <div
              className="rounded-lg p-3"
              style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)" }}
            >
              <pre style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", lineHeight: 1.5, whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}>
                {json}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex gap-2 p-5 pt-3" style={{ borderTop: "1px solid var(--border)" }}>
          <button
            onClick={handleCopy}
            className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg"
            style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
          >
            {copied ? <Check size={14} style={{ color: "var(--chart-2)" }} /> : <Copy size={14} />}
            {copied ? "Copied" : "Copy JSON"}
          </button>
          <button
            onClick={onClose}
            className="flex-1 py-2 rounded-lg"
            style={{ backgroundColor: "var(--primary)", border: "none", color: "var(--primary-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function PublishModal({
  host,
  nodeName,
  onHostChange,
  onNodeNameChange,
  publishing,
  onClose,
  onPublish,
}: {
  host: string;
  nodeName: string;
  onHostChange: (v: string) => void;
  onNodeNameChange: (v: string) => void;
  publishing: boolean;
  onClose: () => void;
  onPublish: () => void;
}) {
  return (
    <div
      className="fixed inset-0 flex items-center justify-center z-50 p-4"
      style={{ backgroundColor: "rgba(0,0,0,0.6)", backdropFilter: "blur(2px)" }}
      onClick={onClose}
    >
      <div
        className="w-full flex flex-col gap-5 rounded-2xl p-6 shadow-2xl"
        style={{ backgroundColor: "var(--card)", border: "1px solid var(--border)", maxWidth: "420px" }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div
              className="flex items-center justify-center rounded-xl"
              style={{ width: "40px", height: "40px", backgroundColor: "color-mix(in srgb, var(--chart-4) 15%, transparent)" }}
            >
              <UploadCloud size={18} style={{ color: "var(--chart-4)" }} />
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Publish DID Document
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
                Force republish to CA registry
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex items-center justify-center rounded-lg"
            style={{ width: "32px", height: "32px", background: "none", border: "1px solid var(--border)", cursor: "pointer", color: "var(--muted-foreground)", flexShrink: 0 }}
          >
            <X size={16} />
          </button>
        </div>

        <div
          className="flex items-start gap-2 p-3 rounded-lg"
          style={{
            backgroundColor: "color-mix(in srgb, var(--chart-4) 8%, transparent)",
            border: "1px solid color-mix(in srgb, var(--chart-4) 20%, transparent)",
          }}
        >
          <AlertTriangle size={14} style={{ color: "var(--chart-4)", flexShrink: 0, marginTop: "2px" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-4)", lineHeight: 1.4 }}>
            Maintenance/recovery endpoint. Normally Guardian publishes DID Documents automatically. Member nodes only.
          </p>
        </div>

        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              CA Host
            </label>
            <input
              type="text"
              value={host}
              onChange={e => onHostChange(e.target.value)}
              placeholder="127.0.0.1"
              style={{
                padding: "8px 12px", borderRadius: "8px",
                border: "1px solid var(--border)", backgroundColor: "var(--background)",
                color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace",
                fontSize: "var(--text-sm)", outline: "none",
              }}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              Node Name
            </label>
            <input
              type="text"
              value={nodeName}
              onChange={e => onNodeNameChange(e.target.value)}
              placeholder="nodeB"
              style={{
                padding: "8px 12px", borderRadius: "8px",
                border: "1px solid var(--border)", backgroundColor: "var(--background)",
                color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace",
                fontSize: "var(--text-sm)", outline: "none",
              }}
            />
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl"
            style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
          >
            Cancel
          </button>
          <button
            onClick={onPublish}
            disabled={publishing}
            className="flex-1 py-2.5 rounded-xl flex items-center justify-center gap-2"
            style={{ backgroundColor: "var(--chart-4)", border: "none", color: "white", cursor: publishing ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", opacity: publishing ? 0.7 : 1 }}
          >
            {publishing ? <Loader2 size={14} className="animate-spin" /> : <UploadCloud size={14} />}
            {publishing ? "Publishing…" : "Publish"}
          </button>
        </div>
      </div>
    </div>
  );
}
