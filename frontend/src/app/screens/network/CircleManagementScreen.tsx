import { ChangeEvent, useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { Archive, ArchiveRestore, Check, ChevronLeft, Clipboard, Copy, Download, Edit3, Link2, Loader2, Mail, MessageCircle, Plus, QrCode, RefreshCw, Search, Send, Share2, Trash2, Upload, UserPlus, Users, X } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { toast } from "sonner";
import circleService, { Circle, CircleInvite, CircleMember, CircleRole } from "../../services/circleService";
import didService, { DIDDocumentPeerSummary } from "../../services/didService";

type Tab = "details" | "members" | "invites";
const roles: CircleRole[] = ["owner", "member"];
const roleLabel = (role?: CircleRole) => role === "owner" ? "Admin" : "Member";
const fieldClass = "w-full rounded-md border border-border bg-input-background px-3 py-2.5 text-sm outline-none focus:border-primary";
const secondaryButton = "inline-flex items-center justify-center gap-2 rounded-md border border-border bg-secondary px-3 py-2 text-sm font-medium text-secondary-foreground transition-opacity active:opacity-70 disabled:opacity-50";
const primaryButton = "inline-flex items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-opacity active:opacity-80 disabled:opacity-50";
const normalizeGuardianDid = (did: string) => did.trim().startsWith("did:guardian:") ? did.trim() : `did:guardian:${did.trim()}`;
const inviteShareValue = (invite: CircleInvite | null) => invite?.url || invite?.qrPayload || (invite?.token ? `sgx-guardian://circle/join?token=${encodeURIComponent(invite.token)}` : "");
const stateLabel = (invite: CircleInvite) => {
  const raw = String(invite.state || invite.status || "").toLowerCase();
  if (raw === "accepted") return "Accepted";
  if (raw === "rejected") return "Rejected";
  if (raw === "expired") return "Expired";
  if (invite.expiresAt && Date.now() > new Date(invite.expiresAt).getTime()) return "Expired";
  if (invite.delivered === true || raw === "sent" || raw === "pending") return "Sent";
  return "Generated";
};

function ConfirmDialog({ title, message, confirmLabel, onConfirm, onClose, busy, tone = "destructive" }: { title: string; message: string; confirmLabel: string; onConfirm: () => void; onClose: () => void; busy: boolean; tone?: "destructive" | "primary" }) {
  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/65 p-4" role="dialog" aria-modal="true">
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-5 shadow-2xl">
        <h2 className="text-lg font-semibold">{title}</h2>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">{message}</p>
        <div className="mt-5 flex justify-end gap-2">
          <button className={secondaryButton} onClick={onClose} disabled={busy}>Cancel</button>
          <button className={tone === "primary" ? primaryButton : "inline-flex items-center gap-2 rounded-md bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground disabled:opacity-50"} onClick={onConfirm} disabled={busy}>
            {busy && <Loader2 size={15} className="animate-spin" />}{confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function CircleManagementScreen() {
  const { circleId = "" } = useParams();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("details");
  const [circle, setCircle] = useState<Circle | null>(null);
  const [members, setMembers] = useState<CircleMember[]>([]);
  const [invites, setInvites] = useState<CircleInvite[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [memberDid, setMemberDid] = useState("");
  const [memberRole, setMemberRole] = useState<CircleRole>("member");
  const [inviteRole] = useState<CircleRole>("member");
  const [inviteHours, setInviteHours] = useState(24);
  const [inviteMaxUses, setInviteMaxUses] = useState(1);
  const [targetDid, setTargetDid] = useState("");
  const [didSearch, setDidSearch] = useState("");
  const [didPeers, setDidPeers] = useState<DIDDocumentPeerSummary[]>([]);
  const [inviteQrOpen, setInviteQrOpen] = useState(false);
  const [newInvite, setNewInvite] = useState<CircleInvite | null>(null);
  const [confirm, setConfirm] = useState<{ kind: "archive" } | { kind: "unarchive" } | { kind: "delete" } | { kind: "member"; did: string } | { kind: "invite"; id: string } | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const [detailResult, memberResult, inviteResult] = await Promise.allSettled([
        circleService.getById(circleId), circleService.getMembers(circleId), circleService.getInvites(circleId),
      ]);
      if (detailResult.status === "rejected") throw detailResult.reason;
      const detail = detailResult.value;
      const memberList = memberResult.status === "fulfilled" ? memberResult.value : [];
      const inviteList = inviteResult.status === "fulfilled" ? inviteResult.value : [];
      setCircle(detail);
      setName(detail.name || "");
      setDescription(detail.description || "");
      setMembers(memberList);
      setInvites(inviteList);
      if (memberResult.status === "rejected") toast.error("Circle loaded, but members could not be retrieved");
      if (inviteResult.status === "rejected") toast.error("Circle loaded, but invites could not be retrieved");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to load Circle controls");
    } finally {
      setLoading(false);
    }
  }, [circleId]);

  useEffect(() => { void reload(); }, [reload]);

  useEffect(() => {
    if (tab !== "invites") return;
    didService.getDocumentPeers()
      .then((result) => setDidPeers(result.peers || []))
      .catch(() => setDidPeers([]));
  }, [tab]);

  const saveDetails = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      const updated = await circleService.update(circleId, { name: name.trim(), description: description.trim() });
      setCircle(updated);
      toast.success("Circle updated");
    } catch (error) { toast.error(error instanceof Error ? error.message : "Update failed"); }
    finally { setBusy(false); }
  };

  const addMember = async (did = memberDid, role = memberRole) => {
    if (!did.trim()) return false;
    try {
      await circleService.addMember(circleId, { did: did.trim(), role });
      return true;
    } catch (error) {
      toast.error(error instanceof Error ? error.message : `Could not add ${did}`);
      return false;
    }
  };

  const submitMember = async () => {
    setBusy(true);
    if (await addMember()) {
      setMemberDid("");
      toast.success("Circle membership added", { description: "Calling becomes available after this DID has an approved trusted-peer record." });
      await reload();
    }
    setBusy(false);
  };

  const uploadMembers = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setBusy(true);
    try {
      const rows = (await file.text()).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      const parsed = rows.map((line, index) => {
        const [did, rawRole] = line.split(",").map((value) => value.trim());
        const normalizedRole = (rawRole || "").toLowerCase();
        if (normalizedRole && normalizedRole !== "role" && !roles.includes(normalizedRole as CircleRole)) {
          throw new Error(`Unsupported Circle role "${rawRole}" on row ${index + 1}; use owner or member`);
        }
        const role = normalizedRole === "owner" ? "owner" : "member";
        if (!did || (did.toLowerCase() !== "did" && !did.startsWith("did:"))) throw new Error(`Invalid DID on row ${index + 1}`);
        return { did, role };
      }).filter((row) => row.did.toLowerCase() !== "did");
      const results = await Promise.allSettled(parsed.map((row) => circleService.addMember(circleId, row)));
      const added = results.filter((result) => result.status === "fulfilled").length;
      if (added) toast.success(`${added} member${added === 1 ? "" : "s"} uploaded`);
      if (added !== results.length) toast.error(`${results.length - added} member rows failed`);
      await reload();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Member upload failed"); }
    finally { setBusy(false); }
  };

  const updateRole = async (did: string, role: CircleRole) => {
    setBusy(true);
    try { await circleService.updateMember(circleId, did, { role }); toast.success("Member role updated"); await reload(); }
    catch (error) { toast.error(error instanceof Error ? error.message : "Role update failed"); }
    finally { setBusy(false); }
  };

  const restoreMember = async (member: CircleMember) => {
    setBusy(true);
    try {
      await circleService.addMember(circleId, { did: member.did, role: member.role || "member" });
      toast.success("Member added back to the Circle");
      await reload();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Member could not be added again");
    } finally {
      setBusy(false);
    }
  };

  const createInvite = async () => {
    const did = targetDid.trim();
    if (!did) { toast.error("Target Guardian DID is required"); return; }
    setBusy(true);
    try {
      const normalizedDid = normalizeGuardianDid(did);
      const invite = await circleService.createInvite(circleId, { targetDid: normalizedDid, role: inviteRole, expiresInMinutes: inviteHours * 60, maxUses: inviteMaxUses, deliver: false });
      setNewInvite({ ...invite, targetDid: invite.targetDid || normalizedDid });
      setInviteQrOpen(false);
      toast.success("Invite generated");
      await reload();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Invite creation failed"); }
    finally { setBusy(false); }
  };

  const copyInvite = async (invite: CircleInvite) => {
    const value = inviteShareValue(invite) || invite.id;
    await navigator.clipboard.writeText(value);
    toast.success("Invite copied");
  };

  const shareInvite = async (invite: CircleInvite) => {
    const value = inviteShareValue(invite);
    if (!value) { toast.error("This invite has no shareable token"); return; }
    try {
      if (navigator.share) {
        await navigator.share({ title: `Join ${circle?.name || "my Circle"}`, text: "Use this verified SG-X Guardian invite to join the Circle.", url: value });
      } else {
        await navigator.clipboard.writeText(value);
        toast.success("Invite copied — paste it into your messaging app");
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      await navigator.clipboard.writeText(value).catch(() => undefined);
      toast.success("Invite copied — paste it into your messaging app");
    }
  };

  const sendDirectInvite = async (invite = newInvite) => {
    if (!invite?.id) { toast.error("Generate an invite first"); return; }
    setBusy(true);
    try {
      const delivered = await circleService.deliverInvite(circleId, invite.id);
      const updated = { ...invite, ...delivered, targetDid: invite.targetDid || delivered.targetDid || targetDid };
      setNewInvite(updated);
      setInvites((prev) => prev.map((item) => item.id === updated.id ? updated : item));
      if (updated.delivered === true) toast.success("Direct invite sent");
      else toast.error("Direct invite was not delivered", { description: updated.deliveryError || "Backend returned delivered:false." });
      await reload();
    } catch (error) {
      toast.error("Direct invite failed", { description: error instanceof Error ? error.message : "Try again." });
    } finally {
      setBusy(false);
    }
  };

  const selectInviteDid = (did: string, label?: string) => {
    const normalizedDid = normalizeGuardianDid(did);
    setTargetDid(normalizedDid);
    setDidSearch(label || normalizedDid);
    setNewInvite(null);
    setInviteQrOpen(false);
  };

  const selectTypedInviteDid = () => {
    const candidate = didSearch.trim();
    if (!candidate) { toast.error("Enter a Guardian DID first"); return; }
    selectInviteDid(candidate);
  };

  const redirectMemberDidToInvite = () => {
    if (memberDid.trim()) selectInviteDid(memberDid.trim());
    setTab("invites");
  };

  const openWhatsApp = (invite: CircleInvite) => {
    const value = inviteShareValue(invite);
    if (!value) { toast.error("Generate an invite link first"); return; }
    window.open(`https://wa.me/?text=${encodeURIComponent(value)}`, "_blank", "noopener,noreferrer");
  };

  const openEmail = (invite: CircleInvite) => {
    const value = inviteShareValue(invite);
    if (!value) { toast.error("Generate an invite link first"); return; }
    window.location.href = `mailto:?subject=${encodeURIComponent(`Join ${circle?.name || "my Circle"}`)}&body=${encodeURIComponent(value)}`;
  };

  const downloadQr = () => {
    const svg = document.querySelector("#admin-circle-invite-qr svg");
    if (!svg || !newInvite) return;
    const blob = new Blob([new XMLSerializer().serializeToString(svg)], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${String(newInvite.id || "circle-invite").replace(/[^a-z0-9-]+/gi, "_")}.svg`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const runConfirmedAction = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      if (confirm.kind === "archive") {
        await circleService.archive(circleId);
        toast.success("Circle archived");
        navigate("/network", { replace: true });
      } else if (confirm.kind === "unarchive") {
        await circleService.unarchive(circleId);
        toast.success("Circle unarchived");
        await reload();
      } else if (confirm.kind === "delete") {
        await circleService.remove(circleId);
        toast.success("Circle deleted");
        navigate("/network", { replace: true });
      } else if (confirm.kind === "member") {
        await circleService.removeMember(circleId, confirm.did);
        toast.success("Member removed");
        await reload();
      } else {
        await circleService.revokeInvite(circleId, confirm.id);
        toast.success("Invite revoked");
        await reload();
      }
      setConfirm(null);
    } catch (error) { toast.error(error instanceof Error ? error.message : "Action failed"); }
    finally { setBusy(false); }
  };

  const currentMembers = members.filter((member) => member.status !== "revoked" && member.status !== "expired");
  const revokedMembers = members.filter((member) => member.status === "revoked");
  const filteredDidPeers = didPeers.filter((peer) => {
    const needle = didSearch.trim().toLowerCase();
    if (!needle) return true;
    return `${peer.did} ${peer.node_name}`.toLowerCase().includes(needle);
  });
  const selectedPeer = didPeers.find((peer) => peer.did === targetDid);

  const memberRow = (member: CircleMember, revoked = false) => {
    const primaryOwner = member.did === circle?.ownerDid;
    return (
    <div key={member.did || member.id} className="flex flex-col gap-3 border-b border-border p-4 last:border-0 sm:flex-row sm:items-center">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2"><p className="truncate text-sm font-medium">{member.name || member.email || member.did}</p>{primaryOwner && <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-primary">Primary admin</span>}{revoked && <span className="rounded-full bg-destructive/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-destructive">Deleted</span>}</div>
        <p className="truncate font-mono text-xs text-muted-foreground">{member.did}</p>
        {revoked && <p className="mt-1 text-xs text-muted-foreground">Membership credential revoked; the DID can be added to this Circle again.</p>}
      </div>
      <select className="rounded-md border border-border bg-input-background px-2 py-2 text-sm" value={member.role || "member"} onChange={(e) => void updateRole(member.did, e.target.value as CircleRole)} disabled={busy || revoked || primaryOwner}>{roles.map((role) => <option key={role} value={role}>{roleLabel(role)}</option>)}</select>
      {revoked ? <button className={primaryButton} onClick={() => void restoreMember(member)} disabled={busy} aria-label={`Add ${member.name || member.did} again`}><UserPlus size={15} />Add again</button> : <button className={secondaryButton} onClick={() => setConfirm({ kind: "member", did: member.did })} disabled={busy || primaryOwner} aria-label={`Remove ${member.name || member.did}`}><Trash2 size={15} className="text-destructive" /></button>}
    </div>
    );
  };

  if (loading && !circle) return <div className="flex h-full items-center justify-center gap-3"><Loader2 className="animate-spin text-primary" /> Loading Circle…</div>;

  return (
    <div className="flex h-full flex-col bg-background">
      <header className="flex h-16 flex-shrink-0 items-center justify-between border-b border-border px-4 md:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <button className={secondaryButton} onClick={() => navigate(`/network?circle=${encodeURIComponent(circleId)}`, { replace: true })} aria-label="Back to Circles"><ChevronLeft size={17} /> Circles</button>
          <div className="min-w-0"><h1 className="truncate text-lg font-semibold">Manage {circle?.name || "Circle"}</h1><p className="text-xs text-muted-foreground">Circle administration</p></div>
        </div>
        <button className={secondaryButton} onClick={() => void reload()} disabled={loading}><RefreshCw size={15} className={loading ? "animate-spin" : ""} /><span className="hidden sm:inline">Refresh</span></button>
      </header>

      <nav className="flex flex-shrink-0 border-b border-border bg-card px-3 md:px-6" aria-label="Circle management">
        {(["details", "members", "invites"] as Tab[]).map((item) => <button key={item} onClick={() => setTab(item)} className="px-4 py-3 text-sm capitalize" style={{ color: tab === item ? "var(--primary)" : "var(--muted-foreground)", borderBottom: tab === item ? "2px solid var(--primary)" : "2px solid transparent" }}>{item}</button>)}
      </nav>

      <main className="flex-1 overflow-y-auto p-4 md:p-6">
        <div className="mx-auto max-w-3xl">
          {tab === "details" && <div className="space-y-5">
            <section className="rounded-xl border border-border bg-card p-5">
              <div className="mb-4 flex items-center gap-2"><Edit3 size={18} className="text-primary" /><h2 className="font-semibold">Circle details</h2></div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">Name</label><input className={fieldClass} value={name} onChange={(e) => setName(e.target.value)} maxLength={100} />
              <label className="mb-1.5 mt-4 block text-xs font-medium text-muted-foreground">Description</label><textarea className={fieldClass} rows={4} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
              <div className="mt-4 flex justify-end"><button className={primaryButton} onClick={saveDetails} disabled={busy || !name.trim()}>{busy && <Loader2 size={15} className="animate-spin" />}Save changes</button></div>
            </section>
            {circle?.status === "archived" ? <section className="rounded-xl border border-border bg-card p-5"><div className="flex items-center gap-2"><Archive size={18} className="text-muted-foreground" /><h2 className="font-semibold">Archived Circle</h2></div><p className="mt-2 text-sm leading-6 text-muted-foreground">This Circle is read-only and remains available in the Archived Circles section for audit history.</p><button className={`${primaryButton} mt-4`} onClick={() => setConfirm({ kind: "unarchive" })} disabled={busy}><ArchiveRestore size={15} />Unarchive Circle</button><div className="mt-4 border-t border-destructive/25 pt-4"><p className="text-sm font-medium text-destructive">Delete this Circle</p><p className="mt-1 text-xs leading-5 text-muted-foreground">Permanently deletes the Circle and revokes every membership credential issued for it. This cannot be undone.</p><button className="mt-3 inline-flex items-center gap-2 rounded-md bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground disabled:opacity-50" onClick={() => setConfirm({ kind: "delete" })} disabled={busy}><Trash2 size={15} />Delete Circle</button></div></section> : <section className="rounded-xl border border-destructive/35 bg-card p-5"><h2 className="font-semibold text-destructive">Circle lifecycle</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">Archiving removes the Circle from active use while retaining its security audit history. Deleting permanently removes the Circle and revokes every membership credential issued for it.</p><div className="mt-4 flex flex-wrap gap-2"><button className="inline-flex items-center gap-2 rounded-md bg-destructive px-4 py-2 text-sm font-semibold text-destructive-foreground disabled:opacity-50" onClick={() => setConfirm({ kind: "archive" })} disabled={busy}><Archive size={15} />Archive Circle</button><button className="inline-flex items-center gap-2 rounded-md border border-destructive px-4 py-2 text-sm font-semibold text-destructive disabled:opacity-50" onClick={() => setConfirm({ kind: "delete" })} disabled={busy}><Trash2 size={15} />Delete Circle</button></div></section>}
          </div>}

          {tab === "members" && <div className="space-y-5">
            <section className="rounded-xl border border-border bg-card p-5"><div className="mb-4 flex items-center gap-2"><UserPlus size={18} className="text-primary" /><h2 className="font-semibold">Add member</h2></div><div className="grid gap-3 sm:grid-cols-[1fr_150px_auto]"><input className={fieldClass} value={memberDid} onChange={(e) => setMemberDid(e.target.value)} placeholder="did:guardian:…" /><select className={fieldClass} value={memberRole} onChange={(e) => setMemberRole(e.target.value as CircleRole)}><option value="member">Member — participant</option><option value="owner">Admin — administrator</option></select><button className={primaryButton} onClick={submitMember} disabled={busy || !memberDid.trim()}><Plus size={15} />Add</button></div><div className="mt-3 flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-muted-foreground">Circle membership does not grant network trust. Voice and video calling activate after this DID completes certificate approval and mutual attestation.</p><button className={secondaryButton} onClick={redirectMemberDidToInvite}><Send size={14} />Use DID invite flow</button></div><div className="mt-4 flex items-center justify-between border-t border-border pt-4"><div><p className="text-sm font-medium">Bulk upload</p><p className="text-xs text-muted-foreground">CSV rows use backend roles: <code>did,role</code> with owner or member</p></div><label className={`${secondaryButton} cursor-pointer`}><Upload size={15} />Upload CSV<input className="hidden" type="file" accept=".csv,text/csv,text/plain" onChange={uploadMembers} disabled={busy} /></label></div></section>
            <section className="overflow-hidden rounded-xl border border-border bg-card"><div className="flex items-center justify-between border-b border-border p-4"><div className="flex items-center gap-2"><Users size={18} className="text-primary" /><h2 className="font-semibold">Active Members</h2></div><span className="text-xs text-muted-foreground">{currentMembers.length} active</span></div>{currentMembers.length === 0 ? <p className="p-8 text-center text-sm text-muted-foreground">No active members in this Circle.</p> : currentMembers.map((member) => memberRow(member))}</section>
            <section className="overflow-hidden rounded-xl border border-destructive/25 bg-card"><div className="flex items-center justify-between border-b border-border p-4"><div className="flex items-center gap-2"><Trash2 size={18} className="text-destructive" /><h2 className="font-semibold">Deleted Members</h2></div><span className="text-xs text-muted-foreground">{revokedMembers.length} deleted</span></div>{revokedMembers.length === 0 ? <p className="p-8 text-center text-sm text-muted-foreground">No deleted members.</p> : revokedMembers.map((member) => memberRow(member, true))}</section>
          </div>}

          {tab === "invites" && <div className="space-y-5">
            <section className="rounded-xl border border-border bg-card p-5">
              <div className="mb-4 flex items-center gap-2"><Link2 size={18} className="text-primary" /><h2 className="font-semibold">Create invite link</h2></div>
              <label className="mb-1.5 block text-xs font-medium text-muted-foreground">Target Guardian DID</label>
              <input
                className={fieldClass}
                value={targetDid}
                onChange={(e) => {
                  setTargetDid(e.target.value);
                  setNewInvite(null);
                  setInviteQrOpen(false);
                }}
                placeholder="did:guardian:..."
              />
              <label className="mb-1.5 mt-3 block text-xs font-medium text-muted-foreground">Search / Select Guardian DID</label>
              <div className="flex items-center gap-2 rounded-md border border-border bg-input-background px-3 py-2.5">
                <Search size={15} className="text-muted-foreground" />
                <input className="min-w-0 flex-1 bg-transparent text-sm outline-none" value={didSearch} onChange={(e) => { const value = e.target.value; setDidSearch(value); if (value.trim().startsWith("did:guardian:")) setTargetDid(normalizeGuardianDid(value)); setNewInvite(null); }} placeholder="Search/select DID..." />
                <button className="text-xs font-semibold text-primary disabled:opacity-40" onClick={selectTypedInviteDid} disabled={!didSearch.trim()}>Select</button>
              </div>
              <div className="mt-2 max-h-48 overflow-y-auto rounded-md border border-border">
                {didSearch.trim() && <button className="flex w-full flex-col gap-1 border-b border-border px-3 py-2 text-left hover:bg-muted/60" onClick={selectTypedInviteDid}>
                  <span className="text-sm font-medium">Use typed DID</span>
                  <span className="break-all font-mono text-[10px] text-muted-foreground">{normalizeGuardianDid(didSearch)}</span>
                </button>}
                {filteredDidPeers.length === 0 && !didSearch.trim() ? <p className="px-3 py-3 text-xs text-muted-foreground">Search discovered Guardians or paste a DID.</p> : filteredDidPeers.map((peer) => {
                  const active = peer.did === targetDid;
                  return (
                  <button key={peer.did} className="flex w-full items-center justify-between gap-3 border-b border-border px-3 py-2 text-left last:border-0 hover:bg-muted/60" onClick={() => selectInviteDid(peer.did, peer.node_name || peer.did)}>
                    <span className="min-w-0">
                    <span className="text-sm font-medium">{peer.node_name || "Guardian"}</span>
                    <span className="block truncate font-mono text-[10px] text-muted-foreground">{peer.did}</span>
                    </span>
                    {active && <Check size={15} className="shrink-0 text-primary" />}
                  </button>
                );})}
              </div>
              {targetDid && <p className="mt-2 break-all font-mono text-xs text-muted-foreground">Selected: {targetDid}</p>}
              <div className="mt-3 grid gap-3 sm:grid-cols-[1fr_1fr_120px_auto]">
                <select className={fieldClass} value={inviteRole} disabled aria-label="Role"><option value="member">Member</option></select>
                <select className={fieldClass} value={inviteHours} onChange={(e) => setInviteHours(Number(e.target.value))}><option value={1}>Expires in 1 hour</option><option value={24}>Expires in 24 hours</option><option value={168}>Expires in 7 days</option></select>
                <input className={fieldClass} type="number" min={1} max={100} value={inviteMaxUses} onChange={(e) => setInviteMaxUses(Math.max(1, Number(e.target.value)))} aria-label="Maximum uses" title="Maximum uses" />
                <button className={primaryButton} onClick={createInvite} disabled={busy || !targetDid.trim()}>{busy ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}Generate Link</button>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">Maximum uses: {inviteMaxUses}. Direct delivery is separate; generating only creates signed invite material.</p>
              {newInvite && <div className="mt-4 rounded-lg border border-primary/30 bg-primary/5 p-4">
                <div className="flex items-center gap-2"><Check size={16} className="text-primary" /><h3 className="text-sm font-semibold">Invite generated</h3></div>
                <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-[110px_1fr]"><dt className="text-muted-foreground">Target</dt><dd className="break-all font-mono text-xs">{newInvite.targetDid || targetDid}</dd><dt className="text-muted-foreground">Guardian</dt><dd>{selectedPeer?.node_name || "Unknown Guardian"}</dd><dt className="text-muted-foreground">Role</dt><dd>{roleLabel(newInvite.role)}</dd><dt className="text-muted-foreground">Expiry</dt><dd>{newInvite.expiresAt ? new Date(newInvite.expiresAt).toLocaleString() : `${inviteHours} hours`}</dd><dt className="text-muted-foreground">Link</dt><dd className="break-all font-mono text-xs">{inviteShareValue(newInvite) || newInvite.id}</dd></dl>
                <div className="mt-4 flex flex-wrap gap-2"><button className={primaryButton} onClick={() => void sendDirectInvite()} disabled={busy}><Send size={14} />Send Direct Invite</button><button className={secondaryButton} onClick={() => void copyInvite(newInvite)}><Copy size={14} />Copy Link</button><button className={secondaryButton} onClick={() => openWhatsApp(newInvite)}><MessageCircle size={14} />WhatsApp</button><button className={secondaryButton} onClick={() => openEmail(newInvite)}><Mail size={14} />Email</button><button className={secondaryButton} onClick={() => void shareInvite(newInvite)}><Share2 size={14} />Share</button><button className={secondaryButton} onClick={() => setInviteQrOpen((open) => !open)}><QrCode size={14} />View / Download QR</button></div>
                {inviteQrOpen && <div id="admin-circle-invite-qr" className="mt-4 inline-flex flex-col items-center gap-3 rounded-md border border-border bg-background p-4"><QRCodeSVG value={inviteShareValue(newInvite) || newInvite.id} size={220} bgColor="transparent" fgColor="var(--foreground)" level="M" /><button className={secondaryButton} onClick={downloadQr}><Download size={14} />Download QR</button></div>}
              </div>}
            </section>
            <section className="overflow-hidden rounded-xl border border-border bg-card"><div className="flex items-center justify-between border-b border-border p-4"><h2 className="font-semibold">Active invites</h2><span className="text-xs text-muted-foreground">{invites.length} total</span></div>{invites.length === 0 ? <p className="p-8 text-center text-sm text-muted-foreground">No active invites.</p> : invites.map((invite) => { const peer = didPeers.find((item) => item.did === invite.targetDid); return <div key={invite.id} className="flex items-center gap-3 border-b border-border p-4 last:border-0"><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{peer?.node_name || invite.circleName || "Guardian invite"}</p><p className="truncate font-mono text-xs text-muted-foreground">{invite.targetDid || invite.id}</p><p className="mt-1 text-xs text-muted-foreground">{roleLabel(invite.role)} · {invite.expiresAt ? `Expires ${new Date(invite.expiresAt).toLocaleString()}` : "No expiry"} · {stateLabel(invite)}</p></div><button className={secondaryButton} onClick={() => void sendDirectInvite(invite)} aria-label="Send direct invite"><Send size={14} /></button><button className={secondaryButton} onClick={() => void copyInvite(invite)} aria-label="Copy invite"><Copy size={14} /></button><button className={secondaryButton} onClick={() => setConfirm({ kind: "invite", id: invite.id })} aria-label="Revoke invite"><X size={15} className="text-destructive" /></button></div>; })}</section>
            <button className={secondaryButton} onClick={() => navigate("/network/join")}><Clipboard size={15} />Open invite preview and join</button>
          </div>}
        </div>
      </main>
      {confirm && <ConfirmDialog title={confirm.kind === "archive" ? "Archive this Circle?" : confirm.kind === "unarchive" ? "Unarchive this Circle?" : confirm.kind === "delete" ? "Permanently delete this Circle?" : confirm.kind === "member" ? "Remove this member?" : "Revoke this invite?"} message={confirm.kind === "archive" ? "The Circle will be removed from Active Circles and moved to Archived Circles with its audit history preserved." : confirm.kind === "unarchive" ? "The Circle will be restored to Active Circles and become fully usable again." : confirm.kind === "delete" ? "This deletes the Circle and revokes every membership credential issued for it. This action cannot be undone." : confirm.kind === "member" ? "The member will immediately lose Circle access and appear under Revoked Members." : "Anyone holding this invite will no longer be able to use it."} confirmLabel={confirm.kind === "archive" ? "Archive Circle" : confirm.kind === "unarchive" ? "Unarchive Circle" : confirm.kind === "delete" ? "Delete Circle" : confirm.kind === "member" ? "Remove" : "Revoke"} tone={confirm.kind === "unarchive" ? "primary" : "destructive"} onConfirm={() => void runConfirmedAction()} onClose={() => setConfirm(null)} busy={busy} />}
    </div>
  );
}
