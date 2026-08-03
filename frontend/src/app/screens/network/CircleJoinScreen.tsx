import { useState } from "react";
import { ArrowLeft, CheckCircle2, Eye, KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import circleService, { JoinPreview, parseInviteMaterial } from "../../services/circleService";

export function CircleJoinScreen() {
  const navigate = useNavigate();
  const [material, setMaterial] = useState("");
  const [ownerHost, setOwnerHost] = useState("");
  const [preview, setPreview] = useState<JoinPreview | null>(null);
  const [redeemRequest, setRedeemRequest] = useState("");
  const [busy, setBusy] = useState<"preview" | "join" | "redeem" | null>(null);
  const inputClass = "w-full rounded-md border border-border bg-input-background px-4 py-3 font-mono text-sm outline-none focus:border-primary";

  const parsed = parseInviteMaterial(material);
  const effectiveOwnerHost = ownerHost.trim() || parsed.ownerHost;

  const previewInvite = async () => {
    if (!parsed.token) return;
    setBusy("preview");
    try {
      const result = await circleService.previewJoin(parsed.token);
      setPreview(result);
      if (!ownerHost && parsed.ownerHost) setOwnerHost(parsed.ownerHost);
    } catch (error) {
      setPreview(null);
      toast.error(error instanceof Error ? error.message : "Invite validation failed");
    } finally { setBusy(null); }
  };

  const join = async () => {
    if (!parsed.token || !effectiveOwnerHost) return;
    setBusy("join");
    try {
      const result = await circleService.join(parsed.token, effectiveOwnerHost);
      toast.success(result.message || "Circle joined");
      navigate("/network", { replace: true });
    } catch (error) { toast.error(error instanceof Error ? error.message : "Join failed"); }
    finally { setBusy(null); }
  };

  const redeem = async () => {
    setBusy("redeem");
    try {
      const request = JSON.parse(redeemRequest);
      const result = await circleService.redeem(request);
      toast.success(result.message || "Signed join request redeemed");
      setRedeemRequest("");
    } catch (error) { toast.error(error instanceof Error ? error.message : "Redeem failed"); }
    finally { setBusy(null); }
  };

  return (
    <div className="flex h-full flex-col bg-background">
      <header className="flex h-16 items-center gap-3 border-b border-border px-4 md:px-6">
        <button className="inline-flex items-center gap-2 rounded-md border border-border bg-secondary px-3 py-2 text-sm" onClick={() => navigate(-1)}><ArrowLeft size={16} />Back</button>
        <div><h1 className="text-lg font-semibold">Join a Circle</h1><p className="text-xs text-muted-foreground">Preview and accept verified invite material</p></div>
      </header>
      <main className="flex-1 overflow-y-auto p-4 md:p-6">
        <div className="mx-auto max-w-xl space-y-5">
          <section className="rounded-xl border border-border bg-card p-5">
            <div className="mb-4 flex items-center gap-2"><ShieldCheck className="text-primary" size={20} /><h2 className="font-semibold">Invite material</h2></div>
            <textarea className={inputClass} rows={5} value={material} onChange={(e) => { setMaterial(e.target.value); setPreview(null); }} placeholder="Paste token or sgx-guardian:// Circle invite link" />
            <label className="mb-1.5 mt-4 block text-xs font-medium text-muted-foreground">Owner Guardian URL</label>
            <input className={inputClass} value={ownerHost || parsed.ownerHost} onChange={(e) => setOwnerHost(e.target.value)} placeholder="Included automatically in a full invite link" />
            <button className="mt-3 inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-50" disabled={!parsed.token || busy !== null} onClick={() => void previewInvite()}>{busy === "preview" ? <Loader2 size={16} className="animate-spin" /> : <Eye size={16} />}Preview invite</button>
          </section>

          {preview && <section className="rounded-xl border border-primary/35 bg-primary/5 p-5"><div className="flex items-center gap-2"><CheckCircle2 size={20} className="text-primary" /><h2 className="font-semibold">Invite verified</h2></div><dl className="mt-4 grid grid-cols-[110px_1fr] gap-2 text-sm"><dt className="text-muted-foreground">Circle</dt><dd>{preview.circle?.name || "Unknown"}</dd><dt className="text-muted-foreground">Role</dt><dd className="capitalize">{preview.role || "member"}</dd><dt className="text-muted-foreground">Issued by</dt><dd className="truncate font-mono text-xs">{preview.inviter || "Not provided"}</dd>{preview.expiresAt && <><dt className="text-muted-foreground">Expires</dt><dd>{new Date(preview.expiresAt).toLocaleString()}</dd></>}</dl><button className="mt-5 inline-flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50" disabled={busy !== null || !effectiveOwnerHost} onClick={() => void join()}>{busy === "join" ? <Loader2 size={16} className="animate-spin" /> : <CheckCircle2 size={16} />}Accept and join</button></section>}

          <details className="rounded-xl border border-border bg-card p-5"><summary className="cursor-pointer text-sm font-semibold">Advanced: owner-side redeem</summary><div className="mt-4"><div className="mb-2 flex items-center gap-2"><KeyRound size={16} className="text-primary" /><p className="text-xs leading-5 text-muted-foreground">The redeem endpoint requires a complete, Guardian-signed JoinRequest—not an invite token. Normally the Join API creates and sends this automatically.</p></div><textarea className={inputClass} rows={8} value={redeemRequest} onChange={(e) => setRedeemRequest(e.target.value)} placeholder='{"inviteToken": {...}, "joinerDid": "did:…", "nonce": "…", "issuedAt": "…", "proof": {...}}' /><button className="mt-3 inline-flex items-center gap-2 rounded-md border border-border bg-secondary px-4 py-2.5 text-sm font-semibold disabled:opacity-50" disabled={!redeemRequest.trim() || busy !== null} onClick={() => void redeem()}>{busy === "redeem" ? <Loader2 size={16} className="animate-spin" /> : <KeyRound size={16} />}Redeem signed request</button></div></details>
        </div>
      </main>
    </div>
  );
}
