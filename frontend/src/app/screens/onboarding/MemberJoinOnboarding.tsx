import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { AlertTriangle, CheckCircle2, Fingerprint, Loader2, ShieldCheck, WifiOff } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "../../contexts/AuthContext";
import { parseInviteMaterial } from "../../services/circleService";
import pwaOnboardingService, { type GuardianOnboardingInfo, type MemberInvitePreview } from "../../services/pwaOnboardingService";

const normalizeFingerprint = (value: string) => value.replace(/[^a-z0-9]/gi, "").toUpperCase();
const passwordValid = (value: string) => value.length >= 12
  && /[A-Z]/.test(value)
  && /[a-z]/.test(value)
  && /[0-9]/.test(value)
  && /[^a-zA-Z0-9]/.test(value);

export function MemberJoinOnboarding() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { joinMember } = useAuth();
  const [info, setInfo] = useState<GuardianOnboardingInfo | null>(null);
  const [loadError, setLoadError] = useState("");
  const [typedFingerprint, setTypedFingerprint] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [inviteMaterial, setInviteMaterial] = useState(() => searchParams.get("invite") || searchParams.get("token") || "");
  const [preview, setPreview] = useState<MemberInvitePreview | null>(null);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<"preview" | "join" | null>(null);
  const [joined, setJoined] = useState(false);

  useEffect(() => {
    void pwaOnboardingService.info()
      .then(setInfo)
      .catch((cause) => setLoadError(cause instanceof Error ? cause.message : "Guardian could not be reached"));
  }, []);

  const fingerprintMatches = useMemo(
    () => Boolean(info && normalizeFingerprint(typedFingerprint) === normalizeFingerprint(info.fingerprint)),
    [info, typedFingerprint],
  );
  const parsedInvite = useMemo(() => parseInviteMaterial(inviteMaterial), [inviteMaterial]);
  const inviteToken = parsedInvite.token;
  const canPreview = fingerprintMatches && confirmed && Boolean(inviteToken) && busy === null;
  const canJoin = Boolean(preview)
    && name.trim().length >= 2
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
    && passwordValid(password)
    && busy === null;

  const verifyInvite = async () => {
    if (!canPreview) return;
    setBusy("preview");
    setPreview(null);
    try {
      // Always call the Guardian currently open in the browser. ownerHost is
      // routing metadata for server-to-server redemption, never a browser
      // redirect target.
      const result = await pwaOnboardingService.previewInvite(inviteToken, parsedInvite.ownerHost || undefined);
      setPreview(result);
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Invitation could not be verified");
    } finally {
      setBusy(null);
    }
  };

  const join = async () => {
    if (!canJoin || !info) return;
    setBusy("join");
    const result = await joinMember({
      name: name.trim(),
      email: email.trim(),
      password,
      inviteToken,
      ownerHost: parsedInvite.ownerHost || undefined,
      acceptedFingerprint: typedFingerprint,
      fingerprintConfirmed: confirmed,
    });
    setBusy(null);
    if (result.error) {
      toast.error(result.error);
      return;
    }
    setJoined(true);
  };

  if (loadError) {
    return <main className="grid min-h-[100dvh] place-items-center bg-background p-6"><section className="max-w-md rounded-xl border border-destructive/40 bg-card p-6 text-center"><WifiOff className="mx-auto text-destructive" /><h1 className="mt-3 text-xl font-semibold">Guardian unavailable</h1><p className="mt-2 text-sm text-muted-foreground">{loadError}</p><button className="mt-5 rounded-md border border-border px-4 py-2 text-sm" onClick={() => location.reload()}>Try again</button></section></main>;
  }

  if (!info) {
    return <main className="grid min-h-[100dvh] place-items-center bg-background"><Loader2 className="animate-spin text-primary" /></main>;
  }

  if (joined) {
    return <main className="grid min-h-[100dvh] place-items-center bg-background p-6"><section className="w-full max-w-md rounded-xl border border-primary/30 bg-card p-6 text-center"><CheckCircle2 size={48} className="mx-auto text-primary" /><h1 className="mt-4 text-2xl font-semibold">Member access created</h1><p className="mt-2 text-sm text-muted-foreground">This browser is registered with {info.guardianName} for {preview?.circleName}.</p><button className="mt-6 w-full rounded-md bg-primary px-4 py-3 font-semibold text-primary-foreground" onClick={() => navigate("/chats", { replace: true })}>Open member dashboard</button><p className="mt-4 text-xs text-muted-foreground">You may now use your browser’s Add to Home Screen option.</p></section></main>;
  }

  return <main className="min-h-[100dvh] bg-background p-4 md:p-8">
    <div className="mx-auto max-w-2xl space-y-5">
      <header className="pt-4 text-center"><ShieldCheck size={42} className="mx-auto text-primary" /><h1 className="mt-3 text-2xl font-semibold">Join this Guardian</h1><p className="mt-2 text-sm text-muted-foreground">Local onboarding—no Internet or browser DID is required.</p></header>

      <section className="rounded-xl border border-border bg-card p-5">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Guardian</p>
        <h2 className="mt-1 text-lg font-semibold">{info.guardianName}</h2>
        <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{info.guardianDid}</p>
        <div className="mt-4 rounded-lg border border-primary/30 bg-primary/5 p-4">
          <div className="flex items-center gap-2"><Fingerprint size={18} className="text-primary" /><p className="font-semibold">Browser-reported fingerprint</p></div>
          <p className="mt-3 text-center font-mono text-xl font-bold tracking-widest">{info.fingerprint}</p>
          <p className="mt-3 text-xs leading-5 text-muted-foreground">Compare this with the code printed on, or independently displayed by, your physical Guardian. If they differ, stop immediately.</p>
        </div>
        <label className="mt-4 block text-sm font-medium">Enter the fingerprint from the physical Guardian</label>
        <input className={`mt-2 h-12 w-full rounded-md border bg-input-background px-4 font-mono uppercase tracking-wider outline-none ${typedFingerprint && !fingerprintMatches ? "border-destructive" : "border-border"}`} value={typedFingerprint} onChange={(event) => { setTypedFingerprint(event.target.value); setConfirmed(false); setPreview(null); }} placeholder="XXXX-XXXX-XXXX-XXXX" autoCapitalize="characters" />
        {typedFingerprint && !fingerprintMatches && <div className="mt-2 flex items-start gap-2 text-sm text-destructive" role="alert"><AlertTriangle size={16} className="mt-0.5 shrink-0" />Fingerprint mismatch. Do not join this Guardian.</div>}
        <label className={`mt-4 flex items-start gap-3 rounded-lg border p-3 ${fingerprintMatches ? "cursor-pointer border-border" : "cursor-not-allowed border-border opacity-50"}`}><input type="checkbox" className="mt-1" disabled={!fingerprintMatches} checked={confirmed} onChange={(event) => { setConfirmed(event.target.checked); setPreview(null); }} /><span className="text-sm leading-6">I compared both codes and verify that this is my intended Guardian.</span></label>
      </section>

      <section className="rounded-xl border border-border bg-card p-5">
        <h2 className="font-semibold">Circle invitation</h2><p className="mt-1 text-sm text-muted-foreground">Paste the member invitation supplied by the Guardian administrator. You will remain on {window.location.host}; the issuing Guardian address is used only by this Guardian to redeem the invitation.</p>
        <textarea className="mt-3 min-h-28 w-full rounded-md border border-border bg-input-background p-3 font-mono text-xs outline-none" value={inviteMaterial} onChange={(event) => { setInviteMaterial(event.target.value); setPreview(null); }} placeholder="Invitation token or sgx-guardian:// link" />
        <button className="mt-3 inline-flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-40" disabled={!canPreview} onClick={() => void verifyInvite()}>{busy === "preview" && <Loader2 size={16} className="animate-spin" />}Verify invitation</button>
        {preview && <div className="mt-4 rounded-lg border border-primary/30 bg-primary/5 p-4"><div className="flex items-center gap-2 font-semibold text-primary"><CheckCircle2 size={17} />Invitation verified</div><dl className="mt-3 grid grid-cols-[90px_1fr] gap-2 text-sm"><dt className="text-muted-foreground">Circle</dt><dd>{preview.circleName}</dd><dt className="text-muted-foreground">Role</dt><dd className="capitalize">{preview.role}</dd><dt className="text-muted-foreground">Expires</dt><dd>{new Date(preview.expiresAt).toLocaleString()}</dd></dl></div>}
      </section>

      {preview && <section className="rounded-xl border border-border bg-card p-5"><h2 className="font-semibold">Create member login</h2><div className="mt-4 grid gap-3"><input className="h-12 rounded-md border border-border bg-input-background px-4 outline-none" value={name} onChange={(event) => setName(event.target.value)} placeholder="Full name" /><input type="email" className="h-12 rounded-md border border-border bg-input-background px-4 outline-none" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Email address" /><input type="password" className="h-12 rounded-md border border-border bg-input-background px-4 outline-none" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="12+ chars, upper/lower, number, symbol" /></div><button className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-3 font-semibold text-primary-foreground disabled:opacity-40" disabled={!canJoin} onClick={() => void join()}>{busy === "join" && <Loader2 size={17} className="animate-spin" />}Create member access</button></section>}
    </div>
  </main>;
}
