import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { AlertTriangle, CheckCircle2, Clock3, Link2, Loader2, UsersRound } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { useAuth } from "../../contexts/AuthContext";
import { parseInviteMaterial } from "../../services/circleService";
import pwaOnboardingService, {
  type AdditionalCircleJoinResult,
  type MemberInvitePreview,
} from "../../services/pwaOnboardingService";

const PENDING_KEY = "sgx_pending_additional_circle";

function restorePending(): AdditionalCircleJoinResult | null {
  try {
    const raw = sessionStorage.getItem(PENDING_KEY);
    return raw ? JSON.parse(raw) as AdditionalCircleJoinResult : null;
  } catch {
    sessionStorage.removeItem(PENDING_KEY);
    return null;
  }
}

export function JoinCircleScreen() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { session, refreshSession } = useAuth();
  const queryInvite = searchParams.get("member_invite") || searchParams.get("invite") || searchParams.get("token") || "";
  const [inviteMaterial, setInviteMaterial] = useState(queryInvite);
  const [preview, setPreview] = useState<MemberInvitePreview | null>(null);
  const [pending, setPending] = useState<AdditionalCircleJoinResult | null>(() => restorePending());
  const [approvalState, setApprovalState] = useState<string>(() => pending?.enrollment.state || "pending");
  const [busy, setBusy] = useState<"preview" | "join" | null>(null);
  const parsed = useMemo(() => parseInviteMaterial(inviteMaterial), [inviteMaterial]);

  useEffect(() => {
    if (!pending || approvalState !== "pending") return;
    let stopped = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const status = await pwaOnboardingService.approvalStatus(
          pending.enrollment.approvalId,
          pending.approvalClaim,
        );
        if (stopped) return;
        setApprovalState(status.state);
        if (status.state === "approved") {
          const refreshed = await refreshSession();
          if (refreshed.error) {
            toast.error("Circle approved, but session refresh failed", { description: refreshed.error });
          } else {
            sessionStorage.removeItem(PENDING_KEY);
            toast.success(`Joined ${status.circleName}`);
            navigate("/chats?tab=groups", { replace: true });
          }
          return;
        }
        if (status.state === "rejected" || status.state === "expired") return;
      } catch {
        // The Guardian may briefly be unreachable; keep the approval pending.
      }
      if (!stopped) timer = window.setTimeout(() => void poll(), 3_000);
    };
    void poll();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [approvalState, navigate, pending, refreshSession]);

  const previewInvite = async () => {
    if (!parsed.token) return;
    setBusy("preview");
    setPreview(null);
    try {
      const result = await pwaOnboardingService.previewInvite(parsed.token, parsed.ownerHost || undefined);
      if (session?.circleIds.includes(result.circleId)) {
        throw new Error("You are already a member of this Circle");
      }
      setPreview(result);
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Invitation could not be verified");
    } finally {
      setBusy(null);
    }
  };

  const requestJoin = async () => {
    if (!preview || !parsed.token) return;
    setBusy("join");
    try {
      const result = await pwaOnboardingService.joinAdditionalCircle(parsed.token);
      sessionStorage.setItem(PENDING_KEY, JSON.stringify(result));
      setPending(result);
      setApprovalState(result.enrollment.state);
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Circle membership could not be requested");
    } finally {
      setBusy(null);
    }
  };

  const reset = () => {
    sessionStorage.removeItem(PENDING_KEY);
    setPending(null);
    setApprovalState("pending");
    setPreview(null);
    setInviteMaterial("");
  };

  if (pending) {
    const rejected = approvalState === "rejected" || approvalState === "expired";
    return <div className="flex h-full flex-col">
      <PageHeader title="Join Circle" onBack={() => navigate("/chats?tab=groups")} />
      <main className="grid flex-1 place-items-center overflow-y-auto p-5">
        <section className={`w-full max-w-md rounded-xl border bg-card p-6 text-center ${rejected ? "border-destructive/40" : "border-primary/30"}`}>
          {rejected ? <AlertTriangle size={46} className="mx-auto text-destructive" /> : approvalState === "approved" ? <CheckCircle2 size={46} className="mx-auto text-primary" /> : <Clock3 size={46} className="mx-auto text-primary" />}
          <h1 className="mt-4 text-xl font-semibold">{approvalState === "rejected" ? "Request declined" : approvalState === "expired" ? "Invitation expired" : approvalState === "approved" ? "Membership approved" : "Waiting for administrator approval"}</h1>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            {rejected ? "Ask the Circle administrator for a new invitation." : approvalState === "approved" ? "Refreshing your Circle access…" : `Your request to join ${pending.enrollment.circleName} is pending. Keep this page open or return later.`}
          </p>
          {rejected && <button onClick={reset} className="mt-5 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground">Try another invite</button>}
        </section>
      </main>
    </div>;
  }

  return <div className="flex h-full flex-col">
    <PageHeader title="Join Circle" subtitle="Add another secure group" onBack={() => navigate("/chats?tab=groups")} />
    <main className="flex-1 overflow-y-auto p-4 md:p-6">
      <div className="mx-auto max-w-xl space-y-4">
        <section className="rounded-xl border border-border bg-card p-5">
          <div className="flex items-start gap-3"><Link2 size={20} className="mt-0.5 text-primary" /><div><h2 className="font-semibold">Paste your member invitation</h2><p className="mt-1 text-sm leading-6 text-muted-foreground">Use the one-time link created by that Circle's administrator. Your existing account and chats will be preserved.</p></div></div>
          <textarea
            value={inviteMaterial}
            onChange={(event) => { setInviteMaterial(event.target.value); setPreview(null); }}
            placeholder="Paste the Circle member invite link"
            rows={4}
            className="mt-4 w-full resize-none rounded-lg border border-border bg-input-background p-3 font-mono text-xs outline-none focus:border-primary"
          />
          <button disabled={!parsed.token || busy !== null} onClick={() => void previewInvite()} className="mt-3 flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50">
            {busy === "preview" && <Loader2 size={17} className="animate-spin" />} Verify invitation
          </button>
        </section>
        {preview && <section className="rounded-xl border border-primary/30 bg-card p-5">
          <div className="flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-full bg-primary/15 text-primary"><UsersRound size={21} /></div><div><h2 className="font-semibold">{preview.circleName}</h2><p className="text-xs text-muted-foreground">Administrator approval required</p></div></div>
          <p className="mt-4 text-sm leading-6 text-muted-foreground">After approval, this Circle will appear under Chats → Groups with its own isolated conversation history.</p>
          <button disabled={busy !== null} onClick={() => void requestJoin()} className="mt-4 flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground disabled:opacity-50">
            {busy === "join" && <Loader2 size={17} className="animate-spin" />} Request to join
          </button>
        </section>}
      </div>
    </main>
  </div>;
}
