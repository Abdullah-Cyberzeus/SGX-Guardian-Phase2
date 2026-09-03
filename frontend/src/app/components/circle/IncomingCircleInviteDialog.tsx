import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { Check, Loader2, X } from "lucide-react";
import { toast } from "sonner";
import { useCircleInviteInbox, useCircles } from "../../hooks/useApiData";
import circleService, { type CircleInvite } from "../../services/circleService";
import pwaOnboardingService from "../../services/pwaOnboardingService";
import { useAuth } from "../../contexts/AuthContext";
import type { MemberEnrollment } from "../../services/circleService";

const DISMISSED_TARGETED_INVITES_KEY = "sgx_dismissed_targeted_circle_invites";

function isPendingInvite(invite: CircleInvite) {
  return String(invite.state || invite.status || "").toLowerCase() === "pending";
}

function targetedInviteExpired(invite: MemberEnrollment) {
  return invite.state === "expired" || (invite.expiresAt ? new Date(invite.expiresAt).getTime() <= Date.now() : false);
}

function loadDismissedTargetedInvites(userId?: string) {
  if (!userId) return new Set<string>();
  try {
    const parsed = JSON.parse(localStorage.getItem(DISMISSED_TARGETED_INVITES_KEY) || "{}");
    return new Set<string>(Array.isArray(parsed[userId]) ? parsed[userId] : []);
  } catch {
    localStorage.removeItem(DISMISSED_TARGETED_INVITES_KEY);
    return new Set<string>();
  }
}

function saveDismissedTargetedInvites(userId: string | undefined, values: Set<string>) {
  if (!userId) return;
  let parsed: Record<string, string[]> = {};
  try {
    parsed = JSON.parse(localStorage.getItem(DISMISSED_TARGETED_INVITES_KEY) || "{}");
  } catch {
    parsed = {};
  }
  parsed[userId] = [...values];
  localStorage.setItem(DISMISSED_TARGETED_INVITES_KEY, JSON.stringify(parsed));
}

export function IncomingCircleInviteDialog() {
  const navigate = useNavigate();
  const { session, refreshSession } = useAuth();
  const { data: invites, refetch: refetchInvites } = useCircleInviteInbox();
  const { refetch: refetchCircles } = useCircles();
  const [targetedInvites, setTargetedInvites] = useState<MemberEnrollment[]>([]);
  const [dismissedTargetedInvites, setDismissedTargetedInvites] = useState<Set<string>>(
    () => loadDismissedTargetedInvites(session?.user.id),
  );
  const [processing, setProcessing] = useState<string | null>(null);
  const hasCircleAccess = (session?.circleIds.length || 0) > 0;
  const pending = useMemo(
    () => (Array.isArray(invites) ? invites : []).filter(isPendingInvite),
    [invites],
  );
  useEffect(() => {
    setDismissedTargetedInvites(loadDismissedTargetedInvites(session?.user.id));
  }, [session?.user.id]);
  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result = await pwaOnboardingService.targetedInvites();
        if (!stopped) setTargetedInvites(Array.isArray(result.invites) ? result.invites : []);
      } catch {
        if (!stopped) setTargetedInvites([]);
      }
      if (!stopped) timer = window.setTimeout(() => void poll(), 5_000);
    };
    void poll();
    return () => {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    };
  }, []);
  const visibleTargetedInvites = hasCircleAccess
    ? targetedInvites.filter((item) => !targetedInviteExpired(item) && !dismissedTargetedInvites.has(item.approvalId))
    : targetedInvites;
  const targetedInvite = visibleTargetedInvites[0];
  const invite = pending[0];
  if (!targetedInvite && !invite) return null;

  const dismissTargetedInvite = () => {
    if (!targetedInvite?.approvalId) return;
    setDismissedTargetedInvites((prev) => {
      const next = new Set(prev);
      next.add(targetedInvite.approvalId);
      saveDismissedTargetedInvites(session?.user.id, next);
      return next;
    });
  };

  const decide = async (decision: "accept" | "reject") => {
    if (targetedInvite) {
      if (processing || !targetedInvite.approvalId) return;
      setProcessing(decision);
      try {
        await pwaOnboardingService.decideTargetedInvite(targetedInvite.approvalId, decision === "accept");
        if (decision === "accept") {
          const refreshed = await refreshSession();
          if (refreshed.error) toast.error("Invite accepted, but session refresh failed", { description: refreshed.error });
          else {
            toast.success("Circle invitation accepted");
            navigate("/chats?tab=groups", { replace: true });
          }
        } else {
          toast.success("Circle invitation rejected");
        }
        setDismissedTargetedInvites((prev) => {
          const next = new Set(prev);
          next.delete(targetedInvite.approvalId);
          saveDismissedTargetedInvites(session?.user.id, next);
          return next;
        });
        const result = await pwaOnboardingService.targetedInvites();
        setTargetedInvites(Array.isArray(result.invites) ? result.invites : []);
        await refetchCircles();
      } catch (cause) {
        toast.error(decision === "accept" ? "Accept failed" : "Reject failed", {
          description: cause instanceof Error ? cause.message : "Try again.",
        });
      } finally {
        setProcessing(null);
      }
      return;
    }
    if (processing || !invite?.id) return;
    setProcessing(decision);
    try {
      if (decision === "accept") {
        await circleService.acceptInvite(invite.id);
        toast.success("Circle invitation accepted");
      } else {
        await circleService.rejectInvite(invite.id);
        toast.success("Circle invitation rejected");
      }
      await Promise.all([refetchInvites(), refetchCircles()]);
    } catch (cause) {
      toast.error(decision === "accept" ? "Accept failed" : "Reject failed", {
        description: cause instanceof Error ? cause.message : "Try again.",
      });
    } finally {
      setProcessing(null);
    }
  };

  if (hasCircleAccess) {
    return (
      <aside className="incoming-call-toast" role="alertdialog" aria-labelledby="incoming-circle-invite-title">
        <div className="incoming-call-icon"><Check size={18} /></div>
        <div className="min-w-0">
          <strong id="incoming-circle-invite-title">Circle invitation</strong>
          <span>{targetedInvite?.circleName || invite?.circleName || "New Circle"}</span>
          <small>{targetedInvite ? "Pending invitation" : "Trusted Circle invitation"}</small>
        </div>
        <button
          className="incoming-decline-icon"
          disabled={!!processing}
          onClick={targetedInvite ? dismissTargetedInvite : () => void decide("reject")}
          aria-label={targetedInvite ? "Move invitation to pending" : "Decline Circle invitation"}
        >
          <X size={17} />
        </button>
        <div className="incoming-call-actions">
          {targetedInvite && (
            <button disabled={!!processing} onClick={() => navigate("/join-circle?tab=pending")}>
              Pending
            </button>
          )}
          <button disabled={!!processing} onClick={() => void decide("reject")}>
            {processing === "reject" ? "..." : "Decline"}
          </button>
          <button disabled={!!processing} onClick={() => void decide("accept")}>
            {processing === "accept" ? "..." : "Accept"}
          </button>
        </div>
      </aside>
    );
  }

  return (
    <div className="fixed inset-0 z-[110] grid place-items-center bg-black/65 p-4" role="dialog" aria-modal="true">
      <section className="w-full max-w-md rounded-xl border border-border bg-card p-5 shadow-2xl">
        <h2 className="text-lg font-semibold">Circle invitation</h2>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">
          You were invited to join {targetedInvite?.circleName || invite?.circleName || "a Circle"} as member.
        </p>
        <p className="mt-3 break-all font-mono text-[10px] text-muted-foreground">
          Invite ID: {targetedInvite?.approvalId || invite?.id || "Unknown"}
        </p>
        {(targetedInvites.length + pending.length) > 1 && <p className="mt-3 text-xs text-muted-foreground">{targetedInvites.length + pending.length - 1} more invite{targetedInvites.length + pending.length === 2 ? "" : "s"} waiting.</p>}
        <div className="mt-5 flex gap-2">
          <button
            className="inline-flex h-11 flex-1 items-center justify-center gap-2 rounded-md border border-border bg-secondary text-sm font-semibold text-secondary-foreground disabled:opacity-50"
            disabled={!!processing}
            onClick={() => void decide("reject")}
          >
            {processing === "reject" ? <Loader2 size={15} className="animate-spin" /> : <X size={15} />}Decline
          </button>
          <button
            className="inline-flex h-11 flex-1 items-center justify-center gap-2 rounded-md bg-primary text-sm font-semibold text-primary-foreground disabled:opacity-50"
            disabled={!!processing}
            onClick={() => void decide("accept")}
          >
            {processing === "accept" ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />}Approve
          </button>
        </div>
      </section>
    </div>
  );
}
