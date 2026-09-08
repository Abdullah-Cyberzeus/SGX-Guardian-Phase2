import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { Check, Loader2, X } from "lucide-react";
import { toast } from "sonner";
import { useCircleInviteInbox, useCircles } from "../../hooks/useApiData";
import circleService, { type CircleInvite } from "../../services/circleService";
import pwaOnboardingService from "../../services/pwaOnboardingService";
import { useAuth } from "../../contexts/AuthContext";
import type { MemberEnrollment } from "../../services/circleService";

function isPendingInvite(invite: CircleInvite) {
  return String(invite.state || invite.status || "").toLowerCase() === "pending";
}

export function IncomingCircleInviteDialog() {
  const navigate = useNavigate();
  const { refreshSession } = useAuth();
  const { data: invites, refetch: refetchInvites } = useCircleInviteInbox();
  const { refetch: refetchCircles } = useCircles();
  const [targetedInvites, setTargetedInvites] = useState<MemberEnrollment[]>([]);
  const [processing, setProcessing] = useState<string | null>(null);
  const pending = useMemo(
    () => (Array.isArray(invites) ? invites : []).filter(isPendingInvite),
    [invites],
  );
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
  const targetedInvite = targetedInvites[0];
  const invite = pending[0];
  if (!targetedInvite && !invite) return null;

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
