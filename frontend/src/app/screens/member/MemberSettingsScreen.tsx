import { LogOut, RefreshCw, ShieldCheck, Trash2, UserRound, UsersRound } from "lucide-react";
import { useNavigate } from "react-router";
import { PageHeader } from "../../components/PageHeader";
import { useAuth } from "../../contexts/AuthContext";
import { toast } from "sonner";
import { PwaStorageControls } from "../../components/PwaStorageControls";

export function MemberSettingsScreen() {
  const navigate = useNavigate();
  const { session, signOut, signOutEverywhere, refreshSession, removeBrowserRegistration } = useAuth();
  const user = session?.user;
  const offline = session?.offline === true;

  const logout = async () => {
    await signOut();
    navigate("/login", { replace: true });
  };

  const logoutEverywhere = async () => {
    const { error } = await signOutEverywhere();
    if (error) {
      toast.error("Sessions could not be revoked", { description: error });
      return;
    }
    navigate("/login", { replace: true });
  };

  const refresh = async () => {
    const { error } = await refreshSession();
    error ? toast.error("Session could not be refreshed", { description: error }) : toast.success("Session refreshed");
  };

  const removeBrowser = async () => {
    if (!window.confirm("Remove this browser registration? You will need a new invitation to rejoin.")) return;
    const { error } = await removeBrowserRegistration();
    if (error) {
      toast.error("Browser could not be removed", { description: error });
      return;
    }
    navigate("/join", { replace: true });
  };

  return <div className="flex h-full flex-col">
    <PageHeader title="Settings" subtitle="Your local Guardian session" />
    <main className="flex-1 overflow-y-auto p-4 md:p-6">
      <div className="mx-auto max-w-2xl space-y-4">
        <section className="rounded-xl border border-border bg-card p-5">
          <div className="flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-full bg-primary/15 text-primary"><UserRound size={20} /></div><div><h2 className="font-semibold">{user?.name || user?.email || "Guardian member"}</h2><p className="text-xs text-muted-foreground">{user?.email}</p></div></div>
          <dl className="mt-5 grid grid-cols-[110px_1fr] gap-2 text-sm"><dt className="text-muted-foreground">Role</dt><dd className="capitalize">{user?.role || "member"}</dd><dt className="text-muted-foreground">Circle access</dt><dd>{session?.circleIds.length || 0} Circle</dd><dt className="text-muted-foreground">Registration</dt><dd className="truncate font-mono text-xs">{session?.browserRegistrationId || "Not registered"}</dd><dt className="text-muted-foreground">Fingerprint</dt><dd className="font-mono text-xs">{session?.guardianFingerprint || "Unavailable"}</dd></dl>
        </section>
        <PwaStorageControls />
        {offline && <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-700 dark:text-amber-300">Guardian is unreachable. Cached settings remain available; session and registration changes require a live LAN connection.</p>}
        <section className="rounded-xl border border-border bg-card p-5">
          <div className="flex items-start gap-3"><ShieldCheck size={20} className="mt-0.5 text-primary" /><div><h2 className="font-semibold">Member access</h2><p className="mt-1 text-sm leading-6 text-muted-foreground">This session can use messages, calls, contacts, files, notifications, and personal settings. Guardian administration remains restricted to an administrator.</p></div></div>
        </section>
        <div className="grid gap-2 sm:grid-cols-2">
          <button disabled={offline} onClick={() => void refresh()} className="flex w-full items-center justify-center gap-2 rounded-md border border-border px-4 py-3 text-sm font-semibold hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"><RefreshCw size={17} />Refresh session</button>
          <button onClick={() => void logout()} className="flex w-full items-center justify-center gap-2 rounded-md border border-border px-4 py-3 text-sm font-semibold hover:bg-muted"><LogOut size={17} />Sign out</button>
          <button disabled={offline} onClick={() => void logoutEverywhere()} className="flex w-full items-center justify-center gap-2 rounded-md border border-destructive/40 px-4 py-3 text-sm font-semibold text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"><UsersRound size={17} />Sign out everywhere</button>
          <button disabled={offline} onClick={() => void removeBrowser()} className="flex w-full items-center justify-center gap-2 rounded-md border border-destructive/40 px-4 py-3 text-sm font-semibold text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"><Trash2 size={17} />Remove this browser</button>
        </div>
      </div>
    </main>
  </div>;
}
