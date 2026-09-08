import { useState } from "react";
import { useNavigate } from "react-router";
import { Eye, EyeOff, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "../../contexts/AuthContext";

const passwordValid = (value: string) => value.length >= 12
  && /[A-Z]/.test(value)
  && /[a-z]/.test(value)
  && /[0-9]/.test(value)
  && /[^a-zA-Z0-9]/.test(value);

export function MemberJoinOnboarding() {
  const navigate = useNavigate();
  const { signUpMember } = useAuth();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);

  const canSubmit = name.trim().length >= 2
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
    && passwordValid(password)
    && !busy;

  const signUp = async () => {
    if (!canSubmit) return;
    setBusy(true);
    const result = await signUpMember({
      name: name.trim(),
      email: email.trim(),
      password,
    });
    setBusy(false);
    if (result.error) {
      toast.error(result.error);
      return;
    }
    navigate("/join-circle", { replace: true });
  };

  return (
    <main className="min-h-[100dvh] bg-background p-4 md:p-8">
      <div className="mx-auto max-w-md space-y-5 pt-10">
        <header className="text-center">
          <ShieldCheck size={42} className="mx-auto text-primary" />
          <h1 className="mt-3 text-2xl font-semibold">Member signup</h1>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            Create your member account. An administrator can add you to a Circle after signup.
          </p>
        </header>

        <section className="rounded-xl border border-border bg-card p-5">
          <h2 className="font-semibold">Create member login</h2>
          <div className="mt-4 grid gap-3">
            <input
              className="h-12 rounded-md border border-border bg-input-background px-4 outline-none"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Full name"
            />
            <input
              type="email"
              className="h-12 rounded-md border border-border bg-input-background px-4 outline-none"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="Email address"
            />
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                className="h-12 w-full rounded-md border border-border bg-input-background px-4 pr-12 outline-none"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                onKeyDown={(event) => { if (event.key === "Enter") void signUp(); }}
                placeholder="12+ chars, upper/lower, number, symbol"
              />
              <button
                type="button"
                className="absolute right-3 top-1/2 z-10 flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-md hover:bg-muted/50"
                style={{ color: "var(--muted-foreground)" }}
                aria-label={showPassword ? "Hide password" : "Show password"}
                onClick={() => setShowPassword((value) => !value)}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>
          <button
            className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-3 font-semibold text-primary-foreground disabled:opacity-40"
            disabled={!canSubmit}
            onClick={() => void signUp()}
          >
            {busy && <Loader2 size={17} className="animate-spin" />}
            Sign up
          </button>
        </section>
      </div>
    </main>
  );
}
