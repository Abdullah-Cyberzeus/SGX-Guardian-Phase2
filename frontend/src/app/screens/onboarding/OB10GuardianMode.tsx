import { useNavigate } from "react-router";
import { ArrowRight, ShieldCheck, UsersRound } from "lucide-react";
import { ProgressDots } from "../../components/ProgressDots";

const GUARDIAN_MODE_KEY = "sgx_guardian_mode";

type GuardianMode = "standard" | "circle_capable";

const modes: Array<{
  value: GuardianMode;
  title: string;
  description: string;
  points: string[];
  icon: typeof ShieldCheck;
}> = [
  {
    value: "standard",
    title: "Standard Guardian",
    description: "Use this Guardian with the current setup flow.",
    points: ["Local dashboard and security tools", "Circle joining when invited", "Existing onboarding behavior"],
    icon: ShieldCheck,
  },
  {
    value: "circle_capable",
    title: "Circle-capable Guardian",
    description: "Prepare this Guardian for Circle creation later.",
    points: ["Create Circles in a future workflow", "Invite members after authority setup", "Same setup behavior for now"],
    icon: UsersRound,
  },
];

export function OB10GuardianMode() {
  const navigate = useNavigate();

  const selectMode = (mode: GuardianMode) => {
    localStorage.setItem(GUARDIAN_MODE_KEY, mode);
    navigate("/onboarding/pairing", { replace: true });
  };

  return (
    <div
      className="flex min-h-[100dvh] flex-col"
      style={{ backgroundColor: "var(--background)" }}
    >
      <div className="flex flex-col items-center px-6 pt-12 pb-6">
        <ProgressDots total={3} current={2} />
        <h2
          className="mt-6 text-center"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xl)",
            fontWeight: "var(--font-weight-semibold)",
            color: "var(--foreground)",
          }}
        >
          Choose Guardian mode
        </h2>
        <p
          className="mt-2 text-center"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
            maxWidth: "320px",
            lineHeight: 1.5,
          }}
        >
          This selection is saved locally for the upcoming Circle workflow.
        </p>
      </div>

      <div className="flex flex-1 flex-col gap-3 px-5 pb-10">
        {modes.map((mode) => {
          const Icon = mode.icon;
          return (
            <button
              key={mode.value}
              type="button"
              onClick={() => selectMode(mode.value)}
              className="group w-full rounded-lg border p-4 text-left transition-colors"
              style={{
                backgroundColor: "var(--card)",
                borderColor: "var(--border)",
              }}
            >
              <span className="flex items-start gap-3">
                <span
                  className="flex shrink-0 items-center justify-center rounded-md"
                  style={{
                    width: "42px",
                    height: "42px",
                    backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)",
                    color: "var(--primary)",
                  }}
                >
                  <Icon size={20} />
                </span>
                <span className="min-w-0 flex-1">
                  <span
                    className="block"
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-base)",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--foreground)",
                    }}
                  >
                    {mode.title}
                  </span>
                  <span
                    className="mt-1 block"
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      color: "var(--muted-foreground)",
                      lineHeight: 1.5,
                    }}
                  >
                    {mode.description}
                  </span>
                </span>
                <ArrowRight
                  className="mt-2 shrink-0 opacity-70 transition-transform group-hover:translate-x-0.5"
                  size={17}
                  style={{ color: "var(--muted-foreground)" }}
                />
              </span>
              <span className="mt-4 grid gap-2 pl-[54px]">
                {mode.points.map((point) => (
                  <span
                    key={point}
                    className="block"
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                      lineHeight: 1.45,
                    }}
                  >
                    {point}
                  </span>
                ))}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
