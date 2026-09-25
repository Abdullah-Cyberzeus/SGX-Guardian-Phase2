// SU02 — Create Mesh Circle (P2.5, spec §32).
//
// Reached from SU01's "Create Mesh Circle" button. The backend does the
// actual work (CA key → own cert → PA key → policy → MeshProfile) inside one
// synchronous POST — there is no live step-by-step feed for those, so this
// screen does not fabricate granular progress for them; it shows one honest
// "creating" state for the request, then a second, real "restarting" state
// backed by MeshLifecycleContext's own poll/WS, since mesh::ca's module doc
// explains the daemon must restart before ONLINE is real (no live-activation
// path from a running API handler — see the plan's P2.4 note).
import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { useMeshLifecycle } from "../../contexts/MeshLifecycleContext";
import meshService, { type CreateCircleResult } from "../../services/meshService";

type Step = "form" | "creating" | "restarting" | "success" | "error";

// First 16 of the NATO phonetic alphabet — a public-domain, internationally
// standard, easy-to-read-aloud word for each hex nibble. Matches the plan's
// §4.5 "fingerprint as a short phrase plus hex" — the phrase is what two
// operators actually read to each other to compare CAs out of band; the full
// hex underneath is what they'd copy/paste if they wanted exactness instead.
const NIBBLE_WORDS = [
  "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel",
  "India", "Juliet", "Kilo", "Lima", "Mike", "November", "Oscar", "Papa",
];

function fingerprintPhrase(fingerprint: string): string {
  const hex = fingerprint.replace(/^sha256:/i, "").replace(/[^0-9a-fA-F]/g, "");
  const prefix = hex.slice(0, 8).toLowerCase();
  return prefix
    .split("")
    .map((nibble) => NIBBLE_WORDS[parseInt(nibble, 16)] ?? "?")
    .join(" ");
}

export function SU02CreateCircle() {
  const navigate = useNavigate();
  const { lifecycle } = useMeshLifecycle();
  const [step, setStep] = useState<Step>("form");
  const [name, setName] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [overlayCidr, setOverlayCidr] = useState("");
  const [certValidityDays, setCertValidityDays] = useState(365);
  const [attestation, setAttestation] = useState<"required" | "preferred" | "off">("preferred");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CreateCircleResult | null>(null);

  // Once the POST returns, the daemon is about to restart — watch the
  // lifecycle context (already polling/reconnecting through the brief
  // restart window, per its own P1.7 design) for CIRCLE_MEMBER/ONLINE.
  useEffect(() => {
    if (step !== "restarting") return;
    if (lifecycle?.state === "ONLINE" || lifecycle?.state === "CIRCLE_MEMBER") {
      setStep("success");
    }
  }, [step, lifecycle?.state]);

  const submit = async () => {
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Give this circle a name.");
      return;
    }
    setError(null);
    setStep("creating");
    try {
      const created = await meshService.createCircle({
        name: trimmed,
        overlayCidr: overlayCidr.trim() || undefined,
        policy: {
          attestation,
          cert_validity_days: certValidityDays,
        },
      });
      setResult(created);
      setStep(created.restarting ? "restarting" : "success");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create the circle.");
      setStep("error");
    }
  };

  return (
    <div
      className="flex flex-col items-center"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)", padding: "24px 16px" }}
    >
      <div className="flex flex-col items-center gap-2" style={{ marginBottom: "24px" }}>
        <CervaisLogo width={96} />
        <h1
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-lg)",
            fontWeight: 700,
            color: "var(--foreground)",
          }}
        >
          Create Mesh Circle
        </h1>
      </div>

      <Card style={{ width: "100%", maxWidth: 440 }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)" }}>
            {step === "form" && "Name your circle"}
            {step === "creating" && "Creating your circle…"}
            {step === "restarting" && "Restarting to activate the mesh…"}
            {step === "success" && "Circle created"}
            {step === "error" && "Could not create the circle"}
          </CardTitle>
          {step === "form" && (
            <CardDescription style={{ fontSize: "var(--text-xs)" }}>
              This Guardian becomes the CA — the trust anchor every member's certificate is
              signed against.
            </CardDescription>
          )}
        </CardHeader>
        <CardContent>
          {step === "form" && (
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label
                  htmlFor="circle-name"
                  style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}
                >
                  Circle name
                </label>
                <Input
                  id="circle-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. SGX-Alpha"
                  maxLength={64}
                />
              </div>

              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                style={{
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                  textAlign: "left",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: 0,
                }}
              >
                {showAdvanced ? "▾" : "▸"} Advanced options
              </button>

              {showAdvanced && (
                <div className="flex flex-col gap-4" style={{ paddingLeft: "4px" }}>
                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor="overlay-cidr"
                      style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}
                    >
                      Overlay subnet (optional — /24 only in this release)
                    </label>
                    <Input
                      id="overlay-cidr"
                      value={overlayCidr}
                      onChange={(e) => setOverlayCidr(e.target.value)}
                      placeholder="192.168.100.0/24"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label
                      htmlFor="cert-validity"
                      style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}
                    >
                      Member certificate validity (days)
                    </label>
                    <Input
                      id="cert-validity"
                      type="number"
                      min={1}
                      value={certValidityDays}
                      onChange={(e) => setCertValidityDays(Number(e.target.value) || 365)}
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      Attestation for new members
                    </label>
                    <div className="flex gap-2">
                      {(["required", "preferred", "off"] as const).map((mode) => (
                        <Button
                          key={mode}
                          type="button"
                          size="sm"
                          variant={attestation === mode ? "default" : "outline"}
                          onClick={() => setAttestation(mode)}
                        >
                          {mode}
                        </Button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {error && (
                <p style={{ fontSize: "var(--text-xs)", color: "var(--destructive, #dc2626)" }}>
                  {error}
                </p>
              )}

              <Button size="lg" onClick={() => void submit()}>
                Create Circle
              </Button>
            </div>
          )}

          {(step === "creating" || step === "restarting") && (
            <div className="flex flex-col items-center gap-3" style={{ padding: "20px 0" }}>
              <div
                className="rounded-full animate-spin"
                style={{
                  width: 28,
                  height: 28,
                  border: "3px solid var(--muted)",
                  borderTopColor: "var(--primary)",
                }}
              />
              <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                {step === "creating"
                  ? "Generating the CA key, your own certificate, and the circle policy…"
                  : "The Guardian restarts briefly to bring the mesh online. This page will update automatically."}
              </p>
            </div>
          )}

          {step === "success" && result && (
            <div className="flex flex-col gap-4">
              <div>
                <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  CA fingerprint
                </p>
                <p
                  style={{
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-medium)",
                    color: "var(--foreground)",
                  }}
                >
                  {fingerprintPhrase(result.caFingerprint)}
                </p>
                <p
                  style={{
                    fontFamily: "monospace",
                    fontSize: "var(--text-xs)",
                    color: "var(--muted-foreground)",
                    wordBreak: "break-all",
                    marginTop: "4px",
                  }}
                >
                  {result.caFingerprint}
                </p>
              </div>
              <div className="rounded-md" style={{ backgroundColor: "var(--muted)", padding: "10px 12px" }}>
                <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  {result.circleName} · {result.overlayIp}
                </p>
              </div>
              <Button
                size="lg"
                onClick={() =>
                  window.alert(
                    "Inviting a Guardian lands with a later update — join codes are Phase 4 work.",
                  )
                }
              >
                Invite a Guardian
              </Button>
              <Button variant="outline" onClick={() => navigate("/home", { replace: true })}>
                Go to Dashboard
              </Button>
            </div>
          )}

          {step === "error" && (
            <div className="flex flex-col gap-3">
              <p style={{ fontSize: "var(--text-sm)", color: "var(--destructive, #dc2626)" }}>
                {error}
              </p>
              <Button variant="outline" onClick={() => setStep("form")}>
                Try again
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
