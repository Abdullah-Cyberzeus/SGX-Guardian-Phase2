import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { Check, Clock, Copy, Hash, Loader2, Shield } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { deviceService, type PairingCodeResponse } from "../../services/deviceService";

type Step = "serial" | "code" | "proof";

function CountdownTimer({ expiresAt }: { expiresAt: number }) {
  const [remaining, setRemaining] = useState(() => Math.max(0, expiresAt - Math.floor(Date.now() / 1000)));

  useEffect(() => {
    const interval = setInterval(() => {
      setRemaining((value) => Math.max(0, value - 1));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  const expired = remaining === 0;
  const urgent = remaining < 60;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
      <Clock size={12} style={{ color: expired ? "var(--destructive)" : urgent ? "var(--chart-5)" : "var(--muted-foreground)" }} />
      <span
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-semibold)",
          color: expired ? "var(--destructive)" : urgent ? "var(--chart-5)" : "var(--muted-foreground)",
        }}
      >
        {expired ? "Expired" : `${minutes}:${String(seconds).padStart(2, "0")} remaining`}
      </span>
    </div>
  );
}

export function ST08DevicePairing() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>("serial");
  const [serial, setSerial] = useState("");
  const [proof, setProof] = useState("");
  const [pairingData, setPairingData] = useState<PairingCodeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [codeCopied, setCodeCopied] = useState(false);

  const normalizedSerial = serial.trim().toUpperCase();
  const canRequestCode = normalizedSerial.length >= 6;
  const canPair = proof.trim().length > 0 && !!pairingData;

  const handleGetCode = async () => {
    if (!canRequestCode || loading) return;
    setLoading(true);
    try {
      const data = await deviceService.getPairingCode(normalizedSerial);
      setPairingData(data);
      setProof("");
      setStep("code");
      toast.success("Pairing code generated");
    } catch (error: any) {
      toast.error(error.message || "Failed to generate pairing code");
    } finally {
      setLoading(false);
    }
  };

  const handlePair = async () => {
    if (!canPair || !pairingData || loading) return;
    setLoading(true);
    try {
      await deviceService.pairDevice(pairingData.serial, proof.trim());
      toast.success("Guardian paired successfully");
      navigate("/devices");
    } catch (error: any) {
      toast.error(error.message || "Pairing failed. Check the proof and try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleCopyPairingCode = async () => {
    if (!pairingData?.pairingCode) return;
    try {
      await navigator.clipboard.writeText(pairingData.pairingCode);
      setCodeCopied(true);
      toast.success("Pairing code copied");
      window.setTimeout(() => setCodeCopied(false), 1500);
    } catch {
      toast.error("Copy failed");
    }
  };
  return (
    <div className="flex h-full min-h-0 flex-col bg-background">
      <PageHeader title="Pair New Guardian" />

      <div className="mx-auto flex min-h-0 w-full max-w-2xl flex-1 flex-col gap-5 overflow-y-auto px-5 py-5 md:px-6">
        <div
          className="rounded-lg border p-4 flex items-start gap-3"
          style={{
            backgroundColor: "color-mix(in srgb, var(--primary) 7%, var(--card))",
            borderColor: "color-mix(in srgb, var(--primary) 18%, var(--border))",
          }}
        >
          <Shield size={18} style={{ color: "var(--primary)", flexShrink: 0, marginTop: "1px" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.5 }}>
            Add a Guardian to this account using its serial number and signed pairing proof.
          </p>
        </div>

        <div className="rounded-lg border border-border " style={{ backgroundColor: "var(--card)" }}>
          <div className="flex items-center gap-3 px-4 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
            <div
              className="rounded-md flex items-center justify-center"
              style={{ width: "38px", height: "38px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}
            >
              <Hash size={18} style={{ color: "var(--primary)" }} />
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                Serial Number
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                Required before a pairing code can be minted.
              </p>
            </div>
          </div>

          <div className="p-4 flex flex-col gap-4">
            <div>
              <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
                Device Serial
              </label>
              <input
                autoFocus={step === "serial"}
                value={serial}
                onChange={(event) => setSerial(event.target.value.toUpperCase())}
                placeholder="e.g. GX-2024-TX-042-A9F3"
                className="w-full px-4 outline-none"
                disabled={step !== "serial"}
                style={{
                  height: "48px",
                  backgroundColor: "var(--input-background)",
                  border: "1.5px solid var(--border)",
                  borderRadius: "var(--radius)",
                  color: "var(--foreground)",
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: "var(--text-sm)",
                  opacity: step === "serial" ? 1 : 0.72,
                }}
              />
            </div>

            {step === "serial" && (
              <button
                onClick={handleGetCode}
                disabled={!canRequestCode || loading}
                className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
                style={{
                  height: "48px",
                  backgroundColor: "var(--primary)",
                  color: "var(--primary-foreground)",
                  borderRadius: "var(--radius)",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-semibold)",
                  border: "none",
                  cursor: canRequestCode && !loading ? "pointer" : "default",
                  opacity: canRequestCode && !loading ? 1 : 0.45,
                }}
              >
                {loading ? <Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} /> : "Generate Pairing Code"}
              </button>
            )}
          </div>
        </div>

        {pairingData && (step === "code" || step === "proof") && (
          <div className="rounded-lg border border-border " style={{ backgroundColor: "var(--card)" }}>
            <div className="px-4 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
              <div className="flex items-center justify-between gap-3">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                  PAIRING CODE
                </p>
                <div className="flex items-center gap-2">
                  <CountdownTimer expiresAt={pairingData.expiresAt} />
                  <button
                    type="button"
                    onClick={handleCopyPairingCode}
                    aria-label="Copy pairing code"
                    title={codeCopied ? "Copied" : "Copy pairing code"}
                    className="flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                    style={{
                      width: "34px",
                      height: "34px",
                      backgroundColor: codeCopied ? "color-mix(in srgb, var(--chart-2) 14%, transparent)" : "var(--secondary)",
                      color: codeCopied ? "var(--chart-2)" : "var(--secondary-foreground)",
                      border: "1px solid var(--border)",
                      cursor: "pointer",
                      flexShrink: 0,
                    }}
                  >
                    {codeCopied ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </div>
              </div>
              <p className="mt-3" style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all", lineHeight: 1.8, userSelect: "all" }}>
                {pairingData.pairingCode}
              </p>
            </div>

            <div className="p-4 flex flex-col gap-4">
              {step === "code" && (
                <button
                  onClick={() => setStep("proof")}
                  className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
                  style={{ height: "48px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", border: "none", cursor: "pointer" }}
                >
                  Enter Signed Proof
                </button>
              )}

              {step === "proof" && (
                <>
                  <div>
                    <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
                      Signed Proof
                    </label>
                    <textarea
                      autoFocus
                      value={proof}
                      onChange={(event) => setProof(event.target.value)}
                      placeholder="Paste the proof string from the Guardian device..."
                      rows={5}
                      className="w-full px-4 py-3 outline-none"
                      style={{
                        backgroundColor: "var(--input-background)",
                        border: "1.5px solid var(--border)",
                        borderRadius: "var(--radius)",
                        color: "var(--foreground)",
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: "11px",
                        resize: "none",
                        lineHeight: 1.7,
                        width: "100%",
                        boxSizing: "border-box",
                      }}
                    />
                  </div>
                  <button
                    onClick={handlePair}
                    disabled={!canPair || loading}
                    className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
                    style={{
                      height: "48px",
                      backgroundColor: "var(--primary)",
                      color: "var(--primary-foreground)",
                      borderRadius: "var(--radius)",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-semibold)",
                      border: "none",
                      cursor: canPair && !loading ? "pointer" : "default",
                      opacity: canPair && !loading ? 1 : 0.45,
                    }}
                  >
                    {loading ? <Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} /> : <><Check size={16} /> Complete Pairing</>}
                  </button>
                </>
              )}
            </div>
          </div>
        )}

        {step !== "serial" && (
          <button
            onClick={() => {
              setStep("serial");
              setPairingData(null);
              setProof("");
            }}
            style={{ height: "42px", background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
          >
            Start Over
          </button>
        )}

        <button
          onClick={() => navigate(-1)}
          style={{ height: "42px", background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
        >
          Back
        </button>
      </div>

      <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
    </div>
  );
}
