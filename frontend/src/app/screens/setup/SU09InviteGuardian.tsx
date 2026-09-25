// SU09 — Invite Guardian / join codes (P4.8, spec §32). Reached from SU02's
// "Invite a Guardian" button (post-circle-creation) and linkable from
// settings for a CA to invite later. Creates a join code, shows it as text
// (the plaintext code only ever exists for this one moment — see
// `mesh::joincode`'s module doc) plus a QR-encodable payload, and lists/
// revokes existing codes.
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
import { joinCodeService, type CreatedJoinCode, type JoinCode } from "../../services/enrollService";

function timeRemaining(expiresAt: string): string {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return "expired";
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins}m left`;
  return `${Math.round(mins / 60)}h left`;
}

export function SU09InviteGuardian() {
  const navigate = useNavigate();
  const [ttlMinutes, setTtlMinutes] = useState(60);
  const [note, setNote] = useState("");
  const [autoApprove, setAutoApprove] = useState(false);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<CreatedJoinCode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [codes, setCodes] = useState<JoinCode[]>([]);

  const refreshList = () => {
    void joinCodeService.list().then(setCodes).catch(() => {});
  };

  useEffect(refreshList, []);

  const create = async () => {
    setCreating(true);
    setError(null);
    try {
      const result = await joinCodeService.create(ttlMinutes, note.trim() || undefined, autoApprove);
      setCreated(result);
      refreshList();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create a join code.");
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (id: string) => {
    try {
      await joinCodeService.revoke(id);
      refreshList();
    } catch {
      // Listing will just still show it — the operator can retry.
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
          Invite a Guardian
        </h1>
      </div>

      {created ? (
        <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
          <CardHeader>
            <CardTitle style={{ fontSize: "var(--text-sm)" }}>Join code</CardTitle>
            <CardDescription style={{ fontSize: "var(--text-xs)" }}>
              Shown once — share it with the Guardian joining, then it's gone from this screen.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p
              style={{
                fontFamily: "monospace",
                fontSize: "var(--text-2xl, 28px)",
                fontWeight: 700,
                letterSpacing: "0.15em",
                textAlign: "center",
                color: "var(--foreground)",
                padding: "16px 0",
              }}
            >
              {created.code}
            </p>
            <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)", textAlign: "center" }}>
              Expires {new Date(created.expiresAt).toLocaleString()}
            </p>
            <Button variant="outline" style={{ marginTop: "16px", width: "100%" }} onClick={() => setCreated(null)}>
              Create another
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
          <CardHeader>
            <CardTitle style={{ fontSize: "var(--text-sm)" }}>New join code</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <label style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  Valid for (minutes)
                </label>
                <Input
                  type="number"
                  min={1}
                  value={ttlMinutes}
                  onChange={(e) => setTtlMinutes(Number(e.target.value) || 60)}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  Note (optional)
                </label>
                <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Warehouse Guardian #3" />
              </div>
              <label className="flex items-center gap-2" style={{ fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                <input type="checkbox" checked={autoApprove} onChange={(e) => setAutoApprove(e.target.checked)} />
                Auto-approve as a member (skip manual approval)
              </label>
              {error && (
                <p style={{ fontSize: "var(--text-xs)", color: "var(--destructive, #dc2626)" }}>{error}</p>
              )}
              <Button size="lg" disabled={creating} onClick={() => void create()}>
                {creating ? "…" : "Create join code"}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {codes.length > 0 && (
        <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
          <CardHeader>
            <CardTitle style={{ fontSize: "var(--text-sm)" }}>Active codes</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col gap-2">
              {codes.map((code) => (
                <div
                  key={code.id}
                  className="flex items-center justify-between gap-2 px-3 py-2"
                  style={{ borderRadius: "var(--radius)", border: "1px solid var(--border)" }}
                >
                  <div className="min-w-0">
                    <p style={{ fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                      {code.note || "(no note)"}
                    </p>
                    <p style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      {code.usedAt ? `Used by ${code.usedByGuardianId ?? "?"}` : timeRemaining(code.expiresAt)}
                    </p>
                  </div>
                  {!code.usedAt && (
                    <Button variant="outline" size="sm" onClick={() => void revoke(code.id)}>
                      Revoke
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Button variant="outline" onClick={() => navigate(-1)}>
        Back
      </Button>
    </div>
  );
}
