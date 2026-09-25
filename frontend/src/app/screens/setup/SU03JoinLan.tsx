// SU03 — Join Circle, LAN search (P3.6, spec §32 "Join Circle").
//
// Reached from SU01's "Join Existing Circle" button. Scans the LAN for
// `CaBeacon` advertisers (`mesh::discovery`), fetches + verifies each one's
// `CaDescriptor`, and lists the results — verified entries selectable,
// unverified ones greyed out and not. Actually *joining* the selected
// circle (the enrollment request/approval round trip) is Phase 4 work
// (P4.6/P4.7) and has no backend yet, so "Join Selected Circle" is a
// placeholder here, the same way SU02's "Invite a Guardian" is a
// placeholder for P4.8 — both screens are honest about what exists today.
import { useCallback, useEffect, useRef, useState } from "react";
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
import meshDiscoveryService, { type DiscoveredCa } from "../../services/meshDiscoveryService";

type ScanPhase = "idle" | "scanning" | "done" | "error";

const POLL_INTERVAL_MS = 700;
// P3.3's own number plus slack for the poll cadence above and the parallel
// fetch+verify round trip after the window closes — a scan genuinely
// finishing in ~5s should still read as "scanning" for most of that, not
// flash past it.
const MAX_POLL_MS = 15_000;

function entryKey(entry: DiscoveredCa): string {
  return `${entry.circleId}:${entry.fingerprint}`;
}

export function SU03JoinLan() {
  const navigate = useNavigate();
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [results, setResults] = useState<DiscoveredCa[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [probeHost, setProbeHost] = useState("");
  const [probePort, setProbePort] = useState("50071");
  const [probeBusy, setProbeBusy] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);

  const pollStopRef = useRef(false);

  const mergeResult = useCallback((entry: DiscoveredCa) => {
    setResults((prev) => {
      const key = entryKey(entry);
      if (prev.some((existing) => entryKey(existing) === key)) return prev;
      return [...prev, entry];
    });
  }, []);

  const runScan = useCallback(async () => {
    pollStopRef.current = false;
    setError(null);
    setResults([]);
    setSelected(null);
    setPhase("scanning");
    try {
      const scanId = await meshDiscoveryService.startLanScan();
      const startedAt = Date.now();
      while (!pollStopRef.current) {
        const status = await meshDiscoveryService.getLanScan(scanId);
        if (status.status === "done") {
          setResults(status.results);
          setPhase("done");
          return;
        }
        if (Date.now() - startedAt > MAX_POLL_MS) {
          setError("The scan is taking longer than expected — try again, or enter a Guardian's address manually below.");
          setPhase("error");
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not scan the LAN for circles.");
      setPhase("error");
    }
  }, []);

  useEffect(() => {
    void runScan();
    return () => {
      pollStopRef.current = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submitProbe = async () => {
    const host = probeHost.trim();
    const port = Number(probePort);
    if (!host || !Number.isFinite(port) || port <= 0) {
      setProbeError("Enter a valid host and port.");
      return;
    }
    setProbeError(null);
    setProbeBusy(true);
    try {
      const entry = await meshDiscoveryService.probe(host, port);
      if (!entry) {
        setProbeError(`No circle answered at ${host}:${port}.`);
        return;
      }
      mergeResult(entry);
      setSelected(entryKey(entry));
    } finally {
      setProbeBusy(false);
    }
  };

  const selectedEntry = results.find((entry) => entryKey(entry) === selected) ?? null;

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
          Join a Circle
        </h1>
      </div>

      <Card style={{ width: "100%", maxWidth: 440, marginBottom: "16px" }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)" }}>
            {phase === "scanning" && "Scanning the local network…"}
            {phase === "done" && results.length > 0 && "Circles found on this network"}
            {phase === "done" && results.length === 0 && "No circles found"}
            {phase === "error" && "Could not finish the scan"}
            {phase === "idle" && "Local network search"}
          </CardTitle>
          <CardDescription style={{ fontSize: "var(--text-xs)" }}>
            Only entries with a valid, verified signature from the circle's own CA can be joined.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {phase === "scanning" && (
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
                Listening for circles on this network…
              </p>
            </div>
          )}

          {phase === "error" && (
            <div className="flex flex-col gap-3">
              <p style={{ fontSize: "var(--text-sm)", color: "var(--destructive, #dc2626)" }}>
                {error}
              </p>
              <Button variant="outline" onClick={() => void runScan()}>
                Try again
              </Button>
            </div>
          )}

          {phase === "done" && results.length === 0 && (
            <div className="flex flex-col gap-3" style={{ padding: "8px 0" }}>
              <p style={{ fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                Nothing answered on this network. Make sure the other Guardian is powered on and
                already created its circle, or enter its address manually below.
              </p>
              <Button variant="outline" onClick={() => void runScan()}>
                Scan again
              </Button>
            </div>
          )}

          {phase === "done" && results.length > 0 && (
            <div className="flex flex-col gap-2">
              {results.map((entry) => {
                const key = entryKey(entry);
                const isSelected = selected === key;
                return (
                  <button
                    key={key}
                    type="button"
                    disabled={!entry.verified}
                    onClick={() => setSelected(key)}
                    className="w-full flex flex-col items-start gap-1 px-4 py-3 text-left transition-opacity"
                    style={{
                      borderRadius: "var(--radius)",
                      border: isSelected
                        ? "1.5px solid var(--primary)"
                        : "1.5px solid var(--border)",
                      backgroundColor: entry.verified ? "var(--card)" : "var(--muted)",
                      opacity: entry.verified ? 1 : 0.55,
                      cursor: entry.verified ? "pointer" : "not-allowed",
                    }}
                  >
                    <div className="w-full flex items-center justify-between">
                      <span
                        style={{
                          fontSize: "var(--text-sm)",
                          fontWeight: "var(--font-weight-medium)",
                          color: "var(--foreground)",
                        }}
                      >
                        {entry.circleName}
                      </span>
                      <span
                        style={{
                          fontSize: "var(--text-xs)",
                          fontWeight: "var(--font-weight-medium)",
                          color: entry.verified ? "var(--success, #16a34a)" : "var(--muted-foreground)",
                        }}
                      >
                        {entry.verified ? "Verified" : "Unverified"}
                      </span>
                    </div>
                    <span
                      style={{
                        fontFamily: "monospace",
                        fontSize: "var(--text-xs)",
                        color: "var(--muted-foreground)",
                      }}
                    >
                      {entry.fingerprintWords}
                    </span>
                    <span style={{ fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                      CA: {entry.caGuardianId} · {entry.lanEndpoint}
                    </span>
                  </button>
                );
              })}
              <Button variant="outline" size="sm" onClick={() => void runScan()} style={{ marginTop: "4px" }}>
                Scan again
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card style={{ width: "100%", maxWidth: 440, marginBottom: "20px" }}>
        <CardHeader>
          <CardTitle style={{ fontSize: "var(--text-sm)" }}>Enter a Guardian's address</CardTitle>
          <CardDescription style={{ fontSize: "var(--text-xs)" }}>
            For a network that blocks automatic discovery.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Input
              value={probeHost}
              onChange={(e) => setProbeHost(e.target.value)}
              placeholder="192.168.1.20"
              className="flex-1"
            />
            <Input
              value={probePort}
              onChange={(e) => setProbePort(e.target.value)}
              placeholder="50071"
              style={{ width: "90px" }}
            />
            <Button onClick={() => void submitProbe()} disabled={probeBusy}>
              {probeBusy ? "…" : "Find"}
            </Button>
          </div>
          {probeError && (
            <p style={{ fontSize: "var(--text-xs)", color: "var(--destructive, #dc2626)", marginTop: "8px" }}>
              {probeError}
            </p>
          )}
        </CardContent>
      </Card>

      <div className="flex flex-col gap-3" style={{ width: "100%", maxWidth: 440 }}>
        <Button
          size="lg"
          disabled={!selectedEntry}
          onClick={() =>
            window.alert(
              "Joining a circle lands with a later update — this Guardian can verify a circle exists but cannot yet request to join it.",
            )
          }
        >
          {selectedEntry ? `Join ${selectedEntry.circleName}` : "Select a verified circle"}
        </Button>
        <Button variant="outline" onClick={() => navigate("/setup")}>
          Back
        </Button>
      </div>
    </div>
  );
}
