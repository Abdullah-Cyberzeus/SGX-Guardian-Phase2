import { PageHeader } from "../../components/PageHeader";
import { CervaisLogo } from "../../components/CervaisLogo";

export function ST15AppVersion() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="App Version" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5 pb-8">
        {/* Version card */}
        <div
          className="flex flex-col items-center py-6 rounded-lg border border-border"
          style={{ backgroundColor: "var(--card)" }}
        >
          <CervaisLogo width={120} />
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-base)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
              marginTop: "12px",
              marginBottom: "2px",
            }}
          >
            SG-X Guardian
          </p>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            Version {__APP_VERSION__}
          </p>
        </div>

        {/* Legal */}
        <div className="text-center">
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              lineHeight: 1.5,
            }}
          >
            © 2026 Cervais Inc. All rights reserved.
            <br />
            Patents pending. SG-X is a trademark of Cervais Inc.
          </p>
        </div>
        </div>
      </div>
    </div>
  );
}
