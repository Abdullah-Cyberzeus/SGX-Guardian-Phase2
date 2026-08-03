import {
  useNavigate,
  useLocation,
  useRouteError,
  isRouteErrorResponse,
} from "react-router";
import { Home } from "lucide-react";
import { Button } from "../../components/ui/button";
import { Card } from "../../components/ui/card";

/** Monospace stack — the "security console" voice for the glitch screen. */
const MONO = "ui-monospace, 'SF Mono', 'SFMono-Regular', Menlo, monospace";

/**
 * SYS01 — 404 Not Found.
 *
 * Rendered both as the catch-all `path: "*"` route and as the router
 * `ErrorBoundary`, so it also covers thrown error responses. Built with
 * shadcn primitives + theme CSS variables; the glitch keyframes live in
 * `src/styles/index.css` (`.nf-glitch`). Mobile-first.
 */
export function SYS01NotFound() {
  const navigate = useNavigate();
  const location = useLocation();
  const error = useRouteError();

  // As an ErrorBoundary, surface the real status if one was thrown.
  const status = isRouteErrorResponse(error) ? error.status : 404;

  return (
    <div
      className="relative flex flex-col items-center justify-center overflow-hidden px-6 text-center"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      {/* Ambient glow behind the digits */}
      <div
        aria-hidden
        className="pointer-events-none absolute rounded-full"
        style={{
          width: "min(440px, 92vw)",
          height: "min(440px, 92vw)",
          background:
            "radial-gradient(circle, color-mix(in srgb, var(--primary) 24%, transparent), transparent 70%)",
        }}
      />

      <div className="relative flex flex-col items-center">
        {/* Glitch digits */}
        <span
          className="nf-glitch"
          data-text={String(status)}
          style={{ fontFamily: MONO, fontSize: "clamp(6rem, 34vw, 11rem)" }}
        >
          {status}
        </span>

        <h1
          className="mt-4 mb-2"
          style={{
            fontFamily: MONO,
            fontSize: "var(--text-base)",
            fontWeight: "var(--font-weight-semibold)",
            letterSpacing: "0.22em",
            color: "var(--foreground)",
          }}
        >
          ROUTE NOT FOUND
        </h1>

        <p
          className="mb-7"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
            maxWidth: "300px",
            lineHeight: 1.6,
          }}
        >
          This page doesn't exist or may have been moved. Check the address and
          try again.
        </p>

        {/* Action card */}
        <Card className="w-full gap-3 p-3" style={{ maxWidth: "340px" }}>
          <Button className="w-full" onClick={() => navigate("/home")}>
            <Home />
            Home
          </Button>

          {/* The path that failed to resolve — terminal-style caption */}
          <div
            className="flex items-center gap-1.5 rounded-md px-2.5 py-2"
            style={{ backgroundColor: "var(--muted)" }}
          >
            <span
              className="shrink-0"
              style={{
                fontFamily: MONO,
                fontSize: "var(--text-xs)",
                color: "var(--muted-foreground)",
              }}
            >
              guardian://
            </span>
            <span
              className="min-w-0 truncate"
              style={{
                fontFamily: MONO,
                fontSize: "var(--text-xs)",
                color: "var(--foreground)",
              }}
            >
              {location.pathname}
            </span>
          </div>
        </Card>
      </div>
    </div>
  );
}
