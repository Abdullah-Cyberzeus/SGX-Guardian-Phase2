import { Component, ReactNode, ErrorInfo } from "react";
import { ShieldAlert, RefreshCw } from "lucide-react";
import { monitoring } from "../services/monitoring";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary] Caught error:", error, info);
    monitoring.capture('react_error', error.message, {
      stack: error.stack,
    });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.href = "/home";
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div
          className="flex flex-col items-center justify-center flex-1 px-6 py-20 gap-5 text-center"
          style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
        >
          <div
            className="rounded-full flex items-center justify-center"
            style={{
              width: "72px",
              height: "72px",
              backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
              border: "1.5px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
            }}
          >
            <ShieldAlert size={32} style={{ color: "var(--destructive)" }} />
          </div>

          <div>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-base)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--foreground)",
                marginBottom: "6px",
              }}
            >
              Something went wrong
            </p>
            <p
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                color: "var(--muted-foreground)",
                lineHeight: 1.6,
                maxWidth: "280px",
              }}
            >
              An unexpected error occurred. Your Guardian is still monitoring your network.
            </p>
          </div>

          {this.state.error && (
            <div
              className="w-full rounded-lg border border-border p-3"
              style={{ backgroundColor: "var(--card)" }}
            >
              <p
                style={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: "10px",
                  color: "var(--muted-foreground)",
                  wordBreak: "break-all",
                  lineHeight: 1.6,
                  textAlign: "left",
                }}
              >
                {this.state.error.message}
              </p>
            </div>
          )}

          <button
            onClick={this.handleReset}
            className="flex items-center justify-center gap-2 transition-opacity active:opacity-80"
            style={{
              height: "48px",
              paddingLeft: "24px",
              paddingRight: "24px",
              backgroundColor: "var(--primary)",
              color: "var(--primary-foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              borderRadius: "var(--radius)",
              border: "none",
              cursor: "pointer",
            }}
          >
            <RefreshCw size={15} />
            Return to Dashboard
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
