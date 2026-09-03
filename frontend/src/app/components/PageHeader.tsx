import { useNavigate } from "react-router";
import { ArrowLeft } from "lucide-react";
import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  titleColor?: string;
  subtitle?: ReactNode;
  subtitleColor?: string;
  showBack?: boolean;
  onBack?: () => void;
  right?: ReactNode;
  /** Render the title at the larger size used by top-level module landings. */
  large?: boolean;
}

export function PageHeader({ title, titleColor, subtitle, subtitleColor, showBack = true, onBack, right, large }: PageHeaderProps) {
  const navigate = useNavigate();

  const handleBack = () => {
    if (onBack) onBack();
    else navigate(-1);
  };

  return (
    <div
      className="flex items-center px-4 md:px-6 border-b border-border h-14 md:h-[72px]"
      style={{ backgroundColor: "var(--background)", flexShrink: 0 }}
    >
      {showBack && (
        <button
          onClick={handleBack}
          className="flex items-center justify-center rounded-md transition-opacity active:opacity-60 mr-2"
          style={{ minWidth: "44px", minHeight: "44px" }}
          aria-label="Go back"
        >
          <ArrowLeft size={20} style={{ color: "var(--foreground)" }} />
        </button>
      )}
      <div className="flex-1 min-w-0">
        <h2
          className="truncate"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: large ? "var(--text-xl)" : "var(--text-base)",
            fontWeight: "var(--font-weight-semibold)",
            color: titleColor || "var(--foreground)",
            lineHeight: 1.3,
          }}
        >
          {title}
        </h2>
        {subtitle && (
          <div
            className="truncate"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: subtitleColor || "var(--muted-foreground)",
              lineHeight: 1.3,
            }}
          >
            {subtitle}
          </div>
        )}
      </div>
      {right && <div className="ml-2">{right}</div>}
    </div>
  );
}
