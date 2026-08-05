import { Moon, Sun } from "lucide-react";
import { useTheme } from "../contexts/ThemeContext";

/**
 * Appearance section for the Settings screen — a single row that flips the
 * app between light and dark mode. Matches the settings-card visual style.
 */
export function ThemeToggle() {
  const { isDark, toggleTheme } = useTheme();

  return (
    <div>
      <p
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-semibold)",
          color: "var(--muted-foreground)",
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          marginBottom: "8px",
          paddingLeft: "4px",
        }}
      >
        Appearance
      </p>
      <div
        className="rounded-lg border border-border overflow-hidden"
        style={{ backgroundColor: "var(--card)" }}
      >
        <button
          onClick={toggleTheme}
          role="switch"
          aria-checked={isDark}
          aria-label="Toggle dark mode"
          className="w-full flex items-center gap-3 px-4 py-4 text-left transition-colors"
          style={{ background: "transparent", border: "none", cursor: "pointer" }}
        >
          {isDark ? (
            <Moon size={18} style={{ color: "var(--primary)", flexShrink: 0 }} />
          ) : (
            <Sun size={18} style={{ color: "var(--primary)", flexShrink: 0 }} />
          )}
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              color: "var(--foreground)",
              flex: 1,
            }}
          >
            {isDark ? "Dark Mode" : "Light Mode"}
          </span>

          {/* Track */}
          <span
            style={{
              width: "44px",
              height: "26px",
              borderRadius: "13px",
              backgroundColor: isDark ? "var(--primary)" : "var(--muted)",
              border: "1px solid var(--border)",
              display: "flex",
              alignItems: "center",
              padding: "2px",
              flexShrink: 0,
              transition: "background-color var(--duration-base, 200ms) ease",
            }}
          >
            {/* Thumb */}
            <span
              style={{
                width: "20px",
                height: "20px",
                borderRadius: "50%",
                backgroundColor: isDark ? "var(--primary-foreground)" : "var(--card)",
                boxShadow: "0 1px 2px rgba(0,0,0,0.3)",
                transform: isDark ? "translateX(18px)" : "translateX(0)",
                transition: "transform var(--duration-base, 200ms) ease",
              }}
            />
          </span>
        </button>
      </div>
    </div>
  );
}
