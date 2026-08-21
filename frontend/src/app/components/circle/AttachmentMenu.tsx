import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { Plus, ImageIcon, FileText, Camera } from "lucide-react";

interface AttachmentMenuProps {
  /** Called with the picked File — caller turns it into a chat attachment. */
  onPick: (file: File) => void;
  disabled?: boolean;
}

const OPTIONS = [
  { id: "gallery", label: "Photos", icon: ImageIcon, color: "var(--chart-1)" },
  { id: "camera", label: "Camera", icon: Camera, color: "var(--chart-3)" },
  { id: "document", label: "Document", icon: FileText, color: "var(--chart-2)" },
] as const;

/**
 * "+" button in the chat composer. Opens a small vertical popup directly
 * above the button — WhatsApp-style — listing attachment sources. Built with
 * plain elements (the app's own popup pattern) so it does not depend on
 * Radix `asChild` + the non-ref-forwarding shadcn Button.
 */
export function AttachmentMenu({ onPick, disabled }: AttachmentMenuProps) {
  const [open, setOpen] = useState(false);
  const galleryRef = useRef<HTMLInputElement>(null);
  const documentRef = useRef<HTMLInputElement>(null);
  const cameraRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const refFor = (id: string) =>
    id === "gallery" ? galleryRef : id === "camera" ? cameraRef : documentRef;

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) onPick(file);
    e.target.value = ""; // allow re-picking the same file
    setOpen(false);
  };

  useEffect(() => {
    if (!open) return;
    const handleOutside = (e: MouseEvent) => {
      if (!containerRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", handleOutside);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleOutside);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  return (
    <div ref={containerRef} className="relative flex-shrink-0">
      <button
        type="button"
        aria-label="Add attachment"
        aria-expanded={open}
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        className="flex flex-shrink-0 items-center justify-center rounded-full transition-transform active:scale-90"
        style={{
          width: "44px",
          height: "44px",
          backgroundColor: "var(--secondary)",
          border: "1px solid var(--border)",
          cursor: "pointer",
          transform: open ? "rotate(45deg)" : "rotate(0deg)",
          transition: "transform 0.15s ease",
        }}
      >
        <Plus size={20} style={{ color: "var(--foreground)" }} />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute z-[90] flex flex-col overflow-hidden rounded-xl border border-border"
          style={{
            bottom: "calc(100% + 10px)",
            left: 0,
            width: "190px",
            backgroundColor: "var(--card)",
            boxShadow: "0 8px 24px rgba(0,0,0,0.25), 0 2px 6px rgba(0,0,0,0.15)",
            transformOrigin: "bottom left",
            animation: "attachment-menu-in 0.14s ease-out",
          }}
        >
          {OPTIONS.map(({ id, label, icon: Icon, color }) => (
            <button
              key={id}
              type="button"
              role="menuitem"
              onClick={() => refFor(id).current?.click()}
              className="flex items-center gap-3 px-4 py-3 transition-colors active:bg-[var(--secondary)]"
              style={{ background: "none", border: "none", cursor: "pointer", textAlign: "left" }}
            >
              <div
                className="flex flex-shrink-0 items-center justify-center rounded-full"
                style={{
                  width: "38px",
                  height: "38px",
                  backgroundColor: color,
                }}
              >
                <Icon size={18} style={{ color: "var(--primary-foreground)" }} />
              </div>
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: "var(--font-weight-medium)",
                  color: "var(--foreground)",
                }}
              >
                {label}
              </span>
            </button>
          ))}
        </div>
      )}

      <style>{`
        @keyframes attachment-menu-in {
          from { opacity: 0; transform: scale(0.9) translateY(6px); }
          to { opacity: 1; transform: scale(1) translateY(0); }
        }
      `}</style>

      {/* Hidden inputs — one per source so each gets the right accept/capture. */}
      <input ref={galleryRef} type="file" accept="image/*,video/*" hidden onChange={handleChange} />
      <input ref={documentRef} type="file" hidden onChange={handleChange} />
      <input
        ref={cameraRef}
        type="file"
        accept="image/*"
        capture="environment"
        hidden
        onChange={handleChange}
      />
    </div>
  );
}
