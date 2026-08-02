import { useRef, useState, type ChangeEvent } from "react";
import { Plus, ImageIcon, FileText, Camera, X } from "lucide-react";

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
 * "+" button in the chat composer. Opens a bottom sheet of attachment
 * sources — built with plain elements (the app's own sheet pattern) so it
 * does not depend on Radix `asChild` + the non-ref-forwarding shadcn Button.
 */
export function AttachmentMenu({ onPick, disabled }: AttachmentMenuProps) {
  const [open, setOpen] = useState(false);
  const galleryRef = useRef<HTMLInputElement>(null);
  const documentRef = useRef<HTMLInputElement>(null);
  const cameraRef = useRef<HTMLInputElement>(null);

  const refFor = (id: string) =>
    id === "gallery" ? galleryRef : id === "camera" ? cameraRef : documentRef;

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) onPick(file);
    e.target.value = ""; // allow re-picking the same file
    setOpen(false);
  };

  return (
    <>
      <button
        type="button"
        aria-label="Add attachment"
        disabled={disabled}
        onClick={() => setOpen(true)}
        className="flex flex-shrink-0 items-center justify-center rounded-full transition-opacity active:opacity-70"
        style={{
          width: "44px",
          height: "44px",
          backgroundColor: "var(--secondary)",
          border: "1px solid var(--border)",
          cursor: "pointer",
        }}
      >
        <Plus size={20} style={{ color: "var(--foreground)" }} />
      </button>

      {open && (
        <div
          className="fixed inset-0 z-[90] flex items-end md:items-center justify-center"
          style={{ backgroundColor: "rgba(0,0,0,0.6)" }}
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full rounded-t-xl md:rounded-xl border-t md:border border-border"
            style={{
              backgroundColor: "var(--card)",
              maxWidth: "440px",
              paddingBottom: "max(20px, env(safe-area-inset-bottom))",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 pb-1 pt-4">
              <h3
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-base)",
                  fontWeight: "var(--font-weight-semibold)",
                  color: "var(--foreground)",
                }}
              >
                Share to chat
              </h3>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close"
                style={{ background: "none", border: "none", cursor: "pointer" }}
              >
                <X size={20} style={{ color: "var(--muted-foreground)" }} />
              </button>
            </div>
            <div className="flex gap-3 px-5 pb-2 pt-3">
              {OPTIONS.map(({ id, label, icon: Icon, color }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => refFor(id).current?.click()}
                  className="flex flex-1 flex-col items-center gap-2 transition-opacity active:opacity-70"
                  style={{ background: "none", border: "none", cursor: "pointer" }}
                >
                  <div
                    className="flex items-center justify-center rounded-full"
                    style={{
                      width: "60px",
                      height: "60px",
                      backgroundColor: `color-mix(in srgb, ${color} 20%, transparent)`,
                      border: `1px solid color-mix(in srgb, ${color} 35%, transparent)`,
                    }}
                  >
                    <Icon size={24} style={{ color }} />
                  </div>
                  <span
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--foreground)",
                    }}
                  >
                    {label}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

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
    </>
  );
}
