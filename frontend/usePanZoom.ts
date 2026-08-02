import { useState } from "react";
import { FileText, Download } from "lucide-react";
import { Dialog, DialogContent, DialogTitle } from "../ui/dialog";
import { formatBytes, type AttachmentMeta } from "./types";

interface MessageAttachmentProps {
  attachment: AttachmentMeta;
  /** Whether the message is from the current user (affects color on tinted bubble). */
  isMe: boolean;
}

/** Renders a file/image attachment inside a chat bubble. */
export function MessageAttachment({ attachment, isMe }: MessageAttachmentProps) {
  const [lightbox, setLightbox] = useState(false);

  if (attachment.kind === "image") {
    return (
      <>
        <button
          type="button"
          onClick={() => setLightbox(true)}
          className="block overflow-hidden rounded-xl"
          style={{ cursor: "pointer", background: "none", border: "none", padding: 0 }}
        >
          <img
            src={attachment.url}
            alt={attachment.name}
            style={{
              maxWidth: "240px",
              maxHeight: "260px",
              width: "100%",
              objectFit: "cover",
              display: "block",
            }}
          />
        </button>
        <Dialog open={lightbox} onOpenChange={setLightbox}>
          <DialogContent className="max-w-[92vw] border-0 bg-transparent p-0 shadow-none sm:max-w-md">
            <DialogTitle className="sr-only">{attachment.name}</DialogTitle>
            <img
              src={attachment.url}
              alt={attachment.name}
              className="max-h-[80vh] w-full rounded-lg object-contain"
            />
          </DialogContent>
        </Dialog>
      </>
    );
  }

  // Non-image: a tappable file chip that downloads the attachment.
  const accent = isMe ? "var(--primary-foreground)" : "var(--foreground)";
  const sub = isMe
    ? "color-mix(in srgb, var(--primary-foreground) 70%, transparent)"
    : "var(--muted-foreground)";

  return (
    <a
      href={attachment.url}
      download={attachment.name}
      className="flex items-center gap-3"
      style={{ textDecoration: "none", minWidth: "180px", maxWidth: "240px" }}
    >
      <div
        className="flex flex-shrink-0 items-center justify-center rounded-lg"
        style={{
          width: "38px",
          height: "38px",
          backgroundColor: isMe
            ? "color-mix(in srgb, var(--primary-foreground) 18%, transparent)"
            : "var(--muted)",
        }}
      >
        <FileText size={18} style={{ color: accent }} />
      </div>
      <div className="min-w-0 flex-1">
        <p
          className="truncate"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-medium)",
            color: accent,
          }}
        >
          {attachment.name}
        </p>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "11px", color: sub }}>
          {formatBytes(attachment.sizeBytes)}
        </p>
      </div>
      <Download size={16} style={{ color: sub, flexShrink: 0 }} />
    </a>
  );
}
