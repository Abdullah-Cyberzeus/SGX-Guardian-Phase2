import { useEffect, useState } from "react";
import { FileText, Download, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Dialog, DialogContent, DialogTitle } from "../ui/dialog";
import { formatBytes, type AttachmentMeta } from "./types";
import chatService from "../../services/chatService";

interface MessageAttachmentProps {
  attachment: AttachmentMeta;
  /** Whether the message is from the current user (affects color on tinted bubble). */
  isMe: boolean;
}

/** Renders a file/image attachment inside a chat bubble. */
export function MessageAttachment({ attachment, isMe }: MessageAttachmentProps) {
  const [lightbox, setLightbox] = useState(false);
  const [imageUrl, setImageUrl] = useState<string | null>(
    attachment.attachmentId ? null : attachment.url,
  );
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (attachment.kind !== "image" || !attachment.attachmentId) {
      setImageUrl(attachment.url);
      return;
    }
    let active = true;
    let objectUrl: string | null = null;
    void chatService.download(attachment.attachmentId)
      .then((blob) => {
        if (!active) return;
        objectUrl = URL.createObjectURL(blob);
        setImageUrl(objectUrl);
      })
      .catch(() => { if (active) setImageUrl(null); });
    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [attachment.attachmentId, attachment.kind, attachment.url]);

  const download = async () => {
    if (!attachment.attachmentId) {
      const anchor = document.createElement("a");
      anchor.href = attachment.url;
      anchor.download = attachment.name;
      anchor.click();
      return;
    }
    setDownloading(true);
    try {
      await chatService.downloadToBrowser(attachment.attachmentId, attachment.name);
    } catch (cause) {
      toast.error("File could not be downloaded", {
        description: cause instanceof Error ? cause.message : undefined,
      });
    } finally {
      setDownloading(false);
    }
  };

  if (attachment.kind === "image") {
    return (
      <>
        <button
          type="button"
          onClick={() => setLightbox(true)}
          className="block overflow-hidden rounded-xl"
          style={{ cursor: "pointer", background: "none", border: "none", padding: 0 }}
        >
          {imageUrl ? <img
            src={imageUrl}
            alt={attachment.name}
            style={{
              maxWidth: "240px",
              maxHeight: "260px",
              width: "100%",
              objectFit: "cover",
              display: "block",
            }}
          /> : <Loader2 className="m-8 animate-spin text-muted-foreground" />}
        </button>
        <Dialog open={lightbox} onOpenChange={setLightbox}>
          <DialogContent className="max-w-[92vw] border-0 bg-transparent p-0 shadow-none sm:max-w-md">
            <DialogTitle className="sr-only">{attachment.name}</DialogTitle>
            {imageUrl && <img
              src={imageUrl}
              alt={attachment.name}
              className="max-h-[80vh] w-full rounded-lg object-contain"
            />}
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
    <button
      type="button"
      onClick={() => void download()}
      disabled={downloading}
      className="flex items-center gap-3"
      style={{
        background: "none",
        border: "none",
        cursor: downloading ? "wait" : "pointer",
        padding: 0,
        textAlign: "left",
        textDecoration: "none",
        minWidth: "180px",
        maxWidth: "240px",
      }}
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
      {downloading
        ? <Loader2 size={16} className="animate-spin" style={{ color: sub, flexShrink: 0 }} />
        : <Download size={16} style={{ color: sub, flexShrink: 0 }} />}
    </button>
  );
}
