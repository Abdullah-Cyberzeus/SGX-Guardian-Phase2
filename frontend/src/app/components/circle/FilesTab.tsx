import { useEffect, useState, type ComponentType } from "react";
import { FileText, Download, ImageIcon, FolderOpen, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Dialog, DialogContent, DialogTitle } from "../ui/dialog";
import { formatBytes, type SharedFile } from "./types";
import chatService from "../../services/chatService";

interface FilesTabProps {
  /** Files shared in the chat — see `collectSharedFiles`. */
  files: SharedFile[];
}

function SectionLabel({ icon: Icon, text }: { icon: ComponentType<{ size?: number; style?: object }>; text: string }) {
  return (
    <div className="mb-2.5 flex items-center gap-1.5">
      <Icon size={13} style={{ color: "var(--muted-foreground)" }} />
      <span
        style={{
          fontFamily: "Inter, sans-serif",
          fontSize: "var(--text-xs)",
          fontWeight: "var(--font-weight-semibold)",
          color: "var(--muted-foreground)",
        }}
      >
        {text}
      </span>
    </div>
  );
}

function AuthenticatedImage({ file, className }: { file: SharedFile; className?: string }) {
  const [source, setSource] = useState(file.attachmentId ? "" : file.url);
  useEffect(() => {
    if (!file.attachmentId) {
      setSource(file.url);
      return;
    }
    let active = true;
    let objectUrl = "";
    void chatService.download(file.attachmentId).then((blob) => {
      if (!active) return;
      objectUrl = URL.createObjectURL(blob);
      setSource(objectUrl);
    }).catch(() => { if (active) setSource(""); });
    return () => {
      active = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [file.attachmentId, file.url]);
  return source
    ? <img src={source} alt={file.name} className={className} style={{ width: "100%", height: "100%", objectFit: "cover", display: "block" }} />
    : <Loader2 className="m-auto animate-spin text-muted-foreground" />;
}

/**
 * Files tab — a read-only view of every photo and file shared in the chat.
 * There is no separate upload here: sharing happens in the chat via the
 * composer's "+" button. This tab is purely a lens over the conversation.
 */
export function FilesTab({ files }: FilesTabProps) {
  const [lightbox, setLightbox] = useState<SharedFile | null>(null);

  const media = files.filter((f) => f.kind === "image");
  const docs = files.filter((f) => f.kind === "file");
  const download = async (file: SharedFile) => {
    try {
      if (file.attachmentId) await chatService.downloadToBrowser(file.attachmentId, file.name);
      else {
        const anchor = document.createElement("a");
        anchor.href = file.url;
        anchor.download = file.name;
        anchor.click();
      }
    } catch (cause) {
      toast.error("File could not be downloaded", { description: cause instanceof Error ? cause.message : undefined });
    }
  };

  if (files.length === 0) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
        <FolderOpen size={36} style={{ color: "var(--muted-foreground)" }} />
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-medium)",
            color: "var(--foreground)",
          }}
        >
          No files shared yet
        </p>
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            color: "var(--muted-foreground)",
            maxWidth: "240px",
            lineHeight: 1.6,
          }}
        >
          Photos and files you share in the chat show up here automatically.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col gap-5 overflow-y-auto p-4">
      {media.length > 0 && (
        <div>
          <SectionLabel icon={ImageIcon} text={`Media · ${media.length}`} />
          <div className="grid grid-cols-3 gap-1.5">
            {media.map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setLightbox(f)}
                className="overflow-hidden rounded-lg"
                style={{
                  aspectRatio: "1 / 1",
                  border: "1px solid var(--border)",
                  cursor: "pointer",
                  padding: 0,
                  background: "var(--muted)",
                }}
              >
                <AuthenticatedImage file={f} />
              </button>
            ))}
          </div>
        </div>
      )}

      {docs.length > 0 && (
        <div>
          <SectionLabel icon={FileText} text={`Documents · ${docs.length}`} />
          <div
            className="overflow-hidden rounded-lg border border-border"
            style={{ backgroundColor: "var(--card)" }}
          >
            {docs.map((f, i) => (
              <button
                key={f.id}
                type="button"
                onClick={() => void download(f)}
                className="flex items-center gap-3 px-4 py-3"
                style={{
                  width: "100%",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  textAlign: "left",
                  textDecoration: "none",
                  borderBottom: i < docs.length - 1 ? "1px solid var(--border)" : undefined,
                }}
              >
                <div
                  className="flex flex-shrink-0 items-center justify-center rounded-lg"
                  style={{
                    width: "40px",
                    height: "40px",
                    backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)",
                  }}
                >
                  <FileText size={18} style={{ color: "var(--primary)" }} />
                </div>
                <div className="min-w-0 flex-1">
                  <p
                    className="truncate"
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-medium)",
                      color: "var(--foreground)",
                    }}
                  >
                    {f.name}
                  </p>
                  <p
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    {formatBytes(f.sizeBytes)} · {f.sharedBy} · {f.sharedAt}
                  </p>
                </div>
                <Download size={16} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
              </button>
            ))}
          </div>
        </div>
      )}

      <Dialog open={!!lightbox} onOpenChange={(o) => !o && setLightbox(null)}>
        <DialogContent className="max-w-[92vw] border-0 bg-transparent p-0 shadow-none sm:max-w-md">
          <DialogTitle className="sr-only">{lightbox?.name ?? "Image"}</DialogTitle>
          {lightbox && (
            <AuthenticatedImage file={lightbox} className="max-h-[80vh] w-full rounded-lg object-contain" />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
