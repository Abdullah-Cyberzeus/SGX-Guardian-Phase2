import { useEffect, useState } from "react";
import { FileQuestion, Loader2, Music } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "../ui/dialog";
import { formatBytes, kindLabel, type VaultFile } from "./types";
import { vaultService } from "../../services/vaultService";

interface FilePreviewDialogProps {
  file: VaultFile | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/** Whether a file has content we can render inline. */
export function canPreview(file: VaultFile): boolean {
  return file.sizeBytes <= 33_554_432 && (
    file.kind === "image" ||
    file.mime === "application/pdf" ||
    file.mime.startsWith("text/") ||
    file.mime === "application/json" ||
    file.mime === "application/xml" ||
    file.mime === "text/csv"
  );
}

const TEXT_LIMIT = 20000;

/** Full-screen-ish file preview — images, video, audio, PDF and text. */
export function FilePreviewDialog({ file, open, onOpenChange }: FilePreviewDialogProps) {
  const [text, setText] = useState<string | null>(null);
  const [textState, setTextState] = useState<"idle" | "loading" | "error">("idle");
  const [remoteUrl, setRemoteUrl] = useState<string | undefined>();

  const url = file?.url ?? remoteUrl;
  const isJson = !!file && file.mime === "application/json";
  const isText = !!file && !!url && (file.mime.startsWith("text/") || isJson);

  useEffect(() => {
    if (!open || !file || file.url) return;
    let objectUrl: string | undefined;
    let cancelled = false;
    void vaultService.preview(file.id).then(async (response) => {
      if (cancelled) return;
      const contentType = response.headers.get("content-type") ?? "";
      if (contentType.includes("application/json") && file.mime !== "application/json") {
        const metadata = await response.json();
        if (metadata?.previewable === false) throw new Error(metadata.reason || "Preview unavailable");
      }
      objectUrl = URL.createObjectURL(await response.blob());
      setRemoteUrl(objectUrl);
    }).catch(() => setTextState("error"));
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      setRemoteUrl(undefined);
    };
  }, [open, file]);

  useEffect(() => {
    if (!open || !isText || !url) {
      setText(null);
      setTextState("idle");
      return;
    }
    let cancelled = false;
    setTextState("loading");
    fetch(url)
      .then((r) => r.text())
      .then((t) => {
        if (cancelled) return;
        let content = t;
        if (isJson) {
          try {
            content = JSON.stringify(JSON.parse(t), null, 2);
          } catch {
            // not valid JSON — show as-is
          }
        }
        setText(
          content.length > TEXT_LIMIT
            ? `${content.slice(0, TEXT_LIMIT)}\n\n… preview truncated`
            : content,
        );
        setTextState("idle");
      })
      .catch(() => {
        if (!cancelled) setTextState("error");
      });
    return () => {
      cancelled = true;
    };
  }, [open, isText, isJson, url]);

  if (!file) return null;

  const isImage = file.kind === "image" && !!url;
  const isVideo = false;
  const isAudio = false;
  const isPdf = !!url && file.mime === "application/pdf";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[920px] gap-0 overflow-hidden p-0">
        {/* Header */}
        <div className="border-b border-border px-4 py-3 pr-12">
          <DialogTitle
            className="truncate"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
            }}
          >
            {file.name}
          </DialogTitle>
          <DialogDescription
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
            }}
          >
            {kindLabel(file.kind)} · {formatBytes(file.sizeBytes)}
          </DialogDescription>
        </div>

        {/* Preview body */}
        <div
          className="flex items-center justify-center overflow-auto p-4"
          style={{
            backgroundColor: "var(--muted)",
            minHeight: "300px",
            maxHeight: "76vh",
          }}
        >
          {isImage && (
            <img
              src={url}
              alt={file.name}
              style={{ maxWidth: "100%", maxHeight: "72vh", objectFit: "contain" }}
            />
          )}

          {isVideo && (
            <video
              src={url}
              controls
              autoPlay
              style={{ maxWidth: "100%", maxHeight: "72vh", borderRadius: "8px" }}
            />
          )}

          {isAudio && (
            <div className="flex flex-col items-center gap-4 py-8">
              <div
                className="flex items-center justify-center rounded-full"
                style={{
                  width: "88px",
                  height: "88px",
                  backgroundColor: "color-mix(in srgb, var(--primary) 14%, transparent)",
                }}
              >
                <Music size={36} style={{ color: "var(--primary)" }} />
              </div>
              <audio src={url} controls style={{ width: "min(420px, 80vw)" }} />
            </div>
          )}

          {isPdf && (
            <iframe
              src={url}
              title={file.name}
              style={{
                width: "100%",
                height: "72vh",
                border: "none",
                borderRadius: "8px",
                backgroundColor: "var(--background)",
              }}
            />
          )}

          {isText && (
            <div className="w-full">
              {textState === "loading" && (
                <div className="flex items-center justify-center gap-2 py-12">
                  <Loader2 size={18} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                    Loading preview…
                  </span>
                </div>
              )}
              {textState === "error" && (
                <p className="py-12 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
                  Could not load this file.
                </p>
              )}
              {textState === "idle" && text !== null && (
                <pre
                  className="overflow-auto rounded-lg border border-border"
                  style={{
                    backgroundColor: "var(--background)",
                    padding: "14px",
                    maxHeight: "68vh",
                    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                    fontSize: "12px",
                    lineHeight: 1.6,
                    color: "var(--foreground)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                >
                  {text}
                </pre>
              )}
            </div>
          )}

          {!isImage && !isVideo && !isAudio && !isPdf && !isText && (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <FileQuestion size={40} strokeWidth={1.5} style={{ color: "var(--muted-foreground)" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                No preview available
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", maxWidth: "260px", lineHeight: 1.6 }}>
                This file type can't be shown here — download it to open it.
              </p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
