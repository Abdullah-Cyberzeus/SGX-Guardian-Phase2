import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { FileX, Loader2 } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { Button } from "../../components/ui/button";
import { useVault } from "../../contexts/VaultContext";
import { FileDetailPanel } from "../../components/vault/FileDetailPanel";
import { ROOT_ID } from "../../components/vault/types";

/** Full-screen file detail — opened when a file is tapped on mobile/tablet. */
export function CS02FileDetail() {
  const { fileId } = useParams<{ fileId: string }>();
  const navigate = useNavigate();
  const { getFile, fetchFile } = useVault();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const file = fileId ? getFile(fileId) : undefined;

  useEffect(() => {
    if (!fileId) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    void fetchFile(fileId)
      .catch((cause) => {
        if (!cancelled) {
          setLoadError(cause instanceof Error ? cause.message : "Unable to load file");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [fileId, fetchFile]);

  if (loading && !file) {
    return (
      <div className="flex h-full flex-col" style={{ backgroundColor: "var(--background)" }}>
        <PageHeader title="File" onBack={() => navigate("/storage")} />
        <div className="flex flex-1 items-center justify-center gap-2 text-sm text-muted-foreground">
          <Loader2 size={18} className="animate-spin" />
          Loading encrypted file…
        </div>
      </div>
    );
  }

  if (!file || loadError) {
    return (
      <div className="flex h-full flex-col" style={{ backgroundColor: "var(--background)" }}>
        <PageHeader title="File" onBack={() => navigate("/storage")} />
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
          <FileX size={40} strokeWidth={1.5} style={{ color: "var(--muted-foreground)" }} />
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--foreground)",
            }}
          >
            File not found
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
            {loadError || "This file may have been removed from the device."}
          </p>
          <Button variant="outline" onClick={() => navigate("/storage")}>
            Back to All Files
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col" style={{ backgroundColor: "var(--background)" }}>
      <PageHeader title={file.name} onBack={() => navigate("/storage")} />
      <div className="flex-1 overflow-hidden">
        <div className="mx-auto h-full w-full max-w-2xl">
          <FileDetailPanel
            file={file}
            onRemoved={() => navigate("/storage")}
            onOpenFolder={(folderId) =>
              navigate(folderId === ROOT_ID ? "/storage" : `/storage?folder=${folderId}`)
            }
          />
        </div>
      </div>
    </div>
  );
}
