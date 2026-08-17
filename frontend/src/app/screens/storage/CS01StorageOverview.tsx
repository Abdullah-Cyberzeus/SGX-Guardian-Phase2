import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
} from "react";
import { useNavigate, useSearchParams } from "react-router";
import { toast } from "sonner";
import {
  AlertCircle, CheckCircle2, Loader2, RotateCcw, Upload, Search,
  FolderPlus, FolderOpen, SearchX, Send, SlidersHorizontal, Star, X,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { useVault } from "../../contexts/VaultContext";
import { Breadcrumbs } from "../../components/vault/Breadcrumbs";
import { EntryRow, ENTRY_ROW_HEIGHT } from "../../components/vault/EntryRow";
import { StorageBar } from "../../components/vault/StorageBar";
import { FileDetailPanel } from "../../components/vault/FileDetailPanel";
import { NewFolderDialog } from "../../components/vault/NewFolderDialog";
import { FolderActionsDialog } from "../../components/vault/FolderActionsDialog";
import { useVirtualRows } from "../../components/vault/useVirtualRows";
import { formatBytes, ROOT_ID, type BrowserEntry } from "../../components/vault/types";
import { useAuth } from "../../contexts/AuthContext";
import { isMemberRole } from "../../utils/authorization";

type FileTypeFilter = "all" | "image" | "document" | "media";
type SizeFilter = "all" | "small" | "medium" | "large" | "very-large";

const MIB = 1024 * 1024;

/** Tracks the desktop (lg+) breakpoint — drives select-in-panel vs navigate. */
function useIsDesktop() {
  const [isDesktop, setIsDesktop] = useState(
    () => typeof window !== "undefined" && window.matchMedia("(min-width: 1024px)").matches,
  );
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const onChange = () => setIsDesktop(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return isDesktop;
}

/** All Files — a Drive-style folder browser over every file on the SGX device. */
export function CS01StorageOverview() {
  const navigate = useNavigate();
  const isDesktop = useIsDesktop();
  const vault = useVault();
  const { session } = useAuth();
  const canManageVault = !isMemberRole(session?.user.role);
  const [searchParams, setSearchParams] = useSearchParams();

  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<typeof vault.files>([]);
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [newFolderOpen, setNewFolderOpen] = useState(false);
  const [actionFolderId, setActionFolderId] = useState<string | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [starredOnly, setStarredOnly] = useState(false);
  const [fileType, setFileType] = useState<FileTypeFilter>("all");
  const [sizeFilter, setSizeFilter] = useState<SizeFilter>("all");
  const uploadRef = useRef<HTMLInputElement>(null);

  // Current folder — falls back to root if the URL points at a stale id.
  const folderParam = searchParams.get("folder") || ROOT_ID;
  const folder = vault.getFolder(folderParam) ?? vault.getFolder(ROOT_ID)!;
  const path = vault.getPath(folder.id);
  const searching = query.trim().length > 0;
  const activeFilterCount =
    Number(starredOnly) + Number(fileType !== "all") + Number(sizeFilter !== "all");

  useEffect(() => {
    if (!searching) {
      setSearchResults([]);
      return;
    }
    const timer = window.setTimeout(() => {
      void vault.searchRemote(query).then(setSearchResults).catch((cause) => {
        toast.error("Search failed", {
          description: cause instanceof Error ? cause.message : "Try again.",
        });
      });
    }, 300);
    return () => window.clearTimeout(timer);
  }, [query, searching, vault.searchRemote]);

  // Rows: search hits across the device, or the current folder's contents.
  const entries = useMemo<BrowserEntry[]>(() => {
    const matchesFilters = (file: typeof vault.files[number]) => {
      if (starredOnly && !file.starred) return false;
      if (fileType !== "all" && file.kind !== fileType) return false;
      if (sizeFilter === "small" && file.sizeBytes >= MIB) return false;
      if (sizeFilter === "medium" && (file.sizeBytes < MIB || file.sizeBytes >= 10 * MIB)) return false;
      if (sizeFilter === "large" && (file.sizeBytes < 10 * MIB || file.sizeBytes >= 50 * MIB)) return false;
      if (sizeFilter === "very-large" && file.sizeBytes < 50 * MIB) return false;
      return true;
    };

    if (searching) {
      return searchResults
        .filter(matchesFilters)
        .map((file) => ({ type: "file" as const, file }));
    }
    const { folders, files } = vault.getChildren(folder.id);
    const filteredFiles = files.filter(matchesFilters);
    return [
      ...(activeFilterCount === 0 ? folders : []).map((f) => ({
        type: "folder" as const,
        folder: f,
        itemCount: vault.childCount(f.id),
      })),
      ...filteredFiles.map((file) => ({ type: "file" as const, file })),
    ];
  }, [
    searching, searchResults, folder.id, vault, starredOnly, fileType,
    sizeFilter, activeFilterCount,
  ]);

  const clearFilters = () => {
    setStarredOnly(false);
    setFileType("all");
    setSizeFilter("all");
  };

  const virtual = useVirtualRows({ count: entries.length, rowHeight: ENTRY_ROW_HEIGHT });

  // Reset scroll to the top whenever the folder or search changes.
  useEffect(() => {
    if (virtual.scrollRef.current) virtual.scrollRef.current.scrollTop = 0;
  }, [folder.id, query, virtual.scrollRef]);

  const selectedFile = selectedFileId ? vault.getFile(selectedFileId) : undefined;
  const actionFolder = actionFolderId ? vault.getFolder(actionFolderId) ?? null : null;

  const navigateFolder = (id: string) => {
    setQuery("");
    setSearchParams(id === ROOT_ID ? {} : { folder: id });
  };

  const openEntry = (entry: BrowserEntry) => {
    if (entry.type === "folder") {
      navigateFolder(entry.folder.id);
      return;
    }
    if (isDesktop) setSelectedFileId(entry.file.id);
    else navigate(`/storage/${entry.file.id}`);
  };

  const handleUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const selected = Array.from(e.target.files ?? []);
    e.target.value = "";
    if (!selected.length) return;
    const results = await Promise.allSettled(selected.map((file) => vault.uploadFile(file, folder.id)));
    const uploaded = results.flatMap((result) => result.status === "fulfilled" ? [result.value] : []);
    const failed = results.length - uploaded.length;
    if (uploaded.length) {
      toast.success(`${uploaded.length} ${uploaded.length === 1 ? "file" : "files"} uploaded`, {
        description: "Encrypted and stored in the Guardian Vault.",
      });
      if (isDesktop && uploaded.length === 1) setSelectedFileId(uploaded[0].id);
    }
    if (failed) toast.error(`${failed} upload${failed === 1 ? "" : "s"} failed`, { description: "Review the upload panel and retry." });
  };

  const handleCreateFolder = async (name: string) => {
    try {
      await vault.addFolder(name, folder.id);
      toast.success("Folder created", {
        description: `"${name}" added to ${folder.id === ROOT_ID ? "All Files" : folder.name}.`,
      });
    } catch (cause) {
      toast.error("Folder could not be created", {
        description: cause instanceof Error ? cause.message : "Try again.",
      });
      throw cause;
    }
  };

  const visibleEntries = entries.slice(virtual.startIndex, virtual.endIndex);

  return (
    <div className="flex h-full flex-col" style={{ backgroundColor: "var(--background)" }}>
      <PageHeader
        title="All Files"
        subtitle={`${vault.files.length.toLocaleString()} files · ${formatBytes(
          vault.usedBytes,
        )} of ${formatBytes(vault.capacityBytes)}`}
        showBack={false}
        large
        right={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-shrink-0 gap-1.5"
              onClick={() => navigate("/storage/transfers")}
            >
              <Send size={15} />
              <span className="hidden sm:inline">Transfer</span>
            </Button>
            {canManageVault && <Button
              variant="outline"
              size="sm"
              className="flex-shrink-0 gap-1.5"
              onClick={() => setNewFolderOpen(true)}
            >
              <FolderPlus size={15} />
              <span className="hidden sm:inline">New</span>
            </Button>}
            <Button
              size="sm"
              className="flex-shrink-0 gap-1.5"
              onClick={() => uploadRef.current?.click()}
            >
              <Upload size={15} />
              <span className="hidden sm:inline">Upload</span>
            </Button>
          </div>
        }
      />

      {vault.error && (
        <div
          className="flex items-center justify-between gap-3 border-b border-destructive/30 px-4 py-2.5"
          style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, var(--background))" }}
        >
          <div className="flex min-w-0 items-center gap-2 text-xs text-destructive">
            <AlertCircle size={15} className="flex-shrink-0" />
            <span className="truncate">Vault unavailable: {vault.error}</span>
          </div>
          <Button variant="outline" size="sm" onClick={() => void vault.refresh()}>Retry</Button>
        </div>
      )}

      {vault.uploads.length > 0 && (
        <section className="border-b border-border bg-card px-4 py-3" aria-label="File uploads" aria-live="polite">
          <div className="mx-auto flex max-w-4xl flex-col gap-2">
            {vault.uploads.map((upload) => (
              <div key={upload.id} className="rounded-lg border border-border bg-background p-3">
                <div className="flex items-center gap-3">
                  {upload.status === "uploading"
                    ? <Loader2 size={17} className="shrink-0 animate-spin text-primary" />
                    : upload.status === "completed"
                      ? <CheckCircle2 size={17} className="shrink-0 text-[var(--chart-2)]" />
                      : <AlertCircle size={17} className="shrink-0 text-destructive" />}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-3 text-xs">
                      <strong className="truncate">{upload.name}</strong>
                      <span className="shrink-0 text-muted-foreground">
                        {upload.status === "uploading" ? `${upload.progress}%` : upload.status}
                      </span>
                    </div>
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full transition-[width] duration-200"
                        style={{
                          width: `${upload.progress}%`,
                          backgroundColor: upload.status === "failed" ? "var(--destructive)" : "var(--primary)",
                        }}
                      />
                    </div>
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      {upload.error || `${formatBytes(upload.loadedBytes)} of ${formatBytes(upload.sizeBytes)}`}
                    </p>
                  </div>
                  {upload.status === "uploading" ? (
                    <Button size="sm" variant="ghost" onClick={() => vault.cancelUpload(upload.id)} aria-label={`Cancel ${upload.name}`}><X size={15} /></Button>
                  ) : upload.status === "failed" || upload.status === "cancelled" ? (
                    <div className="flex gap-1">
                      <Button size="sm" variant="outline" onClick={() => void vault.retryUpload(upload.id).catch((cause) => toast.error("Retry failed", { description: cause instanceof Error ? cause.message : "Select the file again." }))}><RotateCcw size={14} /> Retry</Button>
                      <Button size="sm" variant="ghost" onClick={() => vault.dismissUpload(upload.id)} aria-label={`Dismiss ${upload.name}`}><X size={15} /></Button>
                    </div>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="flex min-h-0 flex-1">
        {/* ── File browser ── */}
        <div className="flex min-w-0 flex-1 flex-col">
          {/* Toolbar */}
          <div className="flex flex-col gap-2.5 border-b border-border px-4 py-3">
            {(searching || path.length > 1) && (
              <div className="min-w-0">
                {searching ? (
                  <span
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-semibold)",
                      color: "var(--foreground)",
                    }}
                  >
                    {entries.length.toLocaleString()}{" "}
                    {entries.length === 1 ? "result" : "results"} for "{query.trim()}"
                  </span>
                ) : (
                  <Breadcrumbs path={path} onNavigate={navigateFolder} />
                )}
              </div>
            )}

            <div className="flex gap-2">
              <div className="relative min-w-0 flex-1">
                <Search
                  size={15}
                  className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2"
                  style={{ color: "var(--muted-foreground)" }}
                />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search all files on this device"
                  className="h-10 pl-9"
                  aria-label="Search files"
                />
              </div>
              <Button
                type="button"
                variant={activeFilterCount > 0 ? "default" : "outline"}
                className="h-10 shrink-0 gap-1.5"
                aria-expanded={filtersOpen}
                onClick={() => setFiltersOpen((open) => !open)}
              >
                <SlidersHorizontal size={15} />
                <span className="hidden sm:inline">Filters</span>
                {activeFilterCount > 0 && (
                  <span className="rounded-full bg-background/20 px-1.5 text-[10px]">
                    {activeFilterCount}
                  </span>
                )}
              </Button>
            </div>

            {filtersOpen && (
              <section
                className="grid gap-3 rounded-lg border border-border bg-card p-3 sm:grid-cols-[auto_1fr_1fr_auto]"
                aria-label="File filters"
              >
                <Button
                  type="button"
                  size="sm"
                  variant={starredOnly ? "default" : "outline"}
                  className="justify-start gap-2"
                  aria-pressed={starredOnly}
                  onClick={() => setStarredOnly((value) => !value)}
                >
                  <Star size={14} fill={starredOnly ? "currentColor" : "none"} />
                  Starred only
                </Button>

                <label className="flex flex-col gap-1 text-[11px] font-medium text-muted-foreground">
                  File type
                  <select
                    value={fileType}
                    onChange={(event) => setFileType(event.target.value as FileTypeFilter)}
                    className="h-9 rounded-md border border-border bg-background px-2 text-sm text-foreground outline-none focus:border-primary"
                  >
                    <option value="all">All types</option>
                    <option value="image">Images</option>
                    <option value="document">Documents</option>
                    <option value="media">Audio and video</option>
                  </select>
                </label>

                <label className="flex flex-col gap-1 text-[11px] font-medium text-muted-foreground">
                  File size
                  <select
                    value={sizeFilter}
                    onChange={(event) => setSizeFilter(event.target.value as SizeFilter)}
                    className="h-9 rounded-md border border-border bg-background px-2 text-sm text-foreground outline-none focus:border-primary"
                  >
                    <option value="all">Any size</option>
                    <option value="small">Under 1 MB</option>
                    <option value="medium">1–10 MB</option>
                    <option value="large">10–50 MB</option>
                    <option value="very-large">50 MB and larger</option>
                  </select>
                </label>

                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className="self-end"
                  disabled={activeFilterCount === 0}
                  onClick={clearFilters}
                >
                  <X size={14} /> Clear
                </Button>
              </section>
            )}

            {activeFilterCount > 0 && (
              <p className="text-xs text-muted-foreground" role="status">
                Showing {entries.length.toLocaleString()} matching{" "}
                {entries.length === 1 ? "file" : "files"} in this view.
              </p>
            )}
          </div>

          {/* Column header — tablet+ */}
          <div
            className="hidden items-center gap-3 border-b border-border px-3 py-2 md:flex"
            style={{ backgroundColor: "var(--card)" }}
          >
            <span style={{ width: "36px" }} className="flex-shrink-0" />
            <span
              className="flex-1"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "11px",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.04em",
              }}
            >
              Name
            </span>
            <span
              className="w-28 flex-shrink-0"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "11px",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.04em",
              }}
            >
              Owner
            </span>
            <span
              className="hidden w-32 flex-shrink-0 lg:block"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "11px",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.04em",
              }}
            >
              Modified
            </span>
            <span
              className="w-24 flex-shrink-0 text-right"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "11px",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--muted-foreground)",
                letterSpacing: "0.04em",
              }}
            >
              Size
            </span>
            <span style={{ width: "36px" }} className="flex-shrink-0" />
          </div>

          {/* Virtualized list */}
          <div ref={virtual.scrollRef} className="min-h-0 flex-1 overflow-y-auto">
            {vault.loading ? (
              <div className="flex flex-1 items-center justify-center p-10 text-sm text-muted-foreground">
                <Loader2 size={18} className="mr-2 animate-spin" /> Loading encrypted Vault…
              </div>
            ) : entries.length === 0 ? (
              <div className="flex flex-col items-center gap-3 px-6 py-16 text-center">
                {searching ? (
                  <SearchX size={38} strokeWidth={1.5} style={{ color: "var(--muted-foreground)" }} />
                ) : (
                  <FolderOpen size={38} strokeWidth={1.5} style={{ color: "var(--muted-foreground)" }} />
                )}
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-sm)",
                    fontWeight: "var(--font-weight-medium)",
                    color: "var(--foreground)",
                  }}
                >
                  {searching || activeFilterCount > 0 ? "No files match" : "This folder is empty"}
                </p>
                <p
                  style={{
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    color: "var(--muted-foreground)",
                    maxWidth: "260px",
                    lineHeight: 1.6,
                  }}
                >
                  {searching || activeFilterCount > 0
                    ? "Try changing your search or clearing one of the active filters."
                    : canManageVault
                      ? "Upload a file here, create a folder, or share one in a Circle."
                      : "Upload an encrypted file or receive one from a Guardian contact."}
                </p>
              </div>
            ) : (
              <div style={{ height: `${virtual.totalHeight}px`, position: "relative" }}>
                <div style={{ transform: `translateY(${virtual.offsetTop}px)` }}>
                  {visibleEntries.map((entry) => (
                    <EntryRow
                      key={entry.type === "folder" ? entry.folder.id : entry.file.id}
                      entry={entry}
                      active={
                        entry.type === "file" &&
                        isDesktop &&
                        selectedFileId === entry.file.id
                      }
                      onOpen={() => openEntry(entry)}
                      onToggleStar={
                        canManageVault && entry.type === "file"
                          ? () => {
                              void vault.toggleStar(entry.file.id).catch((cause) => {
                                toast.error("Star update failed", {
                                  description: cause instanceof Error ? cause.message : "Please try again.",
                                });
                              });
                            }
                          : undefined
                      }
                      onFolderActions={
                        canManageVault && entry.type === "folder" && entry.folder.kind === "user"
                          ? () => setActionFolderId(entry.folder.id)
                          : undefined
                      }
                    />
                  ))}
                </div>
              </div>
            )}
          </div>

          <StorageBar usedBytes={vault.usedBytes} capacityBytes={vault.capacityBytes} />
        </div>

        {/* ── Detail panel — desktop, when a file is open ── */}
        {isDesktop && selectedFile && (
          <div className="hidden w-[380px] flex-shrink-0 border-l border-border lg:flex">
            <FileDetailPanel
              key={selectedFile.id}
              file={selectedFile}
              canManage={canManageVault}
              onRemoved={() => setSelectedFileId(null)}
              onOpenFolder={navigateFolder}
            />
          </div>
        )}
      </div>

      <input ref={uploadRef} type="file" multiple hidden onChange={handleUpload} />
      {canManageVault && <NewFolderDialog
        open={newFolderOpen}
        onOpenChange={setNewFolderOpen}
        parentName={folder.id === ROOT_ID ? "All Files" : folder.name}
        onCreate={handleCreateFolder}
      />}
      {canManageVault && <FolderActionsDialog
        folder={actionFolder}
        folders={vault.folders}
        open={!!actionFolder}
        onOpenChange={(open) => { if (!open) setActionFolderId(null); }}
        onRename={vault.renameFolder}
        onMove={vault.moveFolder}
        onDelete={async (id, recursive) => {
          await vault.deleteFolder(id, recursive);
          if (folder.id === id) navigateFolder(ROOT_ID);
        }}
      />}
    </div>
  );
}
