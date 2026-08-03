import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  useEffect,
  type ReactNode,
} from "react";
import {
  ROOT_ID,
  vaultKindOf,
  type VaultFile,
  type VaultFolder,
} from "../components/vault/types";
import { vaultService, type VaultRecord } from "../services/vaultService";
import { useAuth } from "./AuthContext";

interface VaultChildren {
  folders: VaultFolder[];
  files: VaultFile[];
}

export interface VaultUpload {
  id: string;
  name: string;
  sizeBytes: number;
  loadedBytes: number;
  progress: number;
  status: "uploading" | "completed" | "failed" | "cancelled";
  error?: string;
}

interface VaultContextValue {
  folders: VaultFolder[];
  files: VaultFile[];
  deviceName: string;
  encryption: string;
  capacityBytes: number;
  usedBytes: number;
  loading: boolean;
  error: string | null;
  uploads: VaultUpload[];
  refresh: () => Promise<void>;
  getFolder: (id: string) => VaultFolder | undefined;
  getFile: (id: string) => VaultFile | undefined;
  fetchFile: (id: string) => Promise<VaultFile>;
  /** Direct children of a folder — folders first (A→Z), then files (A→Z). */
  getChildren: (folderId: string) => VaultChildren;
  /** Root → … → folder, for breadcrumbs. */
  getPath: (folderId: string) => VaultFolder[];
  /** Count of direct children (folders + files) in a folder. */
  childCount: (folderId: string) => number;
  /** All files whose name matches the query, across every folder. */
  searchFiles: (query: string) => VaultFile[];
  searchRemote: (query: string) => Promise<VaultFile[]>;
  addFolder: (name: string, parentId: string) => Promise<VaultFolder>;
  renameFolder: (id: string, name: string) => Promise<void>;
  moveFolder: (id: string, parentId: string) => Promise<void>;
  deleteFolder: (id: string, recursive?: boolean) => Promise<void>;
  uploadFile: (file: File, folderId?: string) => Promise<VaultFile>;
  cancelUpload: (id: string) => void;
  retryUpload: (id: string) => Promise<void>;
  dismissUpload: (id: string) => void;
  removeFile: (id: string) => Promise<void>;
  renameFile: (id: string, filename: string) => Promise<void>;
  moveFile: (id: string, folderId: string) => Promise<void>;
  toggleStar: (id: string) => Promise<void>;
}

const VaultContext = createContext<VaultContextValue | null>(null);

/** The only client-created folder is the virtual browser root. */
function seedFolders(): VaultFolder[] {
  const root: VaultFolder = {
    id: ROOT_ID, name: "All Files", parentId: null, kind: "root", createdBy: "—", createdAt: "—",
  };
  return [root];
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** The backend represents its root folder as null or an empty string. */
function toBrowserFolderId(value: unknown): string {
  if (typeof value !== "string") return ROOT_ID;
  const id = value.trim();
  return id || ROOT_ID;
}

/**
 * Single source of truth for every file on the SGX device. Folder and file
 * records are populated only from the Guardian Vault API.
 */
export function VaultProvider({ children }: { children: ReactNode }) {
  const { session, loading: authLoading } = useAuth();
  const [folders, setFolders] = useState<VaultFolder[]>(seedFolders);
  const [files, setFiles] = useState<VaultFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [capacityBytes, setCapacityBytes] = useState(0);
  const [uploads, setUploads] = useState<VaultUpload[]>([]);
  const uploadControllers = useRef(new Map<string, AbortController>());
  const uploadSources = useRef(new Map<string, { file: File; folderId: string }>());

  const mapRecord = useCallback((record: VaultRecord): VaultFile => {
    const id = String(record.vault_id ?? record.id ?? "");
    const mime = String(record.mime ?? "application/octet-stream");
    return {
      id,
      name: String(record.filename ?? record.name ?? id),
      sizeBytes: Number(record.size_plain ?? record.size ?? 0),
      mime,
      kind: vaultKindOf(mime),
      folderId: toBrowserFolderId(record.folder_id),
      sharedBy: String(record.sender_did ?? "You"),
      addedAt: String(record.updated_at ?? record.created_at ?? "—"),
      encrypted: true,
      starred: Boolean(record.starred),
      backendPath: typeof record.path === "string" ? record.path : undefined,
      namespace: typeof record.namespace === "string" ? record.namespace : undefined,
    };
  }, []);

  const mapFolder = useCallback((node: {
    folder_id?: string; id?: string; name: string; parent_id?: string | null;
    namespace?: string; circle_id?: string; created_at?: string;
  }): VaultFolder => ({
    id: String(node.folder_id ?? node.id ?? ""),
    name: node.name,
    parentId: toBrowserFolderId(node.parent_id),
    kind: node.circle_id ? "circle" : "user",
    circleId: node.circle_id || undefined,
    namespace: node.namespace || "personal",
    createdBy: node.circle_id ? "Circle sync" : "You",
    createdAt: node.created_at ?? "—",
  }), []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [listResult, folderResult, treeResult, overviewResult, quotaResult] =
        await Promise.allSettled([
        vaultService.list(), vaultService.listFolders(), vaultService.tree(),
        vaultService.overview(), vaultService.quota(),
      ]);

      const list = listResult.status === "fulfilled" ? listResult.value : null;
      const folderList = folderResult.status === "fulfilled" ? folderResult.value : null;
      const tree = treeResult.status === "fulfilled" ? treeResult.value : null;
      const overview = overviewResult.status === "fulfilled" ? overviewResult.value : null;
      const quota = quotaResult.status === "fulfilled" ? quotaResult.value : null;

      // A file-list failure must not erase a successful tree response (or vice
      // versa). At least one source is enough to render useful Vault contents.
      if (!list && !tree) {
        throw listResult.status === "rejected"
          ? listResult.reason
          : new Error("Unable to load Vault files");
      }

      const listedFiles = list?.files ?? [];
      const treeFiles = tree?.files ?? [];
      const records = new Map(
        [...listedFiles, ...treeFiles]
          .map((record) => [String(record.vault_id ?? record.id ?? ""), record] as const)
          .filter(([id]) => Boolean(id)),
      );
      setFiles([...records.values()].map(mapRecord));
      setFolders(() => {
        const root = seedFolders()[0];
        const apiFolders = [...(folderList?.folders ?? []), ...(tree?.folders ?? [])];
        const known = new Set([ROOT_ID]);
        const mapped = apiFolders.flatMap((node) => {
          const folder = mapFolder(node);
          if (!folder.id || known.has(folder.id)) return [];
          known.add(folder.id);
          return [folder];
        });
        const discovered = listedFiles.flatMap((record) => {
          const id = toBrowserFolderId(record.folder_id);
          if (id === ROOT_ID || known.has(id)) return [];
          known.add(id);
          return [{
            id,
            name: String(record.circle_id ?? record.namespace ?? id),
            parentId: ROOT_ID,
            kind: record.circle_id ? "circle" as const : "user" as const,
            circleId: record.circle_id ?? undefined,
            namespace: record.namespace ?? "personal",
            createdBy: "Guardian",
            createdAt: "Synced",
          }];
        });
        return [root, ...mapped, ...discovered];
      });
      setCapacityBytes(quota?.quota_bytes || overview?.capacity_bytes || 0);

      const optionalFailures = [
        folderResult.status === "rejected" ? "folders" : null,
        treeResult.status === "rejected" ? "folder tree" : null,
        overviewResult.status === "rejected" ? "overview" : null,
        quotaResult.status === "rejected" ? "quota" : null,
      ].filter(Boolean);
      setError(optionalFailures.length
        ? `Some Vault metadata could not be loaded (${optionalFailures.join(", ")}). Files that are available are still shown.`
        : null);
    } catch (cause) {
      // Preserve the last successfully loaded view during transient failures.
      setError(cause instanceof Error ? cause.message : "Unable to load Vault");
    } finally {
      setLoading(false);
    }
  }, [mapFolder, mapRecord]);

  useEffect(() => {
    if (authLoading) return;
    // Do not require a client-side session here. Guardian deployments can run
    // with login disabled, in which case /auth/session has no session to
    // restore while the Vault API is intentionally available. The backend
    // remains the authority and will return 401 when authentication is needed.
    void refresh();
  }, [authLoading, session?.token, refresh]);

  const folderById = useMemo(() => {
    const m = new Map<string, VaultFolder>();
    for (const f of folders) m.set(f.id, f);
    return m;
  }, [folders]);

  // Direct child counts, computed once per data change (cheap lookups at scale).
  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of folders) {
      if (f.parentId) m.set(f.parentId, (m.get(f.parentId) ?? 0) + 1);
    }
    for (const f of files) m.set(f.folderId, (m.get(f.folderId) ?? 0) + 1);
    return m;
  }, [folders, files]);

  const getFolder = useCallback((id: string) => folderById.get(id), [folderById]);
  const getFile = useCallback((id: string) => files.find((f) => f.id === id), [files]);
  const fetchFile = useCallback(async (id: string): Promise<VaultFile> => {
    const file = mapRecord(await vaultService.detail(id));
    setFiles((current) => [
      file,
      ...current.filter((item) => item.id !== file.id),
    ]);
    return file;
  }, [mapRecord]);
  const childCount = useCallback((id: string) => counts.get(id) ?? 0, [counts]);

  const getChildren = useCallback(
    (folderId: string): VaultChildren => ({
      folders: folders
        .filter((f) => f.parentId === folderId)
        .sort((a, b) => collator.compare(a.name, b.name)),
      files: files
        .filter((f) => f.folderId === folderId)
        .sort((a, b) => collator.compare(a.name, b.name)),
    }),
    [folders, files],
  );

  const getPath = useCallback(
    (folderId: string): VaultFolder[] => {
      const path: VaultFolder[] = [];
      let current = folderById.get(folderId);
      let guard = 0;
      while (current && guard++ < 64) {
        path.unshift(current);
        current = current.parentId ? folderById.get(current.parentId) : undefined;
      }
      return path;
    },
    [folderById],
  );

  const searchFiles = useCallback(
    (query: string): VaultFile[] => {
      const q = query.trim().toLowerCase();
      if (!q) return [];
      return files
        .filter((f) => f.name.toLowerCase().includes(q))
        .sort((a, b) => collator.compare(a.name, b.name));
    },
    [files],
  );

  const searchRemote = useCallback(async (query: string) => {
    const response = await vaultService.search(query);
    return response.results.map((result) => mapRecord(result.file));
  }, [mapRecord]);

  const addFolder = useCallback(async (name: string, parentId: string): Promise<VaultFolder> => {
    const parent = folderById.get(parentId);
    const created = await vaultService.createFolder({
      name: name.trim() || "Untitled folder",
      parent_id: parentId === ROOT_ID ? undefined : parentId,
      namespace: parent?.namespace ?? "personal",
    });
    const folder: VaultFolder = {
      id: String(created.folder_id ?? created.id),
      name: created.name,
      parentId,
      kind: "user",
      namespace: created.namespace ?? parent?.namespace ?? "personal",
      createdBy: "You",
      createdAt: created.created_at ?? "Just now",
    };
    setFolders((prev) => [...prev, folder]);
    return folder;
  }, [folderById]);

  const renameFolder = useCallback(async (id: string, name: string) => {
    const current = folderById.get(id);
    if (!current || id === ROOT_ID) throw new Error("This folder cannot be renamed.");
    const updated = mapFolder(await vaultService.updateFolder(id, {
      namespace: current.namespace ?? "personal",
      name: name.trim(),
    }));
    setFolders((items) => items.map((item) =>
      item.id === id
        ? { ...item, ...updated, parentId: item.parentId, namespace: current.namespace }
        : item
    ));
  }, [folderById, mapFolder]);

  const moveFolder = useCallback(async (id: string, parentId: string) => {
    const current = folderById.get(id);
    if (!current || id === ROOT_ID) throw new Error("This folder cannot be moved.");
    const updated = mapFolder(await vaultService.updateFolder(id, {
      namespace: current.namespace ?? "personal",
      parent_id: parentId === ROOT_ID ? "" : parentId,
    }));
    setFolders((items) => items.map((item) =>
      item.id === id
        ? { ...item, ...updated, parentId, namespace: current.namespace }
        : item
    ));
  }, [folderById, mapFolder]);

  const deleteFolder = useCallback(async (id: string, recursive = false) => {
    const current = folderById.get(id);
    if (!current || id === ROOT_ID) throw new Error("This folder cannot be deleted.");
    const descendants = new Set([id]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const item of folders) {
        if (item.parentId && descendants.has(item.parentId) && !descendants.has(item.id)) {
          descendants.add(item.id);
          changed = true;
        }
      }
    }
    await vaultService.deleteFolder(id, {
      ns: current.namespace ?? "personal",
      recursive,
    });
    setFolders((items) => items.filter((item) => !descendants.has(item.id)));
    if (recursive) setFiles((items) => items.filter((item) => !descendants.has(item.folderId)));
  }, [folderById, folders]);

  const uploadFile = useCallback(async (source: File, folderId = ROOT_ID): Promise<VaultFile> => {
    const id = typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `upload-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const controller = new AbortController();
    uploadControllers.current.set(id, controller);
    uploadSources.current.set(id, { file: source, folderId });
    setUploads((items) => [{
      id, name: source.name, sizeBytes: source.size, loadedBytes: 0,
      progress: 0, status: "uploading",
    }, ...items]);
    try {
      const result = await vaultService.upload(source, {
        folder_id: folderId === ROOT_ID ? undefined : folderId,
        signal: controller.signal,
        onProgress: (loaded, total) => {
          const denominator = total || source.size || 1;
          setUploads((items) => items.map((item) => item.id === id ? {
            ...item,
            loadedBytes: loaded,
            progress: Math.min(99, Math.round((loaded / denominator) * 100)),
          } : item));
        },
      });
      const file = mapRecord(result.record);
      setFiles((prev) => [file, ...prev.filter((item) => item.id !== file.id)]);
      setUploads((items) => items.map((item) => item.id === id
        ? { ...item, loadedBytes: source.size, progress: 100, status: "completed" }
        : item));
      window.setTimeout(() => {
        setUploads((items) => items.filter((item) => item.id !== id || item.status !== "completed"));
        uploadSources.current.delete(id);
      }, 3500);
      return file;
    } catch (cause) {
      const cancelled = cause instanceof DOMException && cause.name === "AbortError";
      setUploads((items) => items.map((item) => item.id === id ? {
        ...item,
        status: cancelled ? "cancelled" : "failed",
        error: cancelled ? "Upload cancelled" : cause instanceof Error ? cause.message : "Upload failed",
      } : item));
      throw cause;
    } finally {
      uploadControllers.current.delete(id);
    }
  }, [mapRecord]);

  const cancelUpload = useCallback((id: string) => {
    uploadControllers.current.get(id)?.abort();
  }, []);

  const retryUpload = useCallback(async (id: string) => {
    const source = uploadSources.current.get(id);
    if (!source) throw new Error("The original file is no longer available. Select it again.");
    setUploads((items) => items.filter((item) => item.id !== id));
    uploadSources.current.delete(id);
    await uploadFile(source.file, source.folderId);
  }, [uploadFile]);

  const dismissUpload = useCallback((id: string) => {
    if (uploadControllers.current.has(id)) uploadControllers.current.get(id)?.abort();
    setUploads((items) => items.filter((item) => item.id !== id));
    uploadSources.current.delete(id);
  }, []);

  const removeFile = useCallback(async (id: string) => {
    await vaultService.delete(id);
    setFiles((prev) => prev.filter((f) => f.id !== id));
  }, []);

  const renameFile = useCallback(async (id: string, filename: string) => {
    const updated = mapRecord(await vaultService.update(id, { filename }));
    setFiles((prev) => prev.map((file) => file.id === id ? updated : file));
  }, [mapRecord]);

  const moveFile = useCallback(async (id: string, folderId: string) => {
    const updated = mapRecord(await vaultService.update(id, {
      folder_id: folderId === ROOT_ID ? "" : folderId,
    }));
    setFiles((prev) => prev.map((file) => file.id === id ? updated : file));
  }, [mapRecord]);

  const toggleStar = useCallback(async (id: string) => {
    const current = files.find((file) => file.id === id);
    if (!current) throw new Error("File not found.");
    const next = !current.starred;
    setFiles((items) => items.map((file) => file.id === id ? { ...file, starred: next } : file));
    try {
      const updated = mapRecord(await vaultService.star(id, next));
      setFiles((items) => items.map((file) => file.id === id ? updated : file));
    } catch (cause) {
      setFiles((items) => items.map((file) => file.id === id ? { ...file, starred: current.starred } : file));
      throw cause;
    }
  }, [files, mapRecord]);

  const usedBytes = useMemo(
    () => files.reduce((sum, f) => sum + f.sizeBytes, 0),
    [files],
  );

  const value = useMemo<VaultContextValue>(
    () => ({
      folders,
      files,
      deviceName: "SG-X Guardian",
      encryption: "AES-256-GCM",
      capacityBytes,
      usedBytes,
      loading,
      error,
      uploads,
      refresh,
      getFolder,
      getFile,
      fetchFile,
      getChildren,
      getPath,
      childCount,
      searchFiles,
      searchRemote,
      addFolder,
      renameFolder,
      moveFolder,
      deleteFolder,
      uploadFile,
      cancelUpload,
      retryUpload,
      dismissUpload,
      removeFile,
      renameFile,
      moveFile,
      toggleStar,
    }),
    [
      folders,
      files,
      capacityBytes,
      loading,
      error,
      uploads,
      refresh,
      usedBytes,
      getFolder,
      getFile,
      fetchFile,
      getChildren,
      getPath,
      childCount,
      searchFiles,
      searchRemote,
      addFolder,
      renameFolder,
      moveFolder,
      deleteFolder,
      uploadFile,
      cancelUpload,
      retryUpload,
      dismissUpload,
      removeFile,
      renameFile,
      moveFile,
      toggleStar,
    ],
  );

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export function useVault() {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error("useVault must be used within VaultProvider");
  return ctx;
}
