import { useEffect, useMemo, useState } from "react";
import { FolderInput, Pencil, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "../ui/dialog";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "../ui/alert-dialog";
import { ROOT_ID, type VaultFolder } from "./types";

type Mode = "menu" | "rename" | "move";

interface Props {
  folder: VaultFolder | null;
  folders: VaultFolder[];
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRename: (id: string, name: string) => Promise<void>;
  onMove: (id: string, parentId: string) => Promise<void>;
  onDelete: (id: string, recursive: boolean) => Promise<void>;
}

export function FolderActionsDialog({
  folder, folders, open, onOpenChange, onRename, onMove, onDelete,
}: Props) {
  const [mode, setMode] = useState<Mode>("menu");
  const [name, setName] = useState("");
  const [parentId, setParentId] = useState(ROOT_ID);
  const [busy, setBusy] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  useEffect(() => {
    if (open && folder) {
      setMode("menu");
      setName(folder.name);
      setParentId(folder.parentId ?? ROOT_ID);
      setBusy(false);
    }
  }, [open, folder]);

  const descendants = useMemo(() => {
    if (!folder) return new Set<string>();
    const ids = new Set([folder.id]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const item of folders) {
        if (item.parentId && ids.has(item.parentId) && !ids.has(item.id)) {
          ids.add(item.id);
          changed = true;
        }
      }
    }
    return ids;
  }, [folder, folders]);

  const destinations = folders.filter((item) =>
    !descendants.has(item.id) &&
    (item.id === ROOT_ID || item.namespace === folder?.namespace)
  );

  async function run(action: () => Promise<void>, success: string) {
    setBusy(true);
    try {
      await action();
      toast.success(success);
      onOpenChange(false);
    } catch (cause) {
      toast.error("Folder action failed", {
        description: cause instanceof Error ? cause.message : "Please try again.",
      });
    } finally {
      setBusy(false);
    }
  }

  if (!folder) return null;

  return (
    <>
      <Dialog open={open} onOpenChange={(value) => !busy && onOpenChange(value)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {mode === "menu" ? folder.name : mode === "rename" ? "Rename folder" : "Move folder"}
            </DialogTitle>
            <DialogDescription>
              {mode === "menu"
                ? "Choose how you want to manage this encrypted folder."
                : mode === "rename"
                  ? "Enter a new name. Folder contents will not change."
                  : "Choose a new parent folder in the same Vault namespace."}
            </DialogDescription>
          </DialogHeader>

          {mode === "menu" && (
            <div className="grid gap-2">
              <Button variant="outline" className="justify-start gap-2" onClick={() => setMode("rename")}>
                <Pencil size={16} /> Rename
              </Button>
              <Button variant="outline" className="justify-start gap-2" onClick={() => setMode("move")}>
                <FolderInput size={16} /> Move
              </Button>
              <Button
                variant="outline"
                className="justify-start gap-2 text-destructive hover:text-destructive"
                onClick={() => setDeleteOpen(true)}
              >
                <Trash2 size={16} /> Delete
              </Button>
            </div>
          )}

          {mode === "rename" && (
            <form
              className="grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                const trimmed = name.trim();
                if (trimmed && trimmed !== folder.name) {
                  void run(() => onRename(folder.id, trimmed), "Folder renamed");
                }
              }}
            >
              <Input autoFocus value={name} maxLength={120} onChange={(e) => setName(e.target.value)} />
              <DialogFooter>
                <Button type="button" variant="outline" disabled={busy} onClick={() => setMode("menu")}>Back</Button>
                <Button type="submit" disabled={busy || !name.trim() || name.trim() === folder.name}>
                  {busy ? "Renaming…" : "Rename"}
                </Button>
              </DialogFooter>
            </form>
          )}

          {mode === "move" && (
            <div className="grid gap-4">
              <select
                value={parentId}
                onChange={(e) => setParentId(e.target.value)}
                className="h-10 rounded-md border border-input bg-background px-3 text-sm"
                aria-label="Destination folder"
              >
                {destinations.map((item) => (
                  <option key={item.id} value={item.id}>{item.id === ROOT_ID ? "All Files" : item.name}</option>
                ))}
              </select>
              <DialogFooter>
                <Button variant="outline" disabled={busy} onClick={() => setMode("menu")}>Back</Button>
                <Button
                  disabled={busy || parentId === folder.parentId}
                  onClick={() => void run(() => onMove(folder.id, parentId), "Folder moved")}
                >
                  {busy ? "Moving…" : "Move"}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={deleteOpen} onOpenChange={(value) => !busy && setDeleteOpen(value)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete “{folder.name}”?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently deletes the folder, all nested folders, and every encrypted file inside it.
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={busy}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={(event) => {
                event.preventDefault();
                void run(() => onDelete(folder.id, true), "Folder deleted").then(() => setDeleteOpen(false));
              }}
            >
              {busy ? "Deleting…" : "Delete folder"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
