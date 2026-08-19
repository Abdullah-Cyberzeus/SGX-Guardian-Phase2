import { useEffect, useState, type FormEvent } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";
import { Button } from "../ui/button";
import { Input } from "../ui/input";

interface UploadDescriptionDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Files already picked by the browser file input. */
  fileCount: number;
  folderName: string;
  onConfirm: (description: string) => Promise<void>;
}

/** Confirms an upload and collects an optional description before it starts. */
export function UploadDescriptionDialog({
  open,
  onOpenChange,
  fileCount,
  folderName,
  onConfirm,
}: UploadDescriptionDialogProps) {
  const [description, setDescription] = useState("");
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    if (open) setDescription("");
  }, [open]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setUploading(true);
    try {
      await onConfirm(description.trim());
      onOpenChange(false);
    } catch {
      // Parent displays the API error; keep the dialog open for correction.
    } finally {
      setUploading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>
            Upload {fileCount} {fileCount === 1 ? "file" : "files"}
          </DialogTitle>
          <DialogDescription>To "{folderName}". Encrypted and stored in the Guardian Vault.</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <Input
            autoFocus
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description (optional)"
            aria-label="File description"
            maxLength={280}
          />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={uploading}>
              Cancel
            </Button>
            <Button type="submit" disabled={uploading}>
              {uploading ? "Uploading…" : "Upload"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
