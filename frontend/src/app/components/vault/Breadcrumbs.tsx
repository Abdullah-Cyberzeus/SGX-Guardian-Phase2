import { Fragment } from "react";
import { HardDrive } from "lucide-react";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "../ui/breadcrumb";
import type { VaultFolder } from "./types";

interface BreadcrumbsProps {
  /** Root → … → current folder. */
  path: VaultFolder[];
  onNavigate: (folderId: string) => void;
}

/** Folder path trail — every segment but the last is clickable. */
export function Breadcrumbs({ path, onNavigate }: BreadcrumbsProps) {
  return (
    <Breadcrumb>
      <BreadcrumbList
        className="!flex-nowrap overflow-x-auto"
        style={{ scrollbarWidth: "none" }}
      >
        {path.map((folder, i) => {
          const isLast = i === path.length - 1;
          const label = i === 0 ? "All Files" : folder.name;
          return (
            <Fragment key={folder.id}>
              {i > 0 && <BreadcrumbSeparator />}
              <BreadcrumbItem>
                {isLast ? (
                  <BreadcrumbPage className="flex items-center gap-1.5">
                    {i === 0 && <HardDrive size={14} />}
                    <span className="max-w-[180px] truncate">{label}</span>
                  </BreadcrumbPage>
                ) : (
                  <BreadcrumbLink asChild>
                    <button
                      type="button"
                      onClick={() => onNavigate(folder.id)}
                      className="flex items-center gap-1.5"
                      style={{ background: "none", border: "none", cursor: "pointer" }}
                    >
                      {i === 0 && <HardDrive size={14} />}
                      <span className="max-w-[180px] truncate">{label}</span>
                    </button>
                  </BreadcrumbLink>
                )}
              </BreadcrumbItem>
            </Fragment>
          );
        })}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
