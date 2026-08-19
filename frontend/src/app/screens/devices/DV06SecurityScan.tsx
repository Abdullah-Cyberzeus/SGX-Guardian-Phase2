import { useNavigate } from "react-router";
import { LayoutList } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { EmptyState } from "../../components/EmptyState";

/**
 * Superseded by DV01DevicesList's inline scan action (backed by the real
 * managedDeviceService.startScan/scanStatus) — nothing in the app links
 * here anymore. Kept as a redirect-style pointer rather than deleted,
 * since the route is still reachable by a direct URL or an old bookmark.
 */
export function DV06SecurityScan() {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Security Scan" />
      <EmptyState
        icon={LayoutList}
        heading="Moved to the Devices list"
        subtext="Security scans now run inline from the Devices screen."
        ctaLabel="Open Devices"
        ctaAction={() => navigate("/devices")}
      />
    </div>
  );
}
