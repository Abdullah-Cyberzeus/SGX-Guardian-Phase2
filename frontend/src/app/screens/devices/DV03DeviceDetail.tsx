import { useNavigate } from "react-router";
import { LayoutList } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { EmptyState } from "../../components/EmptyState";

/**
 * Superseded by DV01DevicesList's inline device detail/actions (backed by
 * the real managedDeviceService) — nothing in the app links here anymore.
 * Kept as a redirect-style pointer rather than deleted, since the route is
 * still reachable by a direct URL or an old bookmark.
 */
export function DV03DeviceDetail() {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Device" />
      <EmptyState
        icon={LayoutList}
        heading="Moved to the Devices list"
        subtext="Device details and actions now live inline on the Devices screen."
        ctaLabel="Open Devices"
        ctaAction={() => navigate("/devices")}
      />
    </div>
  );
}
