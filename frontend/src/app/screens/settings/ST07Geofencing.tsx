import { useNavigate } from "react-router";
import { MapPin } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { EmptyState } from "../../components/EmptyState";

/**
 * This settings-tab zone list was pure mock display — no onClick on Add/
 * Delete, a hardcoded fake location. Real geofence zone management (create/
 * edit/delete, live location, RF capture, alerts) already exists in
 * EnterpriseTopology (the Network Topology screen, backed by the real
 * geofence.rs API). Kept as a pointer rather than deleted, since the route
 * is still reachable from Settings.
 */
export function ST07Geofencing() {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Location & Geofencing" />
      <EmptyState
        icon={MapPin}
        heading="Moved to Network Topology"
        subtext="Manage geofence zones from the live map on the Home tab."
        ctaLabel="Open Topology"
        ctaAction={() => navigate("/home/topology")}
      />
    </div>
  );
}
