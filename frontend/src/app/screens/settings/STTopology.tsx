import { useNavigate } from "react-router";
import { Waypoints } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { EmptyState } from "../../components/EmptyState";

/**
 * Legacy radial topology canvas — its node data was entirely mock-shaped
 * (fabricated scores/IPs, a hardcoded "secondary guardian") and nothing in
 * the app links here anymore. Superseded by the real, DID-backed topology
 * at /home/topology (HM03NetworkTopology / CircleLiveTopology). Kept as a
 * pointer rather than deleted since the route is still reachable directly.
 */
export function STTopology() {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Network Topology" />
      <EmptyState
        icon={Waypoints}
        heading="Moved to Home"
        subtext="The live network topology now lives on the Home tab."
        ctaLabel="Open Topology"
        ctaAction={() => navigate("/home/topology")}
      />
    </div>
  );
}
