import { Shield } from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { EmptyState } from "../../components/EmptyState";

/**
 * Multi-Guardian management (adding/prioritizing multiple physical Guardian
 * devices from one admin console) has no backend support yet — this screen
 * was pure mock display with no working actions. Shows an honest "not
 * available" state instead of fabricated Guardian entries.
 */
export function ST09ManageGuardians() {
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Manage Guardians" />
      <EmptyState
        icon={Shield}
        heading="Not available yet"
        subtext="Managing multiple Guardian devices from one console isn't supported in this build."
      />
    </div>
  );
}
