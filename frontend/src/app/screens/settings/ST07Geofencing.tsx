import { useState } from "react";
import { PageHeader } from "../../components/PageHeader";
import { Plus, Trash2, MapPin } from "lucide-react";
import { mockGeofenceZones } from "../../data/mockData";

export function ST07Geofencing() {
  const [zones, setZones] = useState(mockGeofenceZones);

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Location & Geofencing" />
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-4">
        {/* Map placeholder */}
        <div
          className="rounded-lg border border-border flex flex-col items-center justify-center gap-3"
          style={{ backgroundColor: "var(--card)", height: "200px" }}
        >
          <MapPin size={32} style={{ color: "var(--primary)" }} />
          <div className="text-center">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              Energy Facility — Bay City, TX
            </p>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              28.9831° N, 96.0253° W
            </p>
          </div>
        </div>

        {/* Add zone button */}
        <button
          className="w-full flex items-center justify-center gap-2 rounded-md transition-opacity active:opacity-80"
          style={{ height: "44px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", border: "none", cursor: "pointer", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)" }}
        >
          <Plus size={16} /> Add Zone
        </button>

        {/* Zone list */}
        <div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>Geofence Zones</p>
          <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
            {zones.map((zone, i) => (
              <div key={zone.id} className="flex items-center gap-3 px-4 py-4" style={{ borderBottom: i < zones.length - 1 ? "1px solid var(--border)" : undefined }}>
                <div className="rounded-full flex items-center justify-center flex-shrink-0" style={{ width: "36px", height: "36px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
                  <MapPin size={16} style={{ color: "var(--primary)" }} />
                </div>
                <div className="flex-1">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{zone.name}</p>
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                    Radius: {zone.radius}m · {zone.lat.toFixed(4)}°N, {Math.abs(zone.lng).toFixed(4)}°W
                  </p>
                </div>
                <div className="flex items-center gap-1">
                  <button style={{ background: "none", border: "none", cursor: "pointer", padding: "8px" }}>
                    <Trash2 size={15} style={{ color: "var(--muted-foreground)" }} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
        </div>
      </div>
    </div>
  );
}
