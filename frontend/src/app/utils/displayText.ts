export function guardianDisplayText(value: unknown): string {
  return String(value ?? "")
    .replace(/suricata\s*:\s*sid/gi, "Guardian signature")
    .replace(/nebula0/gi, "Guardian Mesh interface")
    .replace(/suricata/gi, "Guardian")
    .replace(/\bnebula\b/gi, "Guardian Mesh")
    .replace(/\bnmap\b/gi, "Guardian")
    .replace(/\btest\b/gi, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}
