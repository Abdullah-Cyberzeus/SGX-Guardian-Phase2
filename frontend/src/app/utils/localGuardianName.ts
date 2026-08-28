export interface LocalGuardianIdentity {
  id?: string;
  nodeId?: string;
  deviceId?: string;
  name?: string;
  hostname?: string;
}

function normalize(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

export function localGuardianDeviceName(guardian?: LocalGuardianIdentity | null): string | null {
  const name = String(guardian?.deviceId || guardian?.name || "").trim();
  return name || null;
}

export function isLocalGuardianNode(node: unknown, guardian?: LocalGuardianIdentity | null): boolean {
  const candidate = normalize(node);
  if (!candidate) return false;
  return [guardian?.nodeId, guardian?.id, guardian?.deviceId, guardian?.name, guardian?.hostname]
    .map(normalize)
    .some((value) => value && value === candidate);
}

export function displayLocalGuardianNode(node: string, guardian?: LocalGuardianIdentity | null): string {
  if (!isLocalGuardianNode(node, guardian)) return node;
  return localGuardianDeviceName(guardian) || node;
}
