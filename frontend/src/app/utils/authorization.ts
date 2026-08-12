export type GuardianRole = "owner" | "admin" | "member";

export function normalizeRole(role?: string | null): GuardianRole | null {
  const normalized = role?.trim().toLowerCase();
  return normalized === "owner" || normalized === "admin" || normalized === "member"
    ? normalized
    : null;
}

export function isMemberRole(role?: string | null): boolean {
  return normalizeRole(role) === "member";
}

export function isAdminRole(role?: string | null): boolean {
  const normalized = normalizeRole(role);
  return normalized === "owner" || normalized === "admin";
}

export function homePathForRole(role?: string | null): string {
  return isMemberRole(role) ? "/chats" : "/home";
}

export function memberCanOpenPath(pathname: string): boolean {
  if (
    pathname === "/chats" || pathname.startsWith("/chats/") ||
    pathname === "/calls" ||
    pathname === "/contacts" ||
    pathname === "/storage" || pathname.startsWith("/storage/") ||
    pathname === "/member-settings" ||
    pathname === "/notifications"
  ) return true;

  return /^\/network\/[^/]+\/chat$/.test(pathname)
    || /^\/network\/[^/]+\/members\/[^/]+\/chat$/.test(pathname);
}
