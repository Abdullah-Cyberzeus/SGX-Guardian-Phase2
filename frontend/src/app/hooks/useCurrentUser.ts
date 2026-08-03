import { useAuth } from "../contexts/AuthContext";

export interface CurrentUser {
  name: string;
  email: string;
  initials: string;
  role: string;
  did: string;
}

/** Derive initials from a display name or email. */
function getInitials(name: string, email: string): string {
  if (name && name.trim().length > 0) {
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return name.trim().substring(0, 2).toUpperCase();
  }
  const localPart = email?.split("@")[0] ?? "U";
  return localPart.substring(0, 2).toUpperCase();
}

/**
 * Generate a deterministic DID from a Supabase user UUID.
 * Produces a realistic did:cervais:0x... string every logged-in user always has.
 */
function generateDID(userId: string): string {
  const hex = userId.replace(/-/g, "");
  // Pad/extend to 64 hex chars to match the expected DID format
  const padded = (hex + hex).substring(0, 64);
  return `did:cervais:0x${padded}`;
}

/**
 * Returns the currently authenticated user's display info
 * (name, email, initials, role, did) sourced from Supabase user_metadata.
 * Falls back to sensible defaults if no session exists.
 */
export function useCurrentUser(): CurrentUser {
  const { user } = useAuth();

  const name: string =
    user?.user_metadata?.name ||
    user?.user_metadata?.full_name ||
    user?.email?.split("@")[0] ||
    "User";

  const email = user?.email ?? "";

  const role: string =
    user?.user_metadata?.role ||
    "Guardian User";

  const initials = getInitials(name, email);

  // Use DID from metadata if set, otherwise derive a deterministic one from the user's UUID
  const did: string =
    user?.user_metadata?.did ||
    (user?.id ? generateDID(user.id) : "");

  return { name, email, initials, role, did };
}