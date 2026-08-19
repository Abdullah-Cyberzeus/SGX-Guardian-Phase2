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
 * Returns the currently authenticated user's display info
 * (name, email, initials, role, and the hosting Guardian DID) sourced from
 * the local authenticated session. The browser account itself has no DID.
 */
export function useCurrentUser(): CurrentUser {
  const { user, session } = useAuth();

  const name: string =
    user?.name ||
    user?.user_metadata?.name ||
    user?.user_metadata?.full_name ||
    user?.email?.split("@")[0] ||
    "User";

  const email = user?.email ?? "";

  const role: string =
    user?.role ||
    user?.user_metadata?.role ||
    "Guardian User";

  const initials = getInitials(name, email);

  // A browser account does not get a DID. It displays the hosting Guardian's
  // existing DID supplied by the authenticated session.
  const did: string =
    session?.guardianDid ||
    user?.user_metadata?.did ||
    "";

  return { name, email, initials, role, did };
}
