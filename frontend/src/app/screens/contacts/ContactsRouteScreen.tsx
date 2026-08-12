import { useAuth } from "../../contexts/AuthContext";
import { isMemberRole } from "../../utils/authorization";
import { MemberContactsScreen } from "../member/MemberContactsScreen";
import { ContactsListScreen } from "./ContactsListScreen";

/**
 * Keep Seerat's editable administrator address book and the restricted PWA
 * contact roster on the same public route without preloading the wrong API.
 */
export function ContactsRouteScreen() {
  const { session } = useAuth();
  return isMemberRole(session?.user.role)
    ? <MemberContactsScreen />
    : <ContactsListScreen />;
}
