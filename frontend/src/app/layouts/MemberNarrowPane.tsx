import { useLocation, Outlet } from "react-router";
import { useAuth } from "../contexts/AuthContext";
import { isMemberRole } from "../utils/authorization";
import { MemberBrandedPanel, type MemberBrandedPanelContext } from "../components/member/MemberBrandedPanel";

function contextForPath(pathname: string): MemberBrandedPanelContext {
  if (pathname.startsWith("/calls")) return "calls";
  if (pathname.startsWith("/contacts")) return "contacts";
  if (pathname.startsWith("/storage")) return "files";
  return "settings";
}

/**
 * Constrains a route's content to the same ~380px column as the Chats list
 * pane (MemberChatsLayout) so every member tab sits at the left, next to the
 * icon rail, like WhatsApp Web. Member-only — admin sessions render the
 * route unchanged.
 */
export function MemberNarrowPane() {
  const { session } = useAuth();
  const location = useLocation();
  const memberSession = isMemberRole(session?.user.role);

  if (!memberSession) return <Outlet />;

  return (
    <>
      <div className="h-full md:hidden">
        <Outlet />
      </div>
      <div className="hidden h-full md:flex">
        <div className="w-[380px] shrink-0 border-r border-border">
          <Outlet />
        </div>
        <div className="min-w-0 flex-1">
          <MemberBrandedPanel context={contextForPath(location.pathname)} />
        </div>
      </div>
    </>
  );
}
