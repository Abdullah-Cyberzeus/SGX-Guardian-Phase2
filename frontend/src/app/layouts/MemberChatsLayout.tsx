import { Outlet, useLocation } from "react-router";
import { useAuth } from "../contexts/AuthContext";
import { isMemberRole } from "../utils/authorization";
import { ChatPaneModeProvider } from "../contexts/ChatPaneModeContext";
import { ChatsListScreen } from "../screens/chat/ChatsListScreen";
import { ChatEmptyState } from "../components/chat/ChatEmptyState";

export function MemberChatsLayout() {
  const { session } = useAuth();
  const location = useLocation();
  const memberSession = isMemberRole(session?.user.role);

  if (!memberSession) return <Outlet />;

  const hasSelection = location.pathname !== "/chats" && location.pathname !== "/chats/";

  return (
    <>
      <div className="h-full md:hidden">
        <Outlet />
      </div>
      <div className="hidden h-full md:flex">
        <div className="w-[380px] shrink-0 border-r border-border">
          <ChatsListScreen compact />
        </div>
        <div className="min-w-0 flex-1">
          {hasSelection ? (
            <ChatPaneModeProvider mode="embedded">
              <Outlet />
            </ChatPaneModeProvider>
          ) : (
            <ChatEmptyState />
          )}
        </div>
      </div>
    </>
  );
}
