import { createContext, useContext, type ReactNode } from "react";

type ChatPaneMode = "standalone" | "embedded";

const ChatPaneModeContext = createContext<ChatPaneMode>("standalone");

export function ChatPaneModeProvider({ mode, children }: { mode: ChatPaneMode; children: ReactNode }) {
  return <ChatPaneModeContext.Provider value={mode}>{children}</ChatPaneModeContext.Provider>;
}

export function useChatPaneMode() {
  return useContext(ChatPaneModeContext);
}
