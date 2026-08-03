import { createRoot } from "react-dom/client";
import App from "./app/App.tsx";
import "./styles/index.css";
import { monitoring } from "./app/services/monitoring";

monitoring.init();

window.onerror = (msg, source, lineno, colno, error) => {
  monitoring.capture('js_error', String(msg), {
    stack: error?.stack,
  });
  return false;
};

window.addEventListener('unhandledrejection', (e: PromiseRejectionEvent) => {
  const msg = e.reason instanceof Error ? e.reason.message : String(e.reason ?? 'Unhandled rejection');
  monitoring.capture('js_error', `Unhandled rejection: ${msg}`, {
    stack: e.reason instanceof Error ? e.reason.stack : undefined,
  });
});

createRoot(document.getElementById("root")!).render(<App />);
