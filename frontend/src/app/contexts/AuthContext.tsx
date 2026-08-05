import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api } from "../services/api";

export interface User {
  id: string;
  email: string;
  name?: string;
  role?: string;
  [key: string]: any;
}

export interface Session {
  user: User;
  token: string;
  expiresAt?: number;
  [key: string]: any;
}

interface AuthContextValue {
  session: Session | null;
  user: User | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<{ error: string | null }>;
  signUp: (email: string, password: string, name: string) => Promise<{ error: string | null }>;
  startCyleniumSignIn: (returnTo: string) => void;
  completeCyleniumSignIn: (code: string, state: string) => Promise<{ error: string | null }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const TOKEN_KEY = "sgx_auth_token";
const CYLENIUM_RETURN_TO_KEY = "sgx_cylenium_return_to";

interface AuthPayload {
  token?: string;
  user?: User;
  userId?: string;
  id?: string;
  email?: string;
  name?: string;
  role?: string;
  expiresAt?: number;
  valid?: boolean;
}

function normalizeSession(payload: AuthPayload, fallbackToken = ""): Session {
  return {
    token: payload.token || fallbackToken,
    expiresAt: payload.expiresAt,
    user: payload.user ?? {
      id: payload.userId ?? payload.id ?? "",
      email: payload.email ?? "",
      name: payload.name,
      role: payload.role,
    },
  };
}

function injectToken(token: string | null) {
  api.setToken(token);
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  // Restore before protected children mount, so their first requests are authenticated.
  const [initialToken] = useState(() => {
    const token = localStorage.getItem(TOKEN_KEY) ?? "";
    api.setToken(token || null);
    return token;
  });
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleUnauthorized = () => {
      injectToken(null);
      setSession(null);
    };
    window.addEventListener("sgx:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("sgx:unauthorized", handleUnauthorized);
  }, []);

  useEffect(() => {
    if (!initialToken) {
      setSession(null);
      setLoading(false);
      return;
    }
    // Restore token from localStorage before session check
    // Validate session with backend
    api.get<AuthPayload>('/auth/session')
      .then((data) => {
        const next = normalizeSession(data, initialToken);
        injectToken(next.token);
        setSession(next);
        setLoading(false);
      })
      .catch((error) => {
        console.warn("AuthContext: no active session found.", error.message);
        injectToken(null);
        setSession(null);
        setLoading(false);
      });
  }, [initialToken]);

  const signIn = async (email: string, password: string): Promise<{ error: string | null }> => {
    try {
      const data = await api.post<AuthPayload>('/auth/login', { email, password });
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Login response did not include a bearer token");
      injectToken(next.token);
      setSession(next);
      return { error: null };
    } catch (e: any) {
      return { error: e.message || "Login failed" };
    }
  };

  const signUp = async (email: string, password: string, name: string): Promise<{ error: string | null }> => {
    try {
      const data = await api.post<AuthPayload>('/auth/signup', { email, password, name });
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Signup response did not include a bearer token");
      injectToken(next.token);
      setSession(next);
      localStorage.removeItem("sgx_onboarded");
      return { error: null };
    } catch (e: any) {
      return { error: e.message || "Signup failed" };
    }
  };

  const startCyleniumSignIn = (returnTo: string) => {
    const redirectUri = `${window.location.origin}/auth/cylenium/callback`;
    sessionStorage.setItem(CYLENIUM_RETURN_TO_KEY, returnTo);
    window.location.assign(api.publicUrl('/auth/cylenium/login', { redirectUri, returnTo }));
  };

  const completeCyleniumSignIn = async (code: string, state: string): Promise<{ error: string | null }> => {
    try {
      const data = await api.request<AuthPayload>('/auth/cylenium/callback', {
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({
          code,
          state,
          redirectUri: `${window.location.origin}/auth/cylenium/callback`,
        }),
      });
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Cylenium login response did not include a bearer token");
      injectToken(next.token);
      setSession(next);
      localStorage.setItem("sgx_cylenium_connected", "1");
      return { error: null };
    } catch (e: any) {
      return { error: e.message || "Cylenium sign-in failed" };
    }
  };

  const signOut = async () => {
    try {
      await api.post('/auth/logout');
    } catch (e) {
      console.error("Logout error", e);
    }
    injectToken(null);
    setSession(null);
    localStorage.removeItem("sgx_onboarded");
  };

  return (
    <AuthContext.Provider
      value={{ session, user: session?.user ?? null, loading, signIn, signUp, startCyleniumSignIn, completeCyleniumSignIn, signOut }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
