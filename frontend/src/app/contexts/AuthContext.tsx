import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { CYLENIUM_OIDC_CONFIG } from "../config/cylenium";
import { api } from "../services/api";
import {
  CYLENIUM_PKCE_CODE_VERIFIER_KEY,
  startCyleniumOidcRedirect,
} from "../utils/cyleniumAuth";

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
  completeCyleniumLogin: (
    code: string,
    state: string,
    codeVerifier?: string | null,
  ) => Promise<{ error: string | null }>;
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

    api.get<AuthPayload>("/auth/session")
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

  const signIn = async (
    email: string,
    password: string,
  ): Promise<{ error: string | null }> => {
    try {
      const data = await api.post<AuthPayload>("/auth/login", { email, password });
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Login response did not include a bearer token");
      injectToken(next.token);
      setSession(next);
      return { error: null };
    } catch (e: any) {
      return { error: e.message || "Login failed" };
    }
  };

  const signUp = async (
    email: string,
    password: string,
    name: string,
  ): Promise<{ error: string | null }> => {
    try {
      const data = await api.post<AuthPayload>("/auth/signup", { email, password, name });
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
    sessionStorage.setItem(CYLENIUM_RETURN_TO_KEY, returnTo);
    void startCyleniumOidcRedirect();
  };

  const completeCyleniumLogin = async (
    code: string,
    state: string,
    codeVerifier?: string | null,
  ): Promise<{ error: string | null }> => {
    try {
      const body: {
        code: string;
        state: string;
        clientId: string;
        redirectUri: string;
        codeVerifier?: string;
      } = {
        code,
        state,
        clientId: CYLENIUM_OIDC_CONFIG.CYLENIUM_CLIENT_ID,
        redirectUri: CYLENIUM_OIDC_CONFIG.CYLENIUM_REDIRECT_URI,
      };
      if (codeVerifier) body.codeVerifier = codeVerifier;

      const data = await api.post<AuthPayload>("/auth/oidc/cylenium/callback", body);
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Cylenium login response did not include a bearer token");
      injectToken(next.token);
      setSession(next);
      localStorage.setItem("sgx_cylenium_connected", "1");
      return { error: null };
    } catch (e: any) {
      return { error: e.message || "Cylenium login failed" };
    }
  };

  const completeCyleniumSignIn = async (
    code: string,
    state: string,
  ): Promise<{ error: string | null }> => {
    const codeVerifier = sessionStorage.getItem(CYLENIUM_PKCE_CODE_VERIFIER_KEY);
    return completeCyleniumLogin(code, state, codeVerifier);
  };

  const signOut = async () => {
    try {
      await api.post("/auth/logout");
    } catch (e) {
      console.error("Logout error", e);
    }
    injectToken(null);
    setSession(null);
    localStorage.removeItem("sgx_onboarded");
  };

  return (
    <AuthContext.Provider
      value={{
        session,
        user: session?.user ?? null,
        loading,
        signIn,
        signUp,
        startCyleniumSignIn,
        completeCyleniumSignIn,
        completeCyleniumLogin,
        signOut,
      }}
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
