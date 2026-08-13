import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import {
  CYLENIUM_OIDC_CONFIG,
  cyleniumConfigErrorMessage,
  isCyleniumConfigured,
} from "../config/cylenium";
import { api } from "../services/api";
import {
  CYLENIUM_PKCE_CODE_VERIFIER_KEY,
  startCyleniumOidcRedirect,
} from "../utils/cyleniumAuth";
import type { GuardianRole } from "../utils/authorization";
import pwaOnboardingService, { type MemberJoinPayload } from "../services/pwaOnboardingService";
import { membershipRepository } from "../../pwa/db/membershipRepository";

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
  scopes: string[];
  guardianDid?: string;
  guardianFingerprint?: string;
  circleIds: string[];
  browserRegistrationId?: string;
  registrationExpiresAt?: number;
  offline?: boolean;
  [key: string]: any;
}

interface AuthContextValue {
  session: Session | null;
  user: User | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<{ error: string | null; role?: string }>;
  signUp: (email: string, password: string, name: string, role: GuardianRole) => Promise<{ error: string | null; role?: string }>;
  startCyleniumSignIn: (returnTo: string) => void;
  completeCyleniumSignIn: (code: string, state: string) => Promise<{ error: string | null }>;
  completeCyleniumLogin: (
    code: string,
    state: string,
    codeVerifier?: string | null,
  ) => Promise<{ error: string | null }>;
  signOut: () => Promise<void>;
  signOutEverywhere: () => Promise<{ error: string | null }>;
  joinMember: (payload: MemberJoinPayload) => Promise<{ error: string | null; role?: string }>;
  refreshSession: () => Promise<{ error: string | null }>;
  removeBrowserRegistration: () => Promise<{ error: string | null }>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const TOKEN_KEY = "sgx_auth_token";
const CYLENIUM_RETURN_TO_KEY = "sgx_cylenium_return_to";
export const AUTH_NOTICE_KEY = "sgx_auth_notice";

interface AuthPayload {
  token?: string;
  user?: User;
  userId?: string;
  id?: string;
  email?: string;
  name?: string;
  role?: string;
  scopes?: string[];
  guardianDid?: string;
  guardianFingerprint?: string;
  circleIds?: string[];
  browserRegistrationId?: string;
  registrationExpiresAt?: number;
  expiresAt?: number;
  valid?: boolean;
}

interface LoginBypassProbe {
  nodeId?: string;
  hostname?: string;
}

function normalizeSession(payload: AuthPayload, fallbackToken = ""): Session {
  const user = payload.user ?? {
    id: payload.userId ?? payload.id ?? "",
    email: payload.email ?? "",
    name: payload.name,
    role: payload.role,
  };
  return {
    token: payload.token || fallbackToken,
    expiresAt: payload.expiresAt,
    scopes: payload.scopes ?? (Array.isArray(user.scopes) ? user.scopes : []),
    guardianDid: payload.guardianDid,
    guardianFingerprint: payload.guardianFingerprint ?? payload.user?.guardianFingerprint,
    circleIds: payload.circleIds ?? (Array.isArray(payload.user?.circleIds) ? payload.user.circleIds : []),
    browserRegistrationId: payload.browserRegistrationId ?? payload.user?.browserRegistrationId,
    registrationExpiresAt: payload.registrationExpiresAt ?? payload.user?.registrationExpiresAt,
    user,
  };
}

function injectToken(token: string | null, storage: "local" | "session" = "local") {
  api.setToken(token);
  localStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(TOKEN_KEY);
  if (token) {
    (storage === "session" ? sessionStorage : localStorage).setItem(TOKEN_KEY, token);
  }
}

const tokenStorageForRole = (role?: string): "local" | "session" =>
  role?.toLowerCase() === "member" ? "session" : "local";

function makeLoginBypassSession(probe?: LoginBypassProbe): Session {
  const nodeId = probe?.nodeId?.trim() || "guardian-local";
  const hostname = probe?.hostname?.trim() || nodeId;
  return {
    token: "",
    scopes: ["admin:*"],
    circleIds: [],
    user: {
      id: nodeId,
      email: `${hostname.toLowerCase()}@local.guardian`,
      name: hostname,
      role: "owner",
      user_metadata: {
        name: hostname,
        role: "Guardian Admin",
      },
    },
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [initialToken] = useState(() => {
    const token = sessionStorage.getItem(TOKEN_KEY) ?? localStorage.getItem(TOKEN_KEY) ?? "";
    api.setToken(token || null);
    return token;
  });
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (session?.user.role?.toLowerCase() === "member") {
      void membershipRepository.save({
        guardianDid: session.guardianDid || "",
        guardianFingerprint: session.guardianFingerprint,
        circleIds: session.circleIds,
        actorId: session.user.id,
        role: "member",
        browserRegistrationId: session.browserRegistrationId,
        sessionExpiresAt: session.expiresAt,
        registrationExpiresAt: session.registrationExpiresAt,
      });
    }
  }, [session]);

  useEffect(() => {
    const handleUnauthorized = () => {
      sessionStorage.setItem(AUTH_NOTICE_KEY, "Your Guardian session expired or was revoked. Please sign in again.");
      injectToken(null);
      setSession(null);
    };
    window.addEventListener("sgx:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("sgx:unauthorized", handleUnauthorized);
  }, []);

  useEffect(() => {
    let cancelled = false;

    const probeLoginBypass = async () => {
      try {
        const probe = await api.get<LoginBypassProbe>("/node/status");
        if (cancelled) return;
        const bypassSession = makeLoginBypassSession(probe);
        injectToken(null);
        setSession(bypassSession);
      } catch {
        if (!cancelled) {
          injectToken(null);
          try {
            const health = await fetch("/api/v1/health", { cache: "no-store", signal: AbortSignal.timeout(1500) });
            if (health.ok) {
              setSession(null);
            } else {
              throw new Error("Guardian unreachable");
            }
          } catch {
            const cached = await membershipRepository.get().catch(() => undefined);
            const registrationValid = cached?.registrationExpiresAt == null
              || cached.registrationExpiresAt > Math.floor(Date.now() / 1000);
            if (cached && registrationValid && !cancelled) {
              setSession({
                token: "",
                offline: true,
                scopes: [],
                guardianDid: cached.guardianDid,
                guardianFingerprint: cached.guardianFingerprint,
                circleIds: cached.circleIds,
                browserRegistrationId: cached.browserRegistrationId,
                expiresAt: cached.sessionExpiresAt,
                registrationExpiresAt: cached.registrationExpiresAt,
                user: { id: cached.actorId, email: "Offline member", role: "member" },
              });
            } else {
              setSession(null);
            }
          }
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    if (!initialToken) {
      void probeLoginBypass();
      return () => {
        cancelled = true;
      };
    }

    api.get<AuthPayload>("/auth/session")
      .then((data) => {
        if (cancelled) return;
        const next = normalizeSession(data, initialToken);
        injectToken(next.token, tokenStorageForRole(next.user.role));
        setSession(next);
        setLoading(false);
      })
      .catch((error) => {
        console.warn("AuthContext: no active session found.", error.message);
        void probeLoginBypass();
      });
    return () => {
      cancelled = true;
    };
  }, [initialToken]);

  const signIn = async (
    email: string,
    password: string,
  ): Promise<{ error: string | null; role?: string }> => {
    try {
      const data = await api.post<AuthPayload>("/auth/login", { email, password });
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Login response did not include a bearer token");
      injectToken(next.token, tokenStorageForRole(next.user.role));
      setSession(next);
      return { error: null, role: next.user.role };
    } catch (e: any) {
      return { error: e.message || "Login failed" };
    }
  };

  const signUp = async (
    email: string,
    password: string,
    name: string,
    role: GuardianRole,
  ): Promise<{ error: string | null; role?: string }> => {
    try {
      const data = await api.post<AuthPayload>("/auth/signup", { email, password, name, role });
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Signup response did not include a bearer token");
      injectToken(next.token);
      setSession(next);
      localStorage.removeItem("sgx_onboarded");
      return { error: null, role: next.user.role };
    } catch (e: any) {
      return { error: e.message || "Signup failed" };
    }
  };

  const startCyleniumSignIn = (returnTo: string) => {
    if (!isCyleniumConfigured()) {
      console.warn(cyleniumConfigErrorMessage());
      return;
    }
    sessionStorage.setItem(CYLENIUM_RETURN_TO_KEY, returnTo);
    void startCyleniumOidcRedirect();
  };

  const completeCyleniumLogin = async (
    code: string,
    state: string,
    codeVerifier?: string | null,
  ): Promise<{ error: string | null }> => {
    try {
      if (!isCyleniumConfigured()) {
        throw new Error(cyleniumConfigErrorMessage());
      }
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
    await membershipRepository.remove().catch(() => {});
    sessionStorage.removeItem(AUTH_NOTICE_KEY);
    localStorage.removeItem("sgx_onboarded");
  };

  const signOutEverywhere = async (): Promise<{ error: string | null }> => {
    try {
      await api.post("/auth/sessions/revoke-all");
      injectToken(null);
      setSession(null);
      await membershipRepository.remove().catch(() => {});
      sessionStorage.removeItem(AUTH_NOTICE_KEY);
      localStorage.removeItem("sgx_onboarded");
      return { error: null };
    } catch (cause) {
      return { error: cause instanceof Error ? cause.message : "Unable to revoke sessions" };
    }
  };

  const joinMember = async (payload: MemberJoinPayload): Promise<{ error: string | null; role?: string }> => {
    try {
      const data = await pwaOnboardingService.join(payload);
      const next = normalizeSession(data);
      if (!next.token || next.user.role !== "member") {
        throw new Error("Guardian did not issue a valid member session");
      }
      injectToken(next.token, "session");
      setSession(next);
      localStorage.setItem("sgx_onboarded", "1");
      return { error: null, role: next.user.role };
    } catch (cause) {
      return { error: cause instanceof Error ? cause.message : "Unable to join Guardian" };
    }
  };

  const refreshSession = async (): Promise<{ error: string | null }> => {
    try {
      const data = await api.post<AuthPayload>("/auth/session/refresh");
      const next = normalizeSession(data);
      if (!next.token) throw new Error("Refresh response did not include a session token");
      injectToken(next.token, tokenStorageForRole(next.user.role));
      setSession(next);
      return { error: null };
    } catch (cause) {
      return { error: cause instanceof Error ? cause.message : "Unable to refresh session" };
    }
  };

  const removeBrowserRegistration = async (): Promise<{ error: string | null }> => {
    try {
      await api.delete("/pwa/registration");
      injectToken(null);
      setSession(null);
      localStorage.removeItem("sgx_onboarded");
      await membershipRepository.remove();
      return { error: null };
    } catch (cause) {
      return { error: cause instanceof Error ? cause.message : "Unable to remove browser" };
    }
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
        signOutEverywhere,
        joinMember,
        refreshSession,
        removeBrowserRegistration,
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
