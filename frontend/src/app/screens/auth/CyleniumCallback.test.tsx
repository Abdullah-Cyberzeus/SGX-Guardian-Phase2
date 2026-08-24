import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  search: "",
  storedState: "state-1" as string | null,
  navigate: vi.fn(),
  completeLogin: vi.fn(),
  clearState: vi.fn(),
  replaceLogin: vi.fn(),
}));

vi.mock("react-router", () => ({
  useNavigate: () => mocks.navigate,
  useSearchParams: () => [new URLSearchParams(mocks.search)],
}));

vi.mock("../../contexts/AuthContext", () => ({
  useAuth: () => ({ completeCyleniumLogin: mocks.completeLogin }),
}));

vi.mock("../../utils/cyleniumAuth", () => ({
  CYLENIUM_PKCE_CODE_VERIFIER_KEY: "sgx_cylenium_oidc_pkce_code_verifier",
  clearStoredCyleniumState: mocks.clearState,
  readStoredCyleniumState: () => mocks.storedState,
  replaceWithCyleniumLogin: mocks.replaceLogin,
}));

vi.mock("../../components/CervaisLogo", () => ({ CervaisLogo: () => null }));

import { CyleniumCallback } from "./CyleniumCallback";

let root: Root | undefined;
let container: HTMLDivElement | undefined;

async function renderCallback() {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root!.render(<CyleniumCallback />);
    await Promise.resolve();
    await Promise.resolve();
  });
  return container;
}

beforeEach(() => {
  mocks.search = "?code=auth-code&state=state-1";
  mocks.storedState = "state-1";
  mocks.navigate.mockReset();
  mocks.completeLogin.mockReset().mockResolvedValue({ error: null });
  mocks.clearState.mockReset();
  mocks.replaceLogin.mockReset().mockResolvedValue(undefined);
  sessionStorage.clear();
  localStorage.clear();
});

afterEach(async () => {
  if (root) await act(async () => root!.unmount());
  container?.remove();
  root = undefined;
  container = undefined;
  vi.useRealTimers();
});

describe("Cylenium callback validation", () => {
  it.each([
    ["?state=state-1", "state-1", "did not return an authorization code"],
    ["?code=auth-code", "state-1", "did not return the sign-in state"],
    ["?code=auth-code&state=state-1", null, "could not find the original"],
    ["?code=auth-code&state=other", "state-1", "state could not be verified"],
  ])("fails closed for an invalid response: %s", async (search, storedState, message) => {
    vi.useFakeTimers();
    mocks.search = search;
    mocks.storedState = storedState;
    const view = await renderCallback();

    expect(view.textContent).toContain("Cylenium sign-in failed");
    expect(view.textContent).toContain(message);
    expect(mocks.completeLogin).not.toHaveBeenCalled();
    expect(mocks.clearState).toHaveBeenCalledOnce();

    await act(async () => { await vi.advanceTimersByTimeAsync(2_200); });
    expect(mocks.replaceLogin).toHaveBeenCalledOnce();
  });

  it("lets the user immediately return to the Cylenium login", async () => {
    vi.useFakeTimers();
    mocks.search = "?state=state-1";
    const view = await renderCallback();
    const button = view.querySelector("button")!;
    await act(async () => {
      button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    expect(mocks.replaceLogin).toHaveBeenCalledOnce();
  });
});

describe("Cylenium callback exchange", () => {
  it("exchanges code, state, and PKCE verifier then navigates to a safe route", async () => {
    sessionStorage.setItem("sgx_cylenium_oidc_pkce_code_verifier", "pkce-verifier");
    sessionStorage.setItem("sgx_cylenium_return_to", "/circles/alpha");
    await renderCallback();

    expect(mocks.completeLogin).toHaveBeenCalledWith("auth-code", "state-1", "pkce-verifier");
    expect(mocks.completeLogin).toHaveBeenCalledOnce();
    expect(mocks.clearState).toHaveBeenCalledOnce();
    expect(sessionStorage.getItem("sgx_cylenium_oidc_pkce_code_verifier")).toBeNull();
    expect(sessionStorage.getItem("sgx_cylenium_return_to")).toBeNull();
    expect(mocks.navigate).toHaveBeenCalledWith("/circles/alpha", { replace: true });
  });

  it("blocks external return URLs and defaults to the home route", async () => {
    sessionStorage.setItem("sgx_cylenium_return_to", "//evil.example/steal");
    await renderCallback();
    expect(mocks.navigate).toHaveBeenCalledWith("/home", { replace: true });
  });

  it("shows backend exchange errors without navigating or clearing PKCE", async () => {
    mocks.completeLogin.mockResolvedValue({ error: "OIDC token signature was rejected" });
    sessionStorage.setItem("sgx_cylenium_oidc_pkce_code_verifier", "retry-verifier");
    const view = await renderCallback();

    expect(view.textContent).toContain("OIDC token signature was rejected");
    expect(mocks.clearState).toHaveBeenCalledOnce();
    expect(mocks.navigate).not.toHaveBeenCalled();
    expect(sessionStorage.getItem("sgx_cylenium_oidc_pkce_code_verifier")).toBe("retry-verifier");
  });

  it("ignores a late exchange result after the callback unmounts", async () => {
    let finish!: (value: { error: null }) => void;
    mocks.completeLogin.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    await renderCallback();

    await act(async () => root!.unmount());
    root = undefined;
    await act(async () => {
      finish({ error: null });
      await Promise.resolve();
    });
    expect(mocks.navigate).not.toHaveBeenCalled();
    expect(mocks.clearState).not.toHaveBeenCalled();
  });
});
