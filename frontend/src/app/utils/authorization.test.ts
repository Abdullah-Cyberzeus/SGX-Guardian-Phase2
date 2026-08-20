import { describe, expect, it } from "vitest";
import {
  homePathForRole,
  isAdminRole,
  isMemberRole,
  memberCanOpenPath,
  normalizeRole,
} from "./authorization";

describe("normalizeRole", () => {
  it("accepts the three known roles, case- and whitespace-insensitively", () => {
    expect(normalizeRole("owner")).toBe("owner");
    expect(normalizeRole(" Admin ")).toBe("admin");
    expect(normalizeRole("MEMBER")).toBe("member");
  });

  it("returns null for unknown, empty, or missing values", () => {
    expect(normalizeRole("superuser")).toBeNull();
    expect(normalizeRole("")).toBeNull();
    expect(normalizeRole(undefined)).toBeNull();
    expect(normalizeRole(null)).toBeNull();
  });
});

describe("isMemberRole / isAdminRole", () => {
  it("classifies member vs owner/admin correctly", () => {
    expect(isMemberRole("member")).toBe(true);
    expect(isMemberRole("owner")).toBe(false);
    expect(isAdminRole("owner")).toBe(true);
    expect(isAdminRole("admin")).toBe(true);
    expect(isAdminRole("member")).toBe(false);
  });

  it("treats an unrecognized role as neither member nor admin", () => {
    expect(isMemberRole("guest")).toBe(false);
    expect(isAdminRole("guest")).toBe(false);
  });
});

describe("homePathForRole", () => {
  it("sends members to /chats and everyone else to /home", () => {
    expect(homePathForRole("member")).toBe("/chats");
    expect(homePathForRole("owner")).toBe("/home");
    expect(homePathForRole("admin")).toBe("/home");
    expect(homePathForRole(undefined)).toBe("/home");
  });
});

describe("memberCanOpenPath", () => {
  it("allows the member-safe top-level routes", () => {
    for (const path of ["/chats", "/calls", "/contacts", "/storage", "/member-settings", "/notifications"]) {
      expect(memberCanOpenPath(path)).toBe(true);
    }
  });

  it("allows nested chat and storage routes", () => {
    expect(memberCanOpenPath("/chats/abc123")).toBe(true);
    expect(memberCanOpenPath("/storage/folder/nested")).toBe(true);
  });

  it("allows a Circle group chat and a Circle member's direct chat route", () => {
    expect(memberCanOpenPath("/network/circle-1/chat")).toBe(true);
    expect(memberCanOpenPath("/network/circle-1/members/did:guardian:abc/chat")).toBe(true);
  });

  it("rejects admin-only routes", () => {
    for (const path of ["/settings", "/policy", "/keys", "/devices", "/network/circle-1/members"]) {
      expect(memberCanOpenPath(path)).toBe(false);
    }
  });
});
