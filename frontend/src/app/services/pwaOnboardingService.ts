import api from "./api";

export interface GuardianOnboardingInfo {
  guardianDid: string;
  guardianName: string;
  fingerprint: string;
  fingerprintAlgorithm: string;
  fingerprintBits: number;
  circles: Array<{ id: string; name: string }>;
  internetRequired: boolean;
  multipleGuardianNote: string;
}

export interface MemberInvitePreview {
  valid: boolean;
  circleId: string;
  circleName: string;
  issuerDid: string;
  expiresAt: string;
  role: "member";
  approvalRequired: boolean;
}

export interface MemberJoinPayload {
  name: string;
  email: string;
  password: string;
  inviteToken: string;
  ownerHost?: string;
  acceptedFingerprint: string;
  fingerprintConfirmed: boolean;
}

export interface MemberJoinResult {
  token: string;
  userId: string;
  email: string;
  role: "member";
  scopes: string[];
  guardianDid: string;
  guardianFingerprint: string;
  circleIds: string[];
  browserRegistrationId: string;
  browserMemberDid: string;
  expiresAt: number;
  registrationExpiresAt: number;
  status: "pending" | "active";
  approvalId?: string;
  approvalClaim?: string;
}

export interface MemberApprovalStatus {
  approvalId: string;
  state: "issued" | "pending" | "approved" | "rejected" | "expired" | string;
  circleName: string;
  memberDid: string;
}

export interface AdditionalCircleEnrollment {
  approvalId: string;
  circleId: string;
  circleName: string;
  memberDid: string;
  state: "pending" | "approved" | "rejected" | "expired" | string;
  createdAt: string;
  expiresAt: string;
}

export interface AdditionalCircleJoinResult {
  enrollment: AdditionalCircleEnrollment;
  approvalClaim: string;
}

export const pwaOnboardingService = {
  info: () => api.get<GuardianOnboardingInfo>("/pwa/onboarding"),
  previewInvite: (inviteToken: string, ownerHost?: string) =>
    api.post<MemberInvitePreview>("/pwa/onboarding/invite-preview", { inviteToken, ownerHost }),
  join: (payload: MemberJoinPayload) =>
    api.post<MemberJoinResult>("/pwa/onboarding/join", payload),
  joinAdditionalCircle: (inviteToken: string) =>
    api.post<AdditionalCircleJoinResult>("/pwa/circles/join", { inviteToken }),
  approvalStatus: (approvalId: string, claim: string) =>
    api.get<MemberApprovalStatus>(`/pwa/onboarding/approval/${encodeURIComponent(approvalId)}`, { claim }),
};

export default pwaOnboardingService;
