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
  expiresAt: number;
  registrationExpiresAt: number;
}

export const pwaOnboardingService = {
  info: () => api.get<GuardianOnboardingInfo>("/pwa/onboarding"),
  previewInvite: (inviteToken: string, ownerHost?: string) =>
    api.post<MemberInvitePreview>("/pwa/onboarding/invite-preview", { inviteToken, ownerHost }),
  join: (payload: MemberJoinPayload) =>
    api.post<MemberJoinResult>("/pwa/onboarding/join", payload),
};

export default pwaOnboardingService;
