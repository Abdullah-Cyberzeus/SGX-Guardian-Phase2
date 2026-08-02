import api from './api';

export interface Policy {
  id: string;
  name: string;
  type: string;
  status: 'active' | 'draft' | 'revoked';
  version: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  signedBy?: string;
  signature?: string;
  rules?: unknown[];
}

export interface SignResponse {
  success: boolean;
  message: string;
  signature: string;
  signedAt: string;
  signedBy: string;
}

export interface VerifyResponse {
  success: boolean;
  policyId: string;
  isValid: boolean;
  verifiedAt: string;
  details: {
    message: string;
    code?: string;
  };
}

/** Response shape for the new safer flow endpoints
 *  (GET/PUT /policy/current and POST /policy/sign-deploy-current).
 *  Backend may include extra fields; we type the ones we actually read. */
export interface CurrentPolicyResponse {
  success?: boolean;
  yaml: string;
  path?: string;
  digest?: string;
  updatedAt?: string;
}

export interface SignDeployResponse {
  success: boolean;
  message?: string;
  stdout?: string;
  stderr?: string;
  signaturePath?: string;
  digest?: string;
  signedAt?: string;
  restartRequired?: boolean;
}

export const policyService = {
  // GET /api/policy - sgx-guardian policy list
  getAll: () => api.get<Policy[]>('/policy'),

  // GET /api/policy/:id
  getById: (id: string) => api.get<Policy>(`/policy/${id}`),

  // POST /api/policy/sign - sgx-guardian policy sign (multipart: policy file, optional key)
  sign: (policy: File, key?: File) => {
    const fd = new FormData();
    fd.append('policy', policy, policy.name);
    if (key) fd.append('key', key, key.name);
    return api.post<{ success: boolean; message: string; stdout: string; stderr: string; restartRequired: boolean; timestamp: string }>('/policy/sign', fd);
  },

  // POST /api/policy/verify - sgx-guardian policy verify (multipart: signed .sig file)
  verifySigned: (signed: File) => {
    const fd = new FormData();
    fd.append('policy', signed, signed.name);
    return api.post<{ success: boolean; message: string; stdout: string; stderr: string; restartRequired: boolean; timestamp: string }>('/policy/verify', fd);
  },

  verify: (policyId: string, signature?: string) =>
    api.post<{ success: boolean; message: string; stdout: string; stderr: string; restartRequired: boolean; timestamp: string }>('/policy/verify', { policyId, signature }),

  // POST /api/policy
  create: (data: { name: string; type?: string; rules?: unknown[] }) =>
    api.post<Policy>('/policy', data),

  // PUT /api/policy/:id
  update: (id: string, data: Partial<Policy>) => api.put<Policy>(`/policy/${id}`, data),

  // DELETE /api/policy/:id
  delete: (id: string) => api.delete<{ success: boolean; message: string }>(`/policy/${id}`),

  // ── Safer "current policy" flow (added by backend May 2026) ────────────
  // GET /api/v1/policy/current — fetch active policy YAML for editor preview
  getCurrent: async (): Promise<CurrentPolicyResponse> => {
    const res = await api.get<{ content: string; source_path: string; version: string; updated_at?: string }>('/policy/current');
    return { yaml: res.content, path: res.source_path, updatedAt: res.updated_at };
  },

  // PUT /api/v1/policy/current — atomic save of edited YAML
  updateCurrent: async (yaml: string): Promise<CurrentPolicyResponse> => {
    const res = await api.put<{ content: string; source_path: string; version: string; updated_at?: string }>('/policy/current', { content: yaml });
    return { yaml: res.content ?? yaml, path: res.source_path, updatedAt: res.updated_at };
  },

  // POST /api/v1/policy/sign-deploy-current — sign saved policy and write policy.sig
  signDeployCurrent: () => api.post<SignDeployResponse>('/policy/sign-deploy-current'),

  // POST /api/v1/policy/verify-deployed — verify deployed policy.sig from disk (no upload)
  verifyDeployed: () => api.post<{ success: boolean; message: string; stdout: string; stderr: string; restartRequired: boolean; timestamp: string }>('/policy/verify-deployed'),

  // GET /api/v1/policy/backup — fetch backup policy YAML
  getBackup: async (): Promise<CurrentPolicyResponse> => {
    const res = await api.get<{ content: string; source_path: string; version: string; updated_at?: string }>('/policy/backup');
    return { yaml: res.content, path: res.source_path, updatedAt: res.updated_at };
  },

  // GET /api/v1/guardian/key/status
  getKeyStatus: () => api.get<{
    exists: boolean;
    privateKeyExists: boolean;
    publicKeyExists: boolean;
    privateKeyPath: string;
    publicKeyPath: string;
    provider: string;
    algorithm: string;
    fingerprint?: string;
  }>('/guardian/key/status'),

  // POST /api/v1/guardian/key/generate
  generateKey: (force = false) => api.post<{
    success: boolean;
    alreadyExists: boolean;
    provider: string;
    algorithm: string;
    stdout: string;
    stderr: string;
    privateKeyPath: string;
    publicKeyPath: string;
    restartRequired: boolean;
    fingerprint?: string;
    backups: { originalPath: string; backupPath: string }[];
  }>('/guardian/key/generate', { force }),
};

export default policyService;
