import api from './api';

export interface TransportInterface {
  name: string;
  transport: string;
  priority: number;
  status: string;
  ip: string | null;
  available: boolean;
}

export interface ActiveTransport {
  name: string;
  transport: string;
}

export interface TransportListResponse {
  node: string;
  interfaces: TransportInterface[];
  active: ActiveTransport | null;
  lock: string | null;
}

export interface TransportStatusResponse {
  node: string;
  active: ActiveTransport | null;
  lock: string | null;
}

export interface TransportLockResponse {
  ok: boolean;
  node: string;
  lock: string | null;
  message: string;
}

export const transportService = {
  // GET /api/v1/transport/list
  getList: (node?: string) =>
    api.get<TransportListResponse>('/transport/list', node ? { node } : undefined),

  // GET /api/v1/transport/status
  getStatus: (node?: string) =>
    api.get<TransportStatusResponse>('/transport/status', node ? { node } : undefined),

  // POST /api/v1/transport/lock
  lock: (node: string, interfaceName: string) =>
    api.post<TransportLockResponse>('/transport/lock', { node, interfaceName }),

  // POST /api/v1/transport/unlock
  unlock: (node: string) =>
    api.post<TransportLockResponse>('/transport/unlock', { node }),
};

export default transportService;
