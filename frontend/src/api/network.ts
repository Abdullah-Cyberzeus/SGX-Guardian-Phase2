import { api } from "./http";
import type { Peer } from "../features/calls/call.types";
export const networkApi = {
  peers: () => api<{ peers: Peer[]; total: number }>("/peers"),
  node: () => api<{ nodeId: string }>("/node/status"),
};

