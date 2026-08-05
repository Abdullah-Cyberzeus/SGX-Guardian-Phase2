import type { DIDDocumentPeerSummary } from "../../services/didService";
import type { CircleTopologyNode } from "./types";

/** Matches a topology node to its published DID Document summary, preferring
 * an exact DID match and falling back to node-name equality. Returns null
 * rather than a fabricated placeholder when nothing matches. */
export function matchDidDocumentPeer(node: CircleTopologyNode, peers: DIDDocumentPeerSummary[]): DIDDocumentPeerSummary | null {
  if (node.did) {
    const byDid = peers.find((peer) => peer.did === node.did);
    if (byDid) return byDid;
  }
  return peers.find((peer) => peer.node_name === node.label) ?? null;
}
