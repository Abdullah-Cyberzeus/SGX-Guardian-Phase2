import type { GroupSignal, MediaType, SignalKind } from "./call.types";

interface GroupRtcCallbacks {
  sendSignal(target: string, type: SignalKind, payload: unknown, operationId: string): Promise<void>;
  onRemoteStream(peerId: string, stream: MediaStream): void;
  onConnectionState(peerId: string, state: RTCPeerConnectionState): void;
}

export class GroupWebRtcService {
  private peers = new Map<string, RTCPeerConnection>();
  private pending = new Map<string, RTCIceCandidateInit[]>();
  private signalChains = new Map<string, Promise<void>>();
  private local?: MediaStream;
  private input?: MediaStream;
  private callbacks?: GroupRtcCallbacks;
  private fallbackAudioContexts: AudioContext[] = [];
  private iceServers: RTCIceServer[] = [];
  private initiators = new Map<string, boolean>();
  private recoveryTimers = new Map<string, number>();
  private recoveryAttempts = new Map<string, number>();

  configureIceServers(iceServers: RTCIceServer[]): void {
    this.iceServers = iceServers;
  }

  async prepare(media: MediaType[]): Promise<MediaStream> {
    this.close();
    const tracks: MediaStreamTrack[] = [];
    const inputs: MediaStreamTrack[] = [];
    if (media.includes("audio")) {
      const microphone = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: false,
      });
      tracks.push(...microphone.getAudioTracks());
      inputs.push(...microphone.getTracks());
    }
    if (media.includes("video")) {
      const camera = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
      });
      tracks.push(...camera.getVideoTracks());
      inputs.push(...camera.getTracks());
    }
    this.input = new MediaStream(inputs);
    this.local = new MediaStream(tracks);
    return this.local;
  }

  configure(callbacks: GroupRtcCallbacks): void {
    this.callbacks = callbacks;
  }

  isReadyForPeers(): boolean {
    return Boolean(this.callbacks && this.local);
  }

  async ensurePeer(peerId: string, initiate: boolean): Promise<void> {
    const existing = this.peers.get(peerId);
    if (existing && !["failed", "closed"].includes(existing.connectionState)) return;
    if (existing) this.removePeer(peerId);
    if (!this.callbacks || !this.local) throw new Error("Group media is not prepared");
    const pc = new RTCPeerConnection({ iceServers: this.iceServers, bundlePolicy: "max-bundle" });
    this.peers.set(peerId, pc);
    this.initiators.set(peerId, initiate);
    this.pending.set(peerId, []);
    this.local.getTracks().forEach((track) => pc.addTrack(track, this.local!));
    pc.ontrack = ({ streams }) => streams[0] && this.callbacks!.onRemoteStream(peerId, streams[0]);
    pc.onconnectionstatechange = () => {
      this.callbacks!.onConnectionState(peerId, pc.connectionState);
      this.handleRecovery(peerId, pc.connectionState);
    };
    pc.onicecandidate = ({ candidate }) => {
      void this.sendReliable(
        peerId,
        candidate ? "ice_candidate" : "ice_complete",
        candidate ? candidate.toJSON() : {},
      );
    };
    if (initiate) {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await this.sendReliable(peerId, "sdp_offer", { type: offer.type, sdp: offer.sdp });
    }
  }

  async apply(signal: GroupSignal): Promise<void> {
    const peerId = signal.sender_device_id;
    await this.ensurePeer(peerId, false);
    const pc = this.peers.get(peerId)!;
    if (signal.type === "sdp_offer") {
      await pc.setRemoteDescription(signal.payload as RTCSessionDescriptionInit);
      await this.flush(peerId);
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await this.sendReliable(peerId, "sdp_answer", { type: answer.type, sdp: answer.sdp });
    } else if (signal.type === "sdp_answer") {
      await pc.setRemoteDescription(signal.payload as RTCSessionDescriptionInit);
      await this.flush(peerId);
    } else if (signal.type === "ice_candidate") {
      const candidate = signal.payload as RTCIceCandidateInit;
      if (pc.remoteDescription) await pc.addIceCandidate(candidate);
      else this.pending.get(peerId)!.push(candidate);
    }
  }

  setAudio(enabled: boolean): void {
    this.local?.getAudioTracks().forEach((track) => { track.enabled = enabled; });
  }

  setVideo(enabled: boolean): void {
    this.local?.getVideoTracks().forEach((track) => { track.enabled = enabled; });
  }

  async shareScreen(): Promise<void> {
    const display = await navigator.mediaDevices.getDisplayMedia({ video: true });
    const track = display.getVideoTracks()[0];
    const replacements = [...this.peers.values()].map(async (pc) => {
      const sender = pc.getSenders().find((item) => item.track?.kind === "video");
      if (sender) await sender.replaceTrack(track);
    });
    await Promise.all(replacements);
    track.onended = () => {
      const camera = this.local?.getVideoTracks()[0] ?? null;
      this.peers.forEach((pc) => {
        pc.getSenders()
          .find((item) => item.track?.kind === "video")
          ?.replaceTrack(camera)
          .catch(() => undefined);
      });
    };
  }

  removePeer(peerId: string): void {
    const timer = this.recoveryTimers.get(peerId);
    if (timer) window.clearTimeout(timer);
    this.recoveryTimers.delete(peerId);
    this.peers.get(peerId)?.close();
    this.peers.delete(peerId);
    this.pending.delete(peerId);
    this.signalChains.delete(peerId);
    this.recoveryAttempts.delete(peerId);
  }

  close(): void {
    this.peers.forEach((peer) => peer.close());
    this.peers.clear(); this.pending.clear(); this.signalChains.clear();
    this.recoveryTimers.forEach((timer) => window.clearTimeout(timer));
    this.recoveryTimers.clear(); this.recoveryAttempts.clear(); this.initiators.clear();
    this.local?.getTracks().forEach((track) => track.stop()); this.local = undefined;
    this.input?.getTracks().forEach((track) => track.stop()); this.input = undefined;
    this.callbacks = undefined;
    this.fallbackAudioContexts.forEach((context) => context.close().catch(() => undefined));
    this.fallbackAudioContexts = [];
  }

  private sendReliable(target: string, type: SignalKind, payload: unknown): Promise<void> {
    const operationId = typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const previous = this.signalChains.get(target) ?? Promise.resolve();
    const task = previous.then(async () => {
      let failure: unknown;
      for (const delay of [0, 300, 900, 1800]) {
        if (delay) await new Promise((resolve) => window.setTimeout(resolve, delay));
        try { await this.callbacks!.sendSignal(target, type, payload, operationId); return; }
        catch (error) { failure = error; }
      }
      throw failure instanceof Error ? failure : new Error("Group signaling failed");
    });
    this.signalChains.set(target, task.catch(() => undefined));
    return task;
  }

  private async flush(peerId: string): Promise<void> {
    const pc = this.peers.get(peerId)!;
    for (const candidate of this.pending.get(peerId)?.splice(0) ?? []) {
      await pc.addIceCandidate(candidate);
    }
  }

  private handleRecovery(peerId: string, state: RTCPeerConnectionState): void {
    if (state === "connected") {
      const timer = this.recoveryTimers.get(peerId);
      if (timer) window.clearTimeout(timer);
      this.recoveryTimers.delete(peerId);
      this.recoveryAttempts.delete(peerId);
      return;
    }
    if (!["disconnected", "failed"].includes(state) || this.recoveryTimers.has(peerId)) return;
    const delay = state === "disconnected" ? 3_000 : 500;
    const timer = window.setTimeout(() => {
      this.recoveryTimers.delete(peerId);
      void this.recover(peerId);
    }, delay);
    this.recoveryTimers.set(peerId, timer);
  }

  private async recover(peerId: string): Promise<void> {
    const pc = this.peers.get(peerId);
    if (!pc || pc.connectionState === "connected") return;
    const attempts = (this.recoveryAttempts.get(peerId) ?? 0) + 1;
    this.recoveryAttempts.set(peerId, attempts);
    const initiate = this.initiators.get(peerId) ?? false;
    try {
      if (attempts <= 2 && initiate) {
        pc.restartIce();
        const offer = await pc.createOffer({ iceRestart: true });
        await pc.setLocalDescription(offer);
        await this.sendReliable(peerId, "sdp_offer", { type: offer.type, sdp: offer.sdp });
      } else {
        this.removePeer(peerId);
        await this.ensurePeer(peerId, initiate);
      }
    } catch {
      this.removePeer(peerId);
      await this.ensurePeer(peerId, initiate).catch(() => undefined);
    }
  }
}
