import type { BrowserSignal, MediaType, SignalKind } from "./call.types";

export interface WebRtcCallbacks {
  sendSignal(type: SignalKind, payload: unknown, operationId: string): Promise<void>;
  onRemoteStream(stream: MediaStream): void;
  onConnectionState(state: RTCPeerConnectionState): void;
}

export class WebRtcService {
  private pc?: RTCPeerConnection;
  private local?: MediaStream;
  private mediaInput?: MediaStream;
  private audioContext?: AudioContext;
  private testOscillator?: OscillatorNode;
  private testGain?: GainNode;
  private testToneTimer?: number;
  private restoreMutedAfterTest = false;
  private pendingCandidates: RTCIceCandidateInit[] = [];
  private callbacks?: WebRtcCallbacks;
  private signalChain: Promise<void> = Promise.resolve();
  private iceServers: RTCIceServer[] = [];
  private recovering = false;

  configureIceServers(iceServers: RTCIceServer[]): void { this.iceServers = iceServers; }

  /**
   * Requests the media the caller asked for. If video specifically fails
   * (camera denied/missing/busy) but audio was also requested, the call
   * continues audio-only rather than aborting outright — `actualMedia`
   * reports what was actually captured so the caller can declare that to
   * the backend and let the user know they've been downgraded. A pure
   * video-only request, or an audio failure, still throws: there is no
   * lesser fallback for those.
   */
  async prepareMedia(media: MediaType[]): Promise<{ stream: MediaStream; actualMedia: MediaType[]; warning?: string }> {
    this.close();
    if (!window.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
      throw new Error("Microphone and camera access requires a trusted HTTPS connection (or localhost). Open this Guardian using its HTTPS address and trust its certificate.");
    }
    const tracks: MediaStreamTrack[] = [];
    const inputTracks: MediaStreamTrack[] = [];
    const actualMedia: MediaType[] = [];
    let warning: string | undefined;

    if (media.includes("audio")) {
      const microphone = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
        video: false,
      });
      inputTracks.push(...microphone.getTracks());

      const context = new AudioContext();
      const destination = context.createMediaStreamDestination();
      context.createMediaStreamSource(microphone).connect(destination);
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = "sine";
      oscillator.frequency.value = 660;
      gain.gain.value = 0;
      oscillator.connect(gain).connect(destination);
      oscillator.start();
      this.audioContext = context;
      this.testOscillator = oscillator;
      this.testGain = gain;
      tracks.push(...destination.stream.getAudioTracks());
      actualMedia.push("audio");
    }

    if (media.includes("video")) {
      try {
        const camera = await navigator.mediaDevices.getUserMedia({
          audio: false,
          video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
        });
        inputTracks.push(...camera.getTracks());
        tracks.push(...camera.getVideoTracks());
        actualMedia.push("video");
      } catch (error) {
        if (!actualMedia.includes("audio")) throw error;
        const reason = error instanceof Error ? error.name : "";
        warning = reason === "NotFoundError"
          ? "No camera was found on this device. Continuing with audio only."
          : reason === "NotAllowedError"
            ? "Camera access was denied. Continuing with audio only — allow camera access and restart the call for video."
            : "Camera could not be started. Continuing with audio only.";
      }
    }

    this.mediaInput = new MediaStream(inputTracks);
    this.local = new MediaStream(tracks);
    return { stream: this.local, actualMedia, warning };
  }

  setup(callbacks: WebRtcCallbacks): RTCPeerConnection {
    this.callbacks = callbacks;
    const pc = new RTCPeerConnection({ iceServers: this.iceServers, bundlePolicy: "max-bundle" });
    this.pc = pc;
    this.local?.getTracks().forEach((track) => pc.addTrack(track, this.local!));
    pc.ontrack = ({ streams }) => streams[0] && callbacks.onRemoteStream(streams[0]);
    pc.onconnectionstatechange = () => callbacks.onConnectionState(pc.connectionState);
    pc.onicecandidate = ({ candidate }) => this.sendSignalReliable(
      candidate ? "ice_candidate" : "ice_complete",
      candidate ? candidate.toJSON() : {},
    ).catch((error) => console.error("ICE signaling failed after retries", error));
    return pc;
  }

  async startCaller(): Promise<void> {
    const pc = this.requirePeer();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await this.sendSignalReliable("sdp_offer", { type: offer.type, sdp: offer.sdp });
  }

  async apply(signal: BrowserSignal): Promise<void> {
    if (signal.type === "error") {
      const payload = signal.payload as { message?: string };
      throw new Error(payload?.message || "Remote Guardian rejected the call");
    }
    const pc = this.requirePeer();
    if (signal.type === "sdp_offer") {
      await pc.setRemoteDescription(signal.payload as RTCSessionDescriptionInit);
      await this.flushCandidates();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await this.sendSignalReliable("sdp_answer", { type: answer.type, sdp: answer.sdp });
    } else if (signal.type === "sdp_answer") {
      if (pc.signalingState !== "have-local-offer") return;
      await pc.setRemoteDescription(signal.payload as RTCSessionDescriptionInit);
      await this.flushCandidates();
    } else if (signal.type === "ice_candidate") {
      const candidate = signal.payload as RTCIceCandidateInit;
      if (pc.remoteDescription) await pc.addIceCandidate(candidate);
      else this.pendingCandidates.push(candidate);
    } else if (signal.type === "hangup") this.close();
  }

  setMuted(muted: boolean): void { this.local?.getAudioTracks().forEach((track) => { track.enabled = !muted; }); }
  setCameraEnabled(enabled: boolean): void { this.local?.getVideoTracks().forEach((track) => { track.enabled = enabled; }); }

  async sendTestTone(): Promise<void> {
    if (!this.audioContext || !this.testOscillator || !this.testGain) {
      throw new Error("Audio was not enabled for this call");
    }
    await this.audioContext.resume();
    if (this.testToneTimer) window.clearTimeout(this.testToneTimer);
    const audioTracks = this.local?.getAudioTracks() ?? [];
    this.restoreMutedAfterTest ||= audioTracks.some((track) => !track.enabled);
    audioTracks.forEach((track) => { track.enabled = true; });
    const now = this.audioContext.currentTime;
    this.testOscillator.frequency.cancelScheduledValues(now);
    this.testOscillator.frequency.setValueAtTime(660, now);
    this.testOscillator.frequency.setValueAtTime(880, now + 0.35);
    this.testOscillator.frequency.setValueAtTime(660, now + 0.7);
    this.testGain.gain.cancelScheduledValues(now);
    this.testGain.gain.setValueAtTime(0, now);
    this.testGain.gain.linearRampToValueAtTime(0.18, now + 0.03);
    this.testGain.gain.setValueAtTime(0.18, now + 1.05);
    this.testGain.gain.linearRampToValueAtTime(0, now + 1.15);
    this.testToneTimer = window.setTimeout(() => {
      if (this.testGain && this.audioContext) {
        this.testGain.gain.setValueAtTime(0, this.audioContext.currentTime);
      }
      if (this.restoreMutedAfterTest) {
        audioTracks.forEach((track) => { track.enabled = false; });
      }
      this.restoreMutedAfterTest = false;
      this.testToneTimer = undefined;
    }, 1250);
  }

  async startScreenShare(): Promise<void> {
    const display = await navigator.mediaDevices.getDisplayMedia({ video: true });
    const track = display.getVideoTracks()[0];
    const sender = this.requirePeer().getSenders().find((item) => item.track?.kind === "video");
    if (!sender) throw new Error("No video sender is available");
    const camera = sender.track;
    await sender.replaceTrack(track);
    track.onended = () => sender.replaceTrack(camera ?? null).catch(() => undefined);
  }

  async restartIce(): Promise<void> {
    const pc = this.requirePeer(); pc.restartIce();
    const offer = await pc.createOffer({ iceRestart: true });
    await pc.setLocalDescription(offer);
    await this.sendSignalReliable("sdp_offer", offer);
  }

  async recover(initiate: boolean): Promise<void> {
    if (this.recovering) return;
    this.recovering = true;
    try {
      await this.restartIce();
      await new Promise((resolve) => window.setTimeout(resolve, 4_000));
      if (this.pc?.connectionState === "connected") return;
      this.pc?.close();
      this.pc = undefined;
      this.pendingCandidates = [];
      if (!this.callbacks || !this.local) throw new Error("Call media is unavailable for recovery");
      this.setup(this.callbacks);
      if (initiate) await this.startCaller();
    } finally {
      this.recovering = false;
    }
  }

  /**
   * The SHA-256 DTLS certificate fingerprint this peer connection's own local
   * description is actually using, once negotiation has produced one. Read
   * directly from the SDP `a=fingerprint` line — the same value the backend
   * extracted from this same SDP when it was signaled — so submitting it back
   * at media-ready time lets the backend confirm the live connection matches
   * what was cryptographically committed to, not just what was requested.
   */
  localDtlsFingerprint(): string | undefined {
    const sdp = this.pc?.localDescription?.sdp;
    if (!sdp) return undefined;
    for (const line of sdp.split(/\r?\n/)) {
      const match = /^a=fingerprint:sha-256 (.+)$/i.exec(line.trim());
      if (!match) continue;
      const normalized = match[1].replace(/:/g, "").toLowerCase();
      if (/^[0-9a-f]{64}$/.test(normalized)) return `sha-256 ${normalized}`;
    }
    return undefined;
  }

  async quality(): Promise<Record<string, number | string>> {
    const reports = await this.requirePeer().getStats();
    const result: Record<string, number | string> = {};
    reports.forEach((report) => {
      if (report.type === "candidate-pair" && report.state === "succeeded") result.rtt_ms = Math.round((report.currentRoundTripTime ?? 0) * 1000);
      if (report.type === "inbound-rtp") {
        const lost = Math.max(0, report.packetsLost ?? 0), received = Math.max(0, report.packetsReceived ?? 0);
        result.packet_loss_percent = lost + received ? Number(((lost / (lost + received)) * 100).toFixed(2)) : 0;
        result.jitter_ms = Math.round((report.jitter ?? 0) * 1000);
      }
      if (report.type === "codec") result.codec = report.mimeType ?? "unknown";
    });
    return result;
  }

  async adaptBitrate(report: Record<string, number | string>): Promise<void> {
    const loss = typeof report.packet_loss_percent === "number" ? report.packet_loss_percent : 0;
    const rtt = typeof report.rtt_ms === "number" ? report.rtt_ms : 0;
    const maxBitrate = loss >= 8 || rtt >= 500
      ? 350_000
      : loss >= 3 || rtt >= 250
        ? 800_000
        : 1_800_000;
    const senders = this.requirePeer().getSenders().filter((sender) => sender.track?.kind === "video");
    await Promise.all(senders.map(async (sender) => {
      const parameters = sender.getParameters();
      parameters.encodings = parameters.encodings?.length ? parameters.encodings : [{}];
      parameters.encodings = parameters.encodings.map((encoding) => ({ ...encoding, maxBitrate }));
      await sender.setParameters(parameters);
    }));
  }

  close(): void {
    this.pc?.close(); this.pc = undefined; this.pendingCandidates = [];
    this.signalChain = Promise.resolve();
    this.recovering = false;
    this.local?.getTracks().forEach((track) => track.stop()); this.local = undefined;
    this.mediaInput?.getTracks().forEach((track) => track.stop()); this.mediaInput = undefined;
    if (this.testToneTimer) window.clearTimeout(this.testToneTimer);
    this.testToneTimer = undefined;
    this.restoreMutedAfterTest = false;
    this.testOscillator?.stop(); this.testOscillator = undefined; this.testGain = undefined;
    this.audioContext?.close().catch(() => undefined); this.audioContext = undefined;
  }

  private requirePeer(): RTCPeerConnection { if (!this.pc) throw new Error("WebRTC is not initialized"); return this.pc; }
  private sendSignalReliable(type: SignalKind, payload: unknown): Promise<void> {
    const operationId = typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const send = async () => {
      let lastError: unknown;
      for (const delay of [0, 300, 900, 1800]) {
        if (delay) await new Promise((resolve) => window.setTimeout(resolve, delay));
        try {
          await this.callbacks!.sendSignal(type, payload, operationId);
          return;
        } catch (error) {
          lastError = error;
        }
      }
      throw lastError instanceof Error ? lastError : new Error(`${type} signaling failed`);
    };
    const queued = this.signalChain.then(send);
    this.signalChain = queued.catch(() => undefined);
    return queued;
  }
  private async flushCandidates(): Promise<void> { const pc = this.requirePeer(); for (const item of this.pendingCandidates.splice(0)) await pc.addIceCandidate(item); }
}
