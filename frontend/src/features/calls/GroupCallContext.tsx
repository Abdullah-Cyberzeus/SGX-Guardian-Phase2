import {
  createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode,
} from "react";
import { groupCallsApi, openGroupSignalSocket } from "../../api/groupCalls";
import type {
  GroupModerationAction, GroupSession, GroupSignal, MediaType,
} from "./call.types";
import { GroupWebRtcService } from "./group-webrtc.service";
import callHistoryService from "../../app/services/callHistoryService";
import { selectActiveGroup } from "./groupCallState";

interface GroupCallValue {
  group?: GroupSession; incoming?: GroupSession; localStream?: MediaStream;
  remoteStreams: Record<string, MediaStream>; error?: string; muted: boolean; cameraEnabled: boolean; localDevice?: string;
  createGroup(memberIds: string[], callAll: boolean, media: MediaType[], title?: string): Promise<void>;
  acceptGroup(): Promise<void>; rejoinGroup(): Promise<void>; declineGroup(): Promise<void>; leaveGroup(): Promise<void>;
  endGroup(): Promise<void>; moderate(action: GroupModerationAction): Promise<void>;
  toggleMute(): void; toggleCamera(): void; shareScreen(): Promise<void>;
}

const offlineGroupError = () => Promise.reject(new Error("Group calls require a live Guardian connection"));
const offlineValue: GroupCallValue = {
  remoteStreams: {}, muted: false, cameraEnabled: false,
  error: "Group calls are unavailable while Guardian is offline",
  createGroup: offlineGroupError, acceptGroup: offlineGroupError, rejoinGroup: offlineGroupError,
  declineGroup: offlineGroupError, leaveGroup: offlineGroupError, endGroup: offlineGroupError,
  moderate: offlineGroupError, toggleMute: () => {}, toggleCamera: () => {}, shareScreen: offlineGroupError,
};
// Root deliberately omits GroupCallProvider offline. Keep cached screens
// functional while ensuring no signaling or media request can be started.
const Context = createContext<GroupCallValue>(offlineValue);

export function GroupCallProvider({ children, localDevice }: { children: ReactNode; localDevice?: string }) {
  const [group, setGroup] = useState<GroupSession>();
  const [groupLocalDevice, setGroupLocalDevice] = useState<string | undefined>(localDevice);
  const [localStream, setLocalStream] = useState<MediaStream>();
  const [remoteStreams, setRemoteStreams] = useState<Record<string, MediaStream>>({});
  const [error, setError] = useState<string>();
  const [muted, setMuted] = useState(false);
  const [cameraEnabled, setCameraEnabled] = useState(true);
  const rtc = useRef(new GroupWebRtcService());
  const signalCursor = useRef(0);
  const pollingSignals = useRef(false);
  const connectedPeers = useRef(new Set<string>());
  const mediaReadySent = useRef(false);
  const lastGroup = useRef<GroupSession | undefined>(undefined);
  // Once this browser leaves/declines/ends a call, never let a late active-call
  // poll resurrect that same session and restart camera/microphone acquisition.
  const locallyClosedGroups = useRef(new Set<string>());
  const refreshSequence = useRef(0);
  const latestAppliedRefresh = useRef(0);
  const startingGroup = useRef(false);
  const localStreamRef = useRef<MediaStream | undefined>(undefined);
  const recoveringLocalMedia = useRef(false);
  const socketConnected = useRef(false);
  const signalApplyChain = useRef(Promise.resolve());
  const effectiveLocalDevice = groupLocalDevice || localDevice;
  const localParticipantState = effectiveLocalDevice ? group?.participants[effectiveLocalDevice]?.state : undefined;

  useEffect(() => {
    localStreamRef.current = localStream;
  }, [localStream]);

  useEffect(() => {
    groupCallsApi.iceServers()
      .then(({ ice_servers }) => rtc.current.configureIceServers(ice_servers))
      .catch((reason) => setError(reason instanceof Error ? reason.message : "ICE configuration failed"));
  }, []);

  const refresh = useCallback(async () => {
    const requestSequence = ++refreshSequence.current;
    const response = await groupCallsApi.active();
    // Polls can overlap. A response older than one already applied must not
    // overwrite newer call state, but a slow newest response is still valid.
    if (requestSequence < latestAppliedRefresh.current) return;
    latestAppliedRefresh.current = requestSequence;
    const localId = response.local_device_id || localDevice;
    setGroupLocalDevice(localId);
    const next = selectActiveGroup(response.groups, localId, locallyClosedGroups.current);
    if (next) lastGroup.current = next;
    if (!next && lastGroup.current && localId) {
      callHistoryService.recordGroup(lastGroup.current, localId);
      lastGroup.current = undefined;
    }
    setGroup(next);
    if (!next) {
      if (startingGroup.current) return;
      rtc.current.close(); localStreamRef.current = undefined; setLocalStream(undefined); setRemoteStreams({}); setError(undefined); return;
    }
    const local = localId ? next.participants[localId] : undefined;
    if (!local || ["kicked", "declined", "left"].includes(local.state)) {
      rtc.current.close(); localStreamRef.current = undefined; setLocalStream(undefined); setRemoteStreams({}); return;
    }
    if (local.state === "joined" && localStreamRef.current && rtc.current.isReadyForPeers()) {
      rtc.current.setAudio(local.audio_allowed && !muted);
      rtc.current.setVideo(local.video_allowed && cameraEnabled);
      for (const participant of Object.values(next.participants)) {
        if (
          participant.device_id !== localId
          && participant.state === "joined"
        ) {
          await rtc.current.ensurePeer(
            participant.device_id,
            (localId ?? "").localeCompare(participant.device_id) < 0,
          );
        } else if (["kicked", "left", "declined"].includes(participant.state)) {
          rtc.current.removePeer(participant.device_id);
          setRemoteStreams((current) => {
            const copy = { ...current }; delete copy[participant.device_id]; return copy;
          });
        }
      }
    }
  }, [cameraEnabled, localDevice, localStream, muted]);

  useEffect(() => {
    let stopped = false;
    const load = () => refresh().catch((reason) => {
      if (!stopped) setError(reason instanceof Error ? reason.message : "Group status failed");
    });
    void load();
    const timer = window.setInterval(load, 1000);
    return () => { stopped = true; window.clearInterval(timer); };
  }, [refresh]);

  useEffect(() => {
    if (!group || !effectiveLocalDevice || !localStream || localParticipantState !== "joined") return;
    rtc.current.configure({
      sendSignal: (target, type, payload, id) =>
        groupCallsApi.signal(group.group_id, target, type, payload, id).then(() => undefined),
      onRemoteStream: (peerId, stream) => setRemoteStreams((current) => ({ ...current, [peerId]: stream })),
      onConnectionState: (peerId, state) => {
        if (state === "connected") connectedPeers.current.add(peerId);
        else connectedPeers.current.delete(peerId);
        const expected = Object.values(group.participants)
          .filter((participant) => participant.device_id !== effectiveLocalDevice && participant.state === "joined").length;
        if (expected > 0 && connectedPeers.current.size >= expected && !mediaReadySent.current) {
          mediaReadySent.current = true;
          groupCallsApi.mediaReady(group.group_id).catch((reason) => setError(reason.message));
        }
      },
    });
    let cancelled = false;
    const applySignal = (signal: GroupSignal) => {
      signalApplyChain.current = signalApplyChain.current.then(async () => {
        if (signal.id <= signalCursor.current) return;
        if (signal.sender_device_id === effectiveLocalDevice) {
          signalCursor.current = Math.max(signalCursor.current, signal.id);
          return;
        }
        await rtc.current.apply(signal);
        signalCursor.current = Math.max(signalCursor.current, signal.id);
      }).catch((reason) => {
        setError(reason instanceof Error ? reason.message : "Group media signaling failed");
      });
    };
    const closeSocket = openGroupSignalSocket(
      group.group_id,
      signalCursor.current,
      applySignal,
      (connected) => { socketConnected.current = connected; },
    );
    const poll = async () => {
      if (cancelled || socketConnected.current || pollingSignals.current) return;
      pollingSignals.current = true;
      try {
        const response = await groupCallsApi.signals(group.group_id, signalCursor.current);
        response.signals.forEach(applySignal);
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : "Group media signaling failed");
      } finally {
        pollingSignals.current = false;
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 1_000);
    const heartbeat = window.setInterval(() => {
      if (!socketConnected.current) {
        groupCallsApi.heartbeat(group.group_id).catch(() => undefined);
      }
    }, 5_000);
    return () => {
      cancelled = true; socketConnected.current = false; closeSocket();
      window.clearInterval(timer); window.clearInterval(heartbeat);
    };
  }, [group?.group_id, effectiveLocalDevice, localParticipantState, localStream]);

  const prepare = async (media: MediaType[]): Promise<MediaType[]> => {
    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        throw new Error("Camera and microphone access requires HTTPS or localhost.");
      }
      const { stream, actualMedia, warning } = await rtc.current.prepare(media);
      localStreamRef.current = stream;
      setLocalStream(stream); setRemoteStreams({}); signalCursor.current = 0;
      connectedPeers.current.clear(); mediaReadySent.current = false;
      if (warning) setError(warning);
      return actualMedia;
    } catch (reason) {
      rtc.current.close();
      localStreamRef.current = undefined;
      setLocalStream(undefined);
      const message = reason instanceof DOMException && reason.name === "NotAllowedError"
        ? "Camera or microphone permission was denied. Allow access in the browser site settings, then try again."
        : reason instanceof Error ? reason.message : "Camera or microphone could not be started.";
      setError(message);
      throw new Error(message);
    }
  };

  useEffect(() => {
    if (
      !group
      || !effectiveLocalDevice
      || localParticipantState !== "joined"
      || localStream
      || startingGroup.current
      || recoveringLocalMedia.current
    ) {
      return;
    }
    recoveringLocalMedia.current = true;
    void prepare(group.requested_media)
      .catch(() => undefined)
      .finally(() => { recoveringLocalMedia.current = false; });
  // `prepare` is intentionally omitted because it is a local async helper;
  // this recovery should run only when the active joined session loses media.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group?.group_id, group?.requested_media, effectiveLocalDevice, localParticipantState, localStream]);

  const createGroup = async (memberIds: string[], callAll: boolean, media: MediaType[], title = "") => {
    setError(undefined); startingGroup.current = true;
    try {
      const actualMedia = await prepare(media);
      const created = await groupCallsApi.create(title, memberIds, callAll, actualMedia);
      setGroup(created.session);
      setGroup(await groupCallsApi.join(created.session.group_id));
    }
    catch (reason) {
      rtc.current.close();
      localStreamRef.current = undefined;
      setLocalStream(undefined);
      throw reason;
    }
    finally { startingGroup.current = false; }
  };
  const acceptGroup = async () => {
    if (!group) return;
    setError(undefined);
    await prepare(group.requested_media);
    setGroup(await groupCallsApi.join(group.group_id));
  };
  const rejoinGroup = async () => {
    if (!group) return;
    setError(undefined);
    await prepare(group.requested_media);
    setGroup(await groupCallsApi.join(group.group_id));
  };
  const declineGroup = async () => {
    if (!group) return;
    const groupId = group.group_id;
    locallyClosedGroups.current.add(groupId);
    latestAppliedRefresh.current = ++refreshSequence.current;
    try {
      const ended = await groupCallsApi.decline(groupId);
      if (effectiveLocalDevice) callHistoryService.recordGroup(ended, effectiveLocalDevice, "declined");
      lastGroup.current = undefined;
      setError(undefined);
      setGroup(undefined);
    } catch (reason) {
      locallyClosedGroups.current.delete(groupId);
      throw reason;
    }
  };
  const leaveGroup = async () => {
    if (!group) return;
    const groupId = group.group_id;
    locallyClosedGroups.current.add(groupId);
    latestAppliedRefresh.current = ++refreshSequence.current;
    try {
      const left = await groupCallsApi.leave(groupId);
      if (effectiveLocalDevice) callHistoryService.recordGroup(left, effectiveLocalDevice);
      lastGroup.current = undefined;
      rtc.current.close();
      localStreamRef.current = undefined;
      connectedPeers.current.clear();
      mediaReadySent.current = false;
      setLocalStream(undefined);
      setRemoteStreams({});
      setError(undefined);
      setGroup(undefined);
    } catch (reason) {
      locallyClosedGroups.current.delete(groupId);
      throw reason;
    }
  };
  const endGroup = async () => {
    if (!group) return;
    const groupId = group.group_id;
    locallyClosedGroups.current.add(groupId);
    latestAppliedRefresh.current = ++refreshSequence.current;
    try {
      const ended = await groupCallsApi.end(groupId);
      if (effectiveLocalDevice) callHistoryService.recordGroup(ended, effectiveLocalDevice);
      lastGroup.current = undefined;
      rtc.current.close(); localStreamRef.current = undefined; setLocalStream(undefined); setRemoteStreams({}); setError(undefined); setGroup(undefined);
    } catch (reason) {
      locallyClosedGroups.current.delete(groupId);
      throw reason;
    }
  };
  const moderate = async (action: GroupModerationAction) => {
    if (group) setGroup(await groupCallsApi.moderate(group.group_id, action));
  };
  const toggleMute = () => {
    const next = !muted; setMuted(next);
    const allowed = !!(group && effectiveLocalDevice && group.participants[effectiveLocalDevice]?.audio_allowed);
    rtc.current.setAudio(allowed && !next);
  };
  const toggleCamera = () => {
    if (!group?.requested_media.includes("video")) return;
    const next = !cameraEnabled; setCameraEnabled(next);
    const allowed = !!(group && effectiveLocalDevice && group.participants[effectiveLocalDevice]?.video_allowed);
    rtc.current.setVideo(allowed && next);
  };
  const incoming = group && effectiveLocalDevice && group.participants[effectiveLocalDevice]?.state === "invited" ? group : undefined;
  const value = useMemo(() => ({
    group, incoming, localStream, remoteStreams, error, muted, cameraEnabled, localDevice: effectiveLocalDevice, createGroup,
    acceptGroup, rejoinGroup, declineGroup, leaveGroup, endGroup, moderate, toggleMute, toggleCamera,
    shareScreen: () => group?.requested_media.includes("video") ? rtc.current.shareScreen() : Promise.resolve(),
  }), [group, incoming, localStream, remoteStreams, error, muted, cameraEnabled, effectiveLocalDevice]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useGroupCall(): GroupCallValue {
  return useContext(Context);
}
