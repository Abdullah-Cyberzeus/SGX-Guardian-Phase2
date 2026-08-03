import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { callsApi, openCallSignalSocket, streamCallEvents } from "../../api/calls";
import { networkApi } from "../../api/network";
import type { BrowserSignal, CallSession, MediaType } from "./call.types";
import { WebRtcService } from "./webrtc.service";

interface CallContextValue { call?:CallSession;incoming?:CallSession;localStream?:MediaStream;remoteStream?:MediaStream;peerId?:string;error?:string;muted:boolean;cameraEnabled:boolean;currentDevice?:string;
 startCall(peerId:string,media:MediaType[]):Promise<void>;accept(media?:MediaType[]):Promise<void>;decline():Promise<void>;end():Promise<void>;toggleMute():void;toggleCamera():void;sendTestTone():Promise<void>;shareScreen():Promise<void> }
const Context=createContext<CallContextValue|null>(null);

export function CallProvider({children}:{children:ReactNode}){
 const[call,setCall]=useState<CallSession>();const[incoming,setIncoming]=useState<CallSession>();const[peerId,setPeerId]=useState<string>();const[currentDevice,setCurrentDevice]=useState<string>();
 const[localStream,setLocalStream]=useState<MediaStream>();const[remoteStream,setRemoteStream]=useState<MediaStream>();const[error,setError]=useState<string>();const[muted,setMuted]=useState(false);const[cameraEnabled,setCameraEnabled]=useState(true);
 const rtc=useRef(new WebRtcService());const localNode=useRef("");const caller=useRef(false);const startedOffer=useRef(false);const lastSignal=useRef(0);
 const signalSocketConnected=useRef(false);const signalApplyChain=useRef(Promise.resolve());
 const hydrate=useCallback(async()=>{const[{nodeId},active,ice]=await Promise.all([networkApi.node(),callsApi.active(),callsApi.iceServers()]);rtc.current.configureIceServers(ice.ice_servers);localNode.current=nodeId;setCurrentDevice(nodeId);const current=active.calls[0];setCall(current);if(current)setPeerId(current.initiator_device_id===nodeId?current.receiver_device_id:current.initiator_device_id);setIncoming(current?.state==="offer_received"?current:undefined)},[]);
 useEffect(()=>{hydrate().catch(e=>setError(e instanceof Error?e.message:"Backend unavailable"))},[hydrate]);
 useEffect(()=>{const abort=new AbortController();let retry:number|undefined;const connect=()=>streamCallEvents(abort.signal,message=>{if(!("session" in message)){hydrate().catch(()=>undefined);return}const next=message.session;setCall(next.terminal?undefined:next);setPeerId(next.initiator_device_id===localNode.current?next.receiver_device_id:next.initiator_device_id);setIncoming(next.state==="offer_received"&&next.receiver_device_id===localNode.current?next:undefined);if(next.terminal){rtc.current.close();setLocalStream(undefined);setRemoteStream(undefined)}}).catch(()=>{if(!abort.signal.aborted)retry=window.setTimeout(connect,3000)});connect();return()=>{abort.abort();if(retry)clearTimeout(retry)}},[hydrate]);
 const setup=useCallback((sessionId:string)=>rtc.current.setup({sendSignal:(type,payload,operationId)=>callsApi.signal(sessionId,type,payload,operationId).then(()=>undefined),onRemoteStream:setRemoteStream,onConnectionState:state=>{if(state==="connected")callsApi.mediaReady(sessionId).catch(e=>setError(e.message));if(state==="failed")rtc.current.recover(caller.current).catch(e=>setError(e.message))}}),[]);
 useEffect(()=>{
  if(!call||!["accepted","media_negotiation","connected"].includes(call.state))return;
  let cancelled=false;let offerRetry:number|undefined;let polling=false;
  const startOffer=async()=>{
   if(cancelled||!caller.current||startedOffer.current||call.state==="connected")return;
   startedOffer.current=true;
   try{await rtc.current.startCaller();setError(undefined)}
   catch(e){startedOffer.current=false;setError(e instanceof Error?e.message:"Offer signaling failed");if(!cancelled)offerRetry=window.setTimeout(startOffer,1200)}
  };
  void startOffer();
  const applySignal=(signal:BrowserSignal)=>{
   signalApplyChain.current=signalApplyChain.current.then(async()=>{if(signal.id<=lastSignal.current)return;await rtc.current.apply(signal);lastSignal.current=Math.max(lastSignal.current,signal.id)}).catch(e=>setError(e instanceof Error?e.message:"Signaling failed"));
  };
  const closeSocket=openCallSignalSocket(call.session_id,lastSignal.current,applySignal,connected=>{signalSocketConnected.current=connected});
  const poll=async()=>{
   if(cancelled||signalSocketConnected.current||polling)return;
   polling=true;
   try{
    const{signals}=await callsApi.signals(call.session_id,lastSignal.current);
    signals.forEach(applySignal);
   }catch(e){setError(e instanceof Error?e.message:"Signaling failed")}
   finally{polling=false}
  };
  void poll();
  const timer=window.setInterval(()=>void poll(),500);
  return()=>{cancelled=true;signalSocketConnected.current=false;closeSocket();window.clearInterval(timer);if(offerRetry)window.clearTimeout(offerRetry)}
 },[call?.session_id,call?.state]);
 const startCall=async(target:string,media:MediaType[])=>{setError(undefined);caller.current=true;startedOffer.current=false;lastSignal.current=0;setPeerId(target);const stream=await rtc.current.prepareMedia(media);setLocalStream(stream);try{const result=await callsApi.initiate(target,media);setup(result.session_id);await hydrate()}catch(e){rtc.current.close();setLocalStream(undefined);throw e}};
 const accept=async(media=incoming?.requested_media??["audio"] as MediaType[])=>{if(!incoming)return;setPeerId(incoming.initiator_device_id);setError(undefined);caller.current=false;lastSignal.current=0;const stream=await rtc.current.prepareMedia(media);setLocalStream(stream);setup(incoming.session_id);await callsApi.accept(incoming.session_id,media);setIncoming(undefined);await hydrate()};
 const decline=async()=>{if(incoming)await callsApi.reject(incoming.session_id);setIncoming(undefined)};const end=async()=>{if(call)await callsApi.end(call.session_id);rtc.current.close();setCall(undefined);setLocalStream(undefined);setRemoteStream(undefined)};
 const toggleMute=()=>{const next=!muted;setMuted(next);rtc.current.setMuted(next)};const toggleCamera=()=>{const next=!cameraEnabled;setCameraEnabled(next);rtc.current.setCameraEnabled(next)};
 const value=useMemo(()=>({call,incoming,peerId,localStream,remoteStream,error,muted,cameraEnabled,currentDevice,startCall,accept,decline,end,toggleMute,toggleCamera,sendTestTone:()=>rtc.current.sendTestTone(),shareScreen:()=>rtc.current.startScreenShare()}),[call,incoming,peerId,localStream,remoteStream,error,muted,cameraEnabled,currentDevice]);return <Context.Provider value={value}>{children}</Context.Provider>;
}
export function useCall(){const value=useContext(Context);if(!value)throw new Error("useCall must be inside CallProvider");return value}

