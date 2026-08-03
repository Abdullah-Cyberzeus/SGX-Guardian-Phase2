import type { ReactNode } from "react";
import { Mic, MicOff, Video, VideoOff, Volume2, VolumeX, PhoneOff } from "lucide-react";
import { Button } from "../ui/button";
import { cn } from "../ui/utils";
import type { CallMode } from "./types";

interface CallControlsProps {
  mode: CallMode;
  muted: boolean;
  cameraOff: boolean;
  speakerOn: boolean;
  disabled?: boolean;
  onToggleMute: () => void;
  onToggleCamera: () => void;
  onToggleSpeaker: () => void;
  onEnd: () => void;
}

function ControlButton({
  label,
  active,
  disabled,
  onClick,
  children,
}: {
  label: string;
  active?: boolean;
  disabled?: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-1.5">
      <Button
        type="button"
        variant="secondary"
        size="icon"
        aria-label={label}
        aria-pressed={active}
        disabled={disabled}
        onClick={onClick}
        className={cn(
          "h-14 w-14 rounded-full border border-border [&_svg]:size-6",
          active
            ? "bg-foreground text-background hover:bg-foreground/90"
            : "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        )}
      >
        {children}
      </Button>
      <span className="text-[11px] text-muted-foreground">{label}</span>
    </div>
  );
}

/** Bottom control row for an active call — mute, camera, speaker, hang up. */
export function CallControls({
  mode,
  muted,
  cameraOff,
  speakerOn,
  disabled,
  onToggleMute,
  onToggleCamera,
  onToggleSpeaker,
  onEnd,
}: CallControlsProps) {
  return (
    <div className="flex items-start justify-center gap-4">
      <ControlButton label={muted ? "Unmute" : "Mute"} active={muted} disabled={disabled} onClick={onToggleMute}>
        {muted ? <MicOff /> : <Mic />}
      </ControlButton>

      {mode === "video" && (
        <ControlButton
          label={cameraOff ? "Start video" : "Stop video"}
          active={cameraOff}
          disabled={disabled}
          onClick={onToggleCamera}
        >
          {cameraOff ? <VideoOff /> : <Video />}
        </ControlButton>
      )}

      <ControlButton
        label={speakerOn ? "Speaker" : "Muted"}
        active={speakerOn}
        disabled={disabled}
        onClick={onToggleSpeaker}
      >
        {speakerOn ? <Volume2 /> : <VolumeX />}
      </ControlButton>

      <div className="flex flex-col items-center gap-1.5">
        <Button
          type="button"
          variant="destructive"
          size="icon"
          aria-label="End call"
          onClick={onEnd}
          className="h-14 w-14 rounded-full [&_svg]:size-6"
        >
          <PhoneOff />
        </Button>
        <span className="text-[11px] text-muted-foreground">End</span>
      </div>
    </div>
  );
}
