import { useEffect, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { AlertTriangle, Camera, Check, ChevronRight, Clock, Copy, Hash, Loader2, QrCode, Upload } from "lucide-react";
import jsQR from "jsqr";
import { ProgressDots } from "../../components/ProgressDots";
import { deviceService, type PairingCodeResponse, type PairResponse } from "../../services/deviceService";

type Mode = "choose" | "serial" | "qr" | "camera" | "review" | "code" | "proof";
type SignupMethod = "serial" | "qr-upload" | "qr-camera";

type BarcodeDetectorResult = { rawValue: string };
type BarcodeDetectorLike = {
  detect: (source: HTMLImageElement | HTMLCanvasElement | HTMLVideoElement | ImageBitmap) => Promise<BarcodeDetectorResult[]>;
};
type BarcodeDetectorConstructor = new (options?: { formats?: string[] }) => BarcodeDetectorLike;

const ONBOARDING_SERIAL_KEY = "sgx_onboarding_serial";
const ONBOARDING_METHOD_KEY = "sgx_onboarding_method";
const ONBOARDING_PAIR_RESPONSE_KEY = "sgx_onboarding_pair_response";
const MAX_QR_DECODE_SIZE = 2400;
const MIN_QR_DECODE_SIZE = 900;

function getBarcodeDetector(): BarcodeDetectorLike | null {
  const Detector = (window as unknown as { BarcodeDetector?: BarcodeDetectorConstructor }).BarcodeDetector;
  return Detector ? new Detector({ formats: ["qr_code"] }) : null;
}

function normalizeSerial(value: string): string | null {
  const cleaned = value.trim().replace(/\s+/g, "").replace(/_/g, "-").toUpperCase();
  if (/^[A-Z0-9-]{6,64}$/.test(cleaned)) return cleaned;
  return null;
}

function extractSerialFromQr(rawValue: string): string | null {
  const raw = rawValue.trim();
  if (!raw) return null;

  const fromDirect = normalizeSerial(raw);
  if (fromDirect) return fromDirect;

  try {
    const parsed = JSON.parse(raw);
    const queue: unknown[] = [parsed];
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item || typeof item !== "object") continue;
      for (const [key, value] of Object.entries(item as Record<string, unknown>)) {
        if (typeof value === "string" && /serial|serialNumber|deviceSerial|sn/i.test(key)) {
          const serial = normalizeSerial(value);
          if (serial) return serial;
        }
        if (value && typeof value === "object") queue.push(value);
      }
    }
  } catch {
    // QR payload is often plain text or a URL.
  }

  try {
    const url = new URL(raw);
    for (const key of ["serial", "serialNumber", "serial_number", "deviceSerial", "sn", "code"]) {
      const value = url.searchParams.get(key);
      if (!value) continue;
      const serial = normalizeSerial(value);
      if (serial) return serial;
    }
  } catch {
    // Not a URL payload.
  }

  const patterns = [
    /(?:serial(?:Number)?|deviceSerial|sn)["'=:\s]+([A-Z0-9][A-Z0-9\-_]{5,})/i,
    /\b(?:GX|SGX)[A-Z0-9\-_]{4,}\b/i,
    /\b[A-Z]{2,5}[-_]?\d{3,5}[-_]?[A-Z0-9\-_]{3,}\b/i,
    /\b\d{6,}\b/,
  ];

  for (const pattern of patterns) {
    const match = raw.match(pattern);
    const value = match?.[1] ?? match?.[0];
    if (!value) continue;
    const serial = normalizeSerial(value);
    if (serial) return serial;
  }

  return null;
}

function loadImage(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      URL.revokeObjectURL(url);
      resolve(image);
    };
    image.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("Unable to read that QR image."));
    };
    image.src = url;
  });
}

async function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(new Error("Unable to read that file."));
    reader.readAsText(file);
  });
}

function isImageFile(file: File) {
  return file.type.startsWith("image/") || /\.(avif|bmp|gif|jpe?g|png|webp)$/i.test(file.name);
}

type ImageCrop = { x: number; y: number; width: number; height: number };

function getImageSize(image: HTMLImageElement) {
  return {
    width: image.naturalWidth || image.width,
    height: image.naturalHeight || image.height,
  };
}

function getCenterCrop(width: number, height: number, ratio: number): ImageCrop {
  const side = Math.max(1, Math.round(Math.min(width, height) * ratio));
  return {
    x: Math.max(0, Math.round((width - side) / 2)),
    y: Math.max(0, Math.round((height - side) / 2)),
    width: side,
    height: side,
  };
}

function drawImageToCanvas(
  image: HTMLImageElement,
  options: { crop?: ImageCrop; maxSize?: number; paddingRatio?: number } = {},
): HTMLCanvasElement {
  const { width, height } = getImageSize(image);
  const crop = options.crop ?? { x: 0, y: 0, width, height };
  const longestSide = Math.max(crop.width, crop.height, 1);
  const upscale = longestSide < MIN_QR_DECODE_SIZE ? MIN_QR_DECODE_SIZE / longestSide : 1;
  const scale = Math.min((options.maxSize ?? MAX_QR_DECODE_SIZE) / longestSide, upscale);
  const drawWidth = Math.max(1, Math.round(crop.width * scale));
  const drawHeight = Math.max(1, Math.round(crop.height * scale));
  const padding = Math.round(Math.max(drawWidth, drawHeight) * (options.paddingRatio ?? 0.08));
  const canvas = document.createElement("canvas");
  canvas.width = drawWidth + padding * 2;
  canvas.height = drawHeight + padding * 2;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Unable to prepare that image for QR decoding.");

  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.imageSmoothingEnabled = false;
  context.drawImage(image, crop.x, crop.y, crop.width, crop.height, padding, padding, drawWidth, drawHeight);
  return canvas;
}

function getDecodeCanvases(image: HTMLImageElement): HTMLCanvasElement[] {
  const { width, height } = getImageSize(image);
  const shortSide = Math.min(width, height);
  const longSide = Math.max(width, height);
  const candidates: Array<{ crop?: ImageCrop; maxSize?: number; paddingRatio?: number }> = [
    { maxSize: MAX_QR_DECODE_SIZE, paddingRatio: 0.08 },
    { maxSize: 1400, paddingRatio: 0.18 },
  ];

  if (shortSide > 0 && longSide / shortSide > 1.15) {
    candidates.push(
      { crop: getCenterCrop(width, height, 1), maxSize: MAX_QR_DECODE_SIZE, paddingRatio: 0.12 },
      { crop: getCenterCrop(width, height, 0.72), maxSize: 1800, paddingRatio: 0.12 },
      { crop: getCenterCrop(width, height, 0.5), maxSize: 1400, paddingRatio: 0.18 },
    );
  }

  return candidates.map((candidate) => drawImageToCanvas(image, candidate));
}

async function decodeQrFromCanvas(canvas: HTMLCanvasElement, detector?: BarcodeDetectorLike | null): Promise<string | null> {
  const nextDetector = detector === undefined ? getBarcodeDetector() : detector;
  if (nextDetector) {
    try {
      const results = await nextDetector.detect(canvas);
      const rawValue = results[0]?.rawValue?.trim();
      if (rawValue) return rawValue;
    } catch {
      // Fall through to jsQR; BarcodeDetector support varies across browsers.
    }
  }

  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context || canvas.width === 0 || canvas.height === 0) return null;
  const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
  const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
  return code?.data?.trim() || null;
}

async function decodeQrFromImage(image: HTMLImageElement): Promise<string | null> {
  const detector = getBarcodeDetector();
  if (detector) {
    try {
      const results = await detector.detect(image);
      const rawValue = results[0]?.rawValue?.trim();
      if (rawValue) return rawValue;
    } catch {
      // Continue with canvas-based decoding.
    }
  }

  for (const canvas of getDecodeCanvases(image)) {
    const rawValue = await decodeQrFromCanvas(canvas, detector);
    if (rawValue) return rawValue;
  }

  return null;
}
function CountdownTimer({ expiresAt }: { expiresAt: number }) {
  const [remaining, setRemaining] = useState(() => Math.max(0, expiresAt - Math.floor(Date.now() / 1000)));

  useEffect(() => {
    const interval = window.setInterval(() => {
      setRemaining(Math.max(0, expiresAt - Math.floor(Date.now() / 1000)));
    }, 1000);
    return () => window.clearInterval(interval);
  }, [expiresAt]);

  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  const expired = remaining === 0;
  const urgent = remaining > 0 && remaining < 60;

  return (
    <div className="flex items-center gap-1.5" style={{ color: expired ? "var(--destructive)" : urgent ? "var(--chart-5)" : "var(--muted-foreground)" }}>
      <Clock size={12} />
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)" }}>
        {expired ? "Expired" : `${minutes}:${String(seconds).padStart(2, "0")} remaining`}
      </span>
    </div>
  );
}
function OptionCard({
  icon,
  title,
  description,
  onClick,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left transition-opacity active:opacity-75"
      style={{
        backgroundColor: "var(--card)",
        border: "1.5px solid var(--border)",
        borderRadius: "var(--radius-card)",
        padding: "20px",
        cursor: "pointer",
      }}
    >
      <div className="flex items-center gap-4">
        <div
          className="flex items-center justify-center rounded-lg flex-shrink-0"
          style={{
            width: "48px",
            height: "48px",
            backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)",
            color: "var(--primary)",
          }}
        >
          {icon}
        </div>
        <div className="flex-1 min-w-0">
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-base)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
              marginBottom: "4px",
            }}
          >
            {title}
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
            {description}
          </p>
        </div>
        <ChevronRight size={16} style={{ color: "var(--muted-foreground)", flexShrink: 0 }} />
      </div>
    </button>
  );
}

export function OB02HardwarePairing() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>("choose");
  const [serial, setSerial] = useState("");
  const [qrSerial, setQrSerial] = useState("");
  const [qrRawValue, setQrRawValue] = useState("");
  const [qrMethod, setQrMethod] = useState<SignupMethod>("qr-upload");
  const [qrError, setQrError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [cameraLoading, setCameraLoading] = useState(false);
  const [pairingData, setPairingData] = useState<PairingCodeResponse | null>(null);
  const [pairingMethod, setPairingMethod] = useState<SignupMethod>("serial");
  const [proof, setProof] = useState("");
  const [pairingLoading, setPairingLoading] = useState(false);
  const [codeCopied, setCodeCopied] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const scanActiveRef = useRef(false);
  const rejectedQrRef = useRef<string | null>(null);

  const savePairingContext = (nextSerial: string, method: SignupMethod, pairedDevice?: PairResponse) => {
    sessionStorage.setItem(ONBOARDING_SERIAL_KEY, nextSerial);
    sessionStorage.setItem(ONBOARDING_METHOD_KEY, method);
    localStorage.setItem(ONBOARDING_SERIAL_KEY, nextSerial);
    localStorage.setItem(ONBOARDING_METHOD_KEY, method);
    if (pairedDevice) {
      sessionStorage.setItem(ONBOARDING_PAIR_RESPONSE_KEY, JSON.stringify(pairedDevice));
    }
  };

  const skipPairing = () => {
    localStorage.setItem("sgx_onboarded", "1");
    navigate("/home", { replace: true });
  };

  const requestPairingCode = async (value: string, method: SignupMethod) => {
    const nextSerial = normalizeSerial(value);
    if (!nextSerial) {
      toast.error("Enter a valid Guardian serial number.");
      return;
    }

    setPairingLoading(true);
    try {
      const data = await deviceService.getPairingCode(nextSerial);
      savePairingContext(nextSerial, method);
      setSerial(nextSerial);
      setPairingMethod(method);
      setPairingData(data);
      setProof("");
      setCodeCopied(false);
      setMode("code");
      toast.success("Pairing code generated");
    } catch (error: any) {
      toast.error(error.message || "Failed to generate pairing code");
    } finally {
      setPairingLoading(false);
    }
  };

  const completePairing = async () => {
    if (!pairingData || !proof.trim() || pairingLoading) return;

    setPairingLoading(true);
    try {
      const pairedDevice = await deviceService.pairDevice(pairingData.serial, proof.trim());
      savePairingContext(pairingData.serial, pairingMethod, pairedDevice);
      toast.success("Guardian paired successfully");
      navigate("/onboarding/did", {
        replace: true,
        state: {
          serial: pairingData.serial,
          signupMethod: pairingMethod,
          pairedDevice,
        },
      });
    } catch (error: any) {
      toast.error(error.message || "Pairing failed. Check the proof and try again.");
    } finally {
      setPairingLoading(false);
    }
  };

  const handleCopyPairingCode = async () => {
    if (!pairingData?.pairingCode) return;
    try {
      await navigator.clipboard.writeText(pairingData.pairingCode);
      setCodeCopied(true);
      toast.success("Pairing code copied");
      window.setTimeout(() => setCodeCopied(false), 1500);
    } catch {
      toast.error("Copy failed");
    }
  };

  const clearPairingChallenge = () => {
    setPairingData(null);
    setProof("");
    setCodeCopied(false);
  };

  const acceptQrValue = (rawValue: string, method: SignupMethod) => {
    const decodedSerial = extractSerialFromQr(rawValue);
    if (!decodedSerial) {
      if (rejectedQrRef.current !== rawValue) {
        setQrError("This QR code did not contain a valid Guardian serial number.");
        rejectedQrRef.current = rawValue;
      }
      return false;
    }

    setQrError(null);
    setQrRawValue(rawValue);
    setQrSerial(decodedSerial);
    setQrMethod(method);
    setMode("review");
    toast.success("Guardian serial decoded");
    return true;
  };

  const handleUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    setUploading(true);
    setQrError(null);
    try {
      let rawValue: string | null = null;
      if (isImageFile(file)) {
        const image = await loadImage(file);
        rawValue = await decodeQrFromImage(image);
        if (!rawValue) {
          setQrError("No QR code was found in that image. Try a sharper photo or enter the serial number.");
          return;
        }
      } else {
        rawValue = await readFileAsText(file);
        if (!rawValue.trim()) {
          setQrError("That file did not contain a QR payload or serial number.");
          return;
        }
      }

      acceptQrValue(rawValue, "qr-upload");
    } catch (error) {
      setQrError(error instanceof Error ? error.message : "Unable to decode that QR file.");
    } finally {
      setUploading(false);
    }
  };

  const stopCamera = () => {
    scanActiveRef.current = false;
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    if (videoRef.current) videoRef.current.srcObject = null;
  };

  const scanFrame = async (detector: BarcodeDetectorLike | null) => {
    if (!scanActiveRef.current) return;
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas) return;

    if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth > 0) {
      const size = Math.min(video.videoWidth, video.videoHeight, 720);
      canvas.width = size;
      canvas.height = size;
      const x = Math.max(0, (video.videoWidth - size) / 2);
      const y = Math.max(0, (video.videoHeight - size) / 2);
      const context = canvas.getContext("2d", { willReadFrequently: true });
      context?.drawImage(video, x, y, size, size, 0, 0, size, size);

      try {
        const rawValue = await decodeQrFromCanvas(canvas, detector);
        if (rawValue && acceptQrValue(rawValue, "qr-camera")) return;
      } catch {
        // Keep scanning; camera frames can fail transiently while focusing.
      }
    }

    if (scanActiveRef.current) {
      rafRef.current = requestAnimationFrame(() => {
        void scanFrame(detector);
      });
    }
  };

  useEffect(() => {
    if (mode !== "camera") {
      stopCamera();
      return;
    }

    let cancelled = false;
    const startCamera = async () => {
      const detector = getBarcodeDetector();

      if (!navigator.mediaDevices?.getUserMedia) {
        setQrError("Camera access is not available in this browser. Upload a QR photo or enter the serial number instead.");
        setMode("qr");
        return;
      }

      setCameraLoading(true);
      setQrError(null);
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: "environment" } },
          audio: false,
        });
        if (cancelled) {
          stream.getTracks().forEach((track) => track.stop());
          return;
        }

        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play();
        }
        scanActiveRef.current = true;
        void scanFrame(detector);
      } catch (error) {
        setQrError(error instanceof Error ? error.message : "Camera permission was not granted.");
        setMode("qr");
      } finally {
        if (!cancelled) setCameraLoading(false);
      }
    };

    void startCamera();
    return () => {
      cancelled = true;
      stopCamera();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  if (mode === "choose") {
    return (
      <div className="flex flex-col" style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <div className="flex flex-col items-center px-6 pt-12 pb-6">
          <ProgressDots total={3} current={2} />
          <h2
            className="mt-6 text-center"
            style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}
          >
            Pair Your Guardian
          </h2>
          <p className="mt-2 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "300px", lineHeight: 1.5 }}>
            Start with the serial number on your Guardian or decode it from the QR label.
          </p>
        </div>

        <div className="flex flex-col gap-4 px-5 flex-1">
          <OptionCard
            icon={<Hash size={24} />}
            title="Use Serial Number"
            description="Enter the Guardian serial number manually."
            onClick={() => setMode("serial")}
          />
          <OptionCard
            icon={<QrCode size={24} />}
            title="Use QR Code"
            description="Upload a QR image, take a QR photo, or scan with this device's camera."
            onClick={() => setMode("qr")}
          />
          <button
            type="button"
            onClick={skipPairing}
            className="self-center mt-1"
            style={{
              background: "none",
              border: "none",
              color: "var(--muted-foreground)",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              textDecoration: "underline",
              textUnderlineOffset: "3px",
            }}
          >
            Skip pairing for now
          </button>
        </div>
        <div className="h-8" />
      </div>
    );
  }

  if (mode === "serial") {
    const canRequestCode = normalizeSerial(serial) !== null;
    return (
      <div className="flex flex-col" style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <div className="flex flex-col items-center px-6 pt-12 pb-6">
          <ProgressDots total={3} current={2} />
          <h2 className="mt-6 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Guardian Serial
          </h2>
          <p className="mt-2 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "280px", lineHeight: 1.5 }}>
            This serial will be linked to your account.
          </p>
        </div>

        <div className="flex flex-col gap-4 px-5 flex-1">
          <div>
            <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
              Device Serial
            </label>
            <input
              autoFocus
              value={serial}
              onChange={(event) => setSerial(event.target.value.toUpperCase())}
              placeholder="e.g. GX-2024-TX-042-A9F3"
              className="w-full px-4 outline-none"
              style={{
                height: "48px",
                backgroundColor: "var(--input-background)",
                border: "1.5px solid var(--border)",
                borderRadius: "var(--radius)",
                color: "var(--foreground)",
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "var(--text-sm)",
              }}
            />
          </div>
        </div>

        <div className="px-5 pb-10 flex flex-col gap-3">
          <button
            onClick={() => requestPairingCode(serial, "serial")}
            disabled={!canRequestCode || pairingLoading}
            className="w-full flex items-center justify-center gap-2"
            style={{
              height: "52px",
              backgroundColor: "var(--primary)",
              color: "var(--primary-foreground)",
              borderRadius: "var(--radius)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-base)",
              fontWeight: "var(--font-weight-semibold)",
              border: "none",
              cursor: canRequestCode && !pairingLoading ? "pointer" : "default",
              opacity: canRequestCode && !pairingLoading ? 1 : 0.45,
            }}
          >
            {pairingLoading ? <Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} /> : "Generate Pairing Code"}
          </button>
          <button
            onClick={() => setMode("choose")}
            style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
          >
            Back
          </button>
        </div>
      </div>
    );
  }


  if ((mode === "code" || mode === "proof") && pairingData) {
    const canPair = proof.trim().length > 0 && !pairingLoading;
    const backMode: Mode = pairingMethod === "serial" ? "serial" : "review";

    return (
      <div className="flex flex-col" style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <div className="flex flex-col items-center px-6 pt-12 pb-6">
          <ProgressDots total={3} current={2} />
          <h2 className="mt-6 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Verify Guardian Pairing
          </h2>
          <p className="mt-2 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "320px", lineHeight: 1.5 }}>
            Copy the pairing code to the Guardian, then paste its signed proof here.
          </p>
        </div>

        <div className="flex-1 overflow-y-auto px-5 pb-5">
          <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
            <div className="flex items-center justify-between gap-3 px-4 py-4" style={{ borderBottom: "1px solid var(--border)" }}>
              <div className="min-w-0">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                  GUARDIAN SERIAL
                </p>
                <p className="mt-1" style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)", wordBreak: "break-all" }}>
                  {pairingData.serial}
                </p>
              </div>
              <CountdownTimer expiresAt={pairingData.expiresAt} />
            </div>

            <div className="p-4" style={{ borderBottom: "1px solid var(--border)" }}>
              <div className="flex items-center justify-between gap-3">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em" }}>
                  PAIRING CODE
                </p>
                <button
                  type="button"
                  onClick={handleCopyPairingCode}
                  aria-label="Copy pairing code"
                  title={codeCopied ? "Copied" : "Copy pairing code"}
                  className="flex items-center justify-center rounded-md transition-opacity active:opacity-80"
                  style={{
                    width: "34px",
                    height: "34px",
                    backgroundColor: codeCopied ? "color-mix(in srgb, var(--chart-2) 14%, transparent)" : "var(--secondary)",
                    color: codeCopied ? "var(--chart-2)" : "var(--secondary-foreground)",
                    border: "1px solid var(--border)",
                    cursor: "pointer",
                    flexShrink: 0,
                  }}
                >
                  {codeCopied ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
              <p className="mt-3" style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all", lineHeight: 1.8, userSelect: "all" }}>
                {pairingData.pairingCode}
              </p>
            </div>

            <div className="p-4" style={{ borderBottom: mode === "proof" ? "1px solid var(--border)" : undefined }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>
                CHALLENGE HASH
              </p>
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--muted-foreground)", wordBreak: "break-all", lineHeight: 1.7, userSelect: "all" }}>
                {pairingData.challenge}
              </p>
            </div>

            {mode === "proof" && (
              <div className="p-4 flex flex-col gap-4">
                <div>
                  <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)", marginBottom: "6px", display: "block" }}>
                    Signed Proof
                  </label>
                  <textarea
                    autoFocus
                    value={proof}
                    onChange={(event) => setProof(event.target.value)}
                    placeholder="Paste the proof string from the Guardian device..."
                    rows={5}
                    className="w-full px-4 py-3 outline-none"
                    style={{
                      backgroundColor: "var(--input-background)",
                      border: "1.5px solid var(--border)",
                      borderRadius: "var(--radius)",
                      color: "var(--foreground)",
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: "11px",
                      resize: "none",
                      lineHeight: 1.7,
                      width: "100%",
                      boxSizing: "border-box",
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="px-5 pb-10 flex flex-col gap-3">
          {mode === "code" ? (
            <button
              onClick={() => setMode("proof")}
              className="w-full flex items-center justify-center gap-2"
              style={{ height: "52px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)", borderRadius: "var(--radius)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", border: "none", cursor: "pointer" }}
            >
              Enter Signed Proof
            </button>
          ) : (
            <button
              onClick={completePairing}
              disabled={!canPair}
              className="w-full flex items-center justify-center gap-2"
              style={{
                height: "52px",
                backgroundColor: "var(--primary)",
                color: "var(--primary-foreground)",
                borderRadius: "var(--radius)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-base)",
                fontWeight: "var(--font-weight-semibold)",
                border: "none",
                cursor: canPair ? "pointer" : "default",
                opacity: canPair ? 1 : 0.45,
              }}
            >
              {pairingLoading ? <Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} /> : <><Check size={16} /> Complete Pairing</>}
            </button>
          )}
          <button
            onClick={() => {
              clearPairingChallenge();
              setMode(backMode);
            }}
            style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
          >
            {pairingMethod === "serial" ? "Change Serial" : "Back to QR Review"}
          </button>
          <button
            onClick={() => {
              clearPairingChallenge();
              setQrSerial("");
              setQrRawValue("");
              setMode("choose");
            }}
            style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
          >
            Start Over
          </button>
        </div>
        <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
      </div>
    );
  }
  if (mode === "qr") {
    return (
      <div className="flex flex-col" style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <div className="flex flex-col items-center px-6 pt-12 pb-6">
          <ProgressDots total={3} current={2} />
          <h2 className="mt-6 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            QR Pairing
          </h2>
          <p className="mt-2 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "300px", lineHeight: 1.5 }}>
            Decode the Guardian serial from a QR code.
          </p>
        </div>

        <div className="flex flex-col gap-4 px-5 flex-1">
          {qrError && (
            <div
              className="rounded-lg border p-3 flex items-start gap-2"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 8%, var(--card))",
                borderColor: "color-mix(in srgb, var(--destructive) 22%, transparent)",
              }}
            >
              <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0, marginTop: "2px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)", lineHeight: 1.5 }}>
                {qrError}
              </p>
            </div>
          )}

          <input ref={fileInputRef} type="file" accept="image/*,.txt,.json,.csv,.log" className="hidden" onChange={handleUpload} />

          <OptionCard
            icon={uploading ? <Loader2 size={24} style={{ animation: "spin 1s linear infinite" }} /> : <Upload size={24} />}
            title="Upload QR Code or File"
            description="Choose a QR photo, screenshot, or text file that contains the serial."
            onClick={() => fileInputRef.current?.click()}
          />
          <OptionCard
            icon={<Camera size={24} />}
            title="Scan with Camera"
            description="Use this device's camera to read the Guardian QR label live."
            onClick={() => setMode("camera")}
          />
        </div>

        <div className="px-5 pb-10 flex flex-col gap-3">
          <button
            onClick={() => setMode("serial")}
            style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
          >
            Enter Serial Instead
          </button>
          <button
            onClick={() => setMode("choose")}
            style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
          >
            Back
          </button>
        </div>
        <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
      </div>
    );
  }

  if (mode === "camera") {
    return (
      <div className="flex flex-col" style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
        <div className="flex flex-col items-center px-6 pt-12 pb-6">
          <ProgressDots total={3} current={2} />
          <h2 className="mt-6 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Scan QR Code
          </h2>
        </div>

        <div className="px-5 flex-1 flex flex-col gap-4">
          <div
            className="relative overflow-hidden rounded-lg border border-border"
            style={{ aspectRatio: "1 / 1", backgroundColor: "var(--muted)" }}
          >
            <video
              ref={videoRef}
              muted
              playsInline
              className="absolute inset-0 h-full w-full object-cover"
            />
            <canvas ref={canvasRef} className="hidden" />
            <div className="absolute inset-6 pointer-events-none">
              {[
                { top: 0, left: 0, borderTop: true, borderLeft: true },
                { top: 0, right: 0, borderTop: true, borderRight: true },
                { bottom: 0, left: 0, borderBottom: true, borderLeft: true },
                { bottom: 0, right: 0, borderBottom: true, borderRight: true },
              ].map((corner, index) => (
                <div
                  key={index}
                  className="absolute"
                  style={{
                    width: "34px",
                    height: "34px",
                    top: corner.top,
                    left: corner.left,
                    right: (corner as any).right,
                    bottom: (corner as any).bottom,
                    borderTop: corner.borderTop ? "3px solid var(--primary)" : undefined,
                    borderLeft: corner.borderLeft ? "3px solid var(--primary)" : undefined,
                    borderBottom: (corner as any).borderBottom ? "3px solid var(--primary)" : undefined,
                    borderRight: (corner as any).borderRight ? "3px solid var(--primary)" : undefined,
                  }}
                />
              ))}
              <div
                style={{
                  position: "absolute",
                  left: 0,
                  right: 0,
                  height: "2px",
                  backgroundColor: "var(--primary)",
                  opacity: 0.85,
                  animation: "scanline 1.6s ease-in-out infinite",
                }}
              />
            </div>
            {cameraLoading && (
              <div className="absolute inset-0 flex items-center justify-center" style={{ backgroundColor: "rgba(0,0,0,0.35)" }}>
                <Loader2 size={26} style={{ color: "white", animation: "spin 1s linear infinite" }} />
              </div>
            )}
          </div>

          {qrError && (
            <div
              className="rounded-lg border p-3 flex items-start gap-2"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 8%, var(--card))",
                borderColor: "color-mix(in srgb, var(--destructive) 22%, transparent)",
              }}
            >
              <AlertTriangle size={16} style={{ color: "var(--destructive)", flexShrink: 0, marginTop: "2px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)", lineHeight: 1.5 }}>
                {qrError}
              </p>
            </div>
          )}
        </div>

        <div className="px-5 pb-10 flex flex-col gap-3">
          <button
            onClick={() => setMode("qr")}
            style={{ height: "48px", backgroundColor: "var(--secondary)", border: "1px solid var(--border)", borderRadius: "var(--radius)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}
          >
            Cancel Scan
          </button>
        </div>
        <style>{`
          @keyframes scanline { 0%, 100% { top: 14%; } 50% { top: 86%; } }
          @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        `}</style>
      </div>
    );
  }

  return (
    <div className="flex flex-col" style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}>
      <div className="flex flex-col items-center px-6 pt-12 pb-6">
        <ProgressDots total={3} current={2} />
        <div
          className="mt-6 rounded-full flex items-center justify-center"
          style={{ width: "58px", height: "58px", backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)" }}
        >
          <Check size={28} style={{ color: "var(--chart-2)" }} />
        </div>
        <h2 className="mt-4 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
          Serial Decoded
        </h2>
      </div>

      <div className="px-5 flex-1">
        <div className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>
            GUARDIAN SERIAL
          </p>
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)", wordBreak: "break-all" }}>
            {qrSerial}
          </p>
        </div>
        <p className="mt-3" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
          Source: {qrMethod === "qr-upload" ? "Uploaded QR code" : "Camera scan"}
        </p>
        {qrRawValue && qrRawValue !== qrSerial && (
          <p className="mt-3" style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", wordBreak: "break-all", lineHeight: 1.6 }}>
            {qrRawValue}
          </p>
        )}
      </div>

      <div className="px-5 pb-10 flex flex-col gap-3">
        <button
          onClick={() => requestPairingCode(qrSerial, qrMethod)}
          disabled={pairingLoading || !normalizeSerial(qrSerial)}
          className="w-full flex items-center justify-center gap-2"
          style={{
            height: "52px",
            backgroundColor: "var(--primary)",
            color: "var(--primary-foreground)",
            borderRadius: "var(--radius)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-base)",
            fontWeight: "var(--font-weight-semibold)",
            border: "none",
            cursor: !pairingLoading && normalizeSerial(qrSerial) ? "pointer" : "default",
            opacity: !pairingLoading && normalizeSerial(qrSerial) ? 1 : 0.45,
          }}
        >
          {pairingLoading ? <Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} /> : "Generate Pairing Code"}
        </button>
        <button
          onClick={() => setMode("qr")}
          style={{ background: "none", border: "none", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
        >
          Scan Again
        </button>
      </div>
    </div>
  );
}
