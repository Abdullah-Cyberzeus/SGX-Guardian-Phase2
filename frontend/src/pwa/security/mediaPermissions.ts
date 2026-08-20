const CALL_PATHS = ["/calls", "/network", "/chats"];
const CAMERA_ONLY_PATHS = ["/join", "/onboarding"];
const USER_GESTURE_GRACE_MS = 15_000;
let lastUserGestureAt = 0;

function isCallRoute(pathname: string) {
  return CALL_PATHS.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function isCameraOnlyRoute(pathname: string) {
  return CAMERA_ONLY_PATHS.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function hasRecentUserGesture() {
  return Boolean(navigator.userActivation?.isActive)
    || Date.now() - lastUserGestureAt <= USER_GESTURE_GRACE_MS;
}

function requestedAudio(constraints?: MediaStreamConstraints) {
  return Boolean(constraints?.audio);
}

function requestedVideo(constraints?: MediaStreamConstraints) {
  return Boolean(constraints?.video);
}

function assertMediaAllowed(constraints?: MediaStreamConstraints) {
  const path = window.location.pathname;
  const audio = requestedAudio(constraints);
  const video = requestedVideo(constraints);
  const routeAllowed = isCallRoute(path) || (video && !audio && isCameraOnlyRoute(path));

  if (!routeAllowed) {
    throw new DOMException("Camera and microphone access is restricted to Guardian call and onboarding screens.", "SecurityError");
  }
  if (document.visibilityState !== "visible") {
    throw new DOMException("Camera and microphone access requires the Guardian tab to be visible.", "NotAllowedError");
  }
  if (!hasRecentUserGesture()) {
    throw new DOMException("Camera and microphone access must be started by a user action.", "NotAllowedError");
  }
}

export function installMediaPermissionGuard() {
  if (typeof window === "undefined" || !navigator.mediaDevices) return;
  const devices = navigator.mediaDevices as MediaDevices & {
    __sgxGuardInstalled?: boolean;
  };
  if (devices.__sgxGuardInstalled) return;

  const markGesture = () => {
    lastUserGestureAt = Date.now();
  };
  window.addEventListener("pointerdown", markGesture, { capture: true, passive: true });
  window.addEventListener("keydown", markGesture, { capture: true, passive: true });

  const originalGetUserMedia = devices.getUserMedia?.bind(devices);
  if (originalGetUserMedia) {
    devices.getUserMedia = (constraints?: MediaStreamConstraints) => {
      assertMediaAllowed(constraints);
      return originalGetUserMedia(constraints);
    };
  }

  const originalGetDisplayMedia = devices.getDisplayMedia?.bind(devices);
  if (originalGetDisplayMedia) {
    devices.getDisplayMedia = (constraints?: DisplayMediaStreamOptions) => {
      if (!isCallRoute(window.location.pathname)) {
        throw new DOMException("Screen sharing is restricted to Guardian call screens.", "SecurityError");
      }
      if (!hasRecentUserGesture()) {
        throw new DOMException("Screen sharing must be started by a user action.", "NotAllowedError");
      }
      return originalGetDisplayMedia(constraints);
    };
  }

  devices.__sgxGuardInstalled = true;
}
