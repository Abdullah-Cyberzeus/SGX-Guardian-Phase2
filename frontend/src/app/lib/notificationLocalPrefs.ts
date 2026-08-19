import { settingsRepository } from "../../pwa/db/settingsRepository";

// Local-only notification behavior (Phase 9): whether this browser reacts to
// notifications at all, and how — sound, vibration, and a Do Not Disturb
// window. None of this is synced or Guardian-enforced; each browser decides
// for itself. Contrast with PrivacySettings, which patches the backend.

const KEYS = {
  masterEnabled: "notify.masterEnabled",
  sound: "notify.sound",
  vibration: "notify.vibration",
  dndStart: "notify.dndStart",
  dndEnd: "notify.dndEnd",
} as const;

export interface LocalNotificationPrefs {
  masterEnabled: boolean;
  sound: boolean;
  vibration: boolean;
  /** "HH:MM" 24h local time, or "" for no DND window. */
  dndStart: string;
  dndEnd: string;
}

const DEFAULTS: LocalNotificationPrefs = {
  masterEnabled: true,
  sound: true,
  vibration: true,
  dndStart: "",
  dndEnd: "",
};

export async function loadLocalNotificationPrefs(): Promise<LocalNotificationPrefs> {
  const [masterEnabled, sound, vibration, dndStart, dndEnd] = await Promise.all([
    settingsRepository.get<boolean>(KEYS.masterEnabled),
    settingsRepository.get<boolean>(KEYS.sound),
    settingsRepository.get<boolean>(KEYS.vibration),
    settingsRepository.get<string>(KEYS.dndStart),
    settingsRepository.get<string>(KEYS.dndEnd),
  ]);
  return {
    masterEnabled: masterEnabled ?? DEFAULTS.masterEnabled,
    sound: sound ?? DEFAULTS.sound,
    vibration: vibration ?? DEFAULTS.vibration,
    dndStart: dndStart ?? DEFAULTS.dndStart,
    dndEnd: dndEnd ?? DEFAULTS.dndEnd,
  };
}

export async function saveLocalNotificationPref<K extends keyof LocalNotificationPrefs>(
  key: K,
  value: LocalNotificationPrefs[K],
): Promise<void> {
  await settingsRepository.set(KEYS[key], value);
}

/** True when `now` (defaults to the current time) falls inside the DND
 * window, including windows that wrap past midnight (e.g. 22:00 -> 07:00). */
export function isWithinDnd(prefs: Pick<LocalNotificationPrefs, "dndStart" | "dndEnd">, now = new Date()): boolean {
  const { dndStart, dndEnd } = prefs;
  if (!dndStart || !dndEnd) return false;
  const minutesOfDay = now.getHours() * 60 + now.getMinutes();
  const toMinutes = (value: string) => {
    const [h, m] = value.split(":").map(Number);
    return (h || 0) * 60 + (m || 0);
  };
  const start = toMinutes(dndStart);
  const end = toMinutes(dndEnd);
  if (start === end) return false;
  if (start < end) return minutesOfDay >= start && minutesOfDay < end;
  return minutesOfDay >= start || minutesOfDay < end; // wraps past midnight
}

let audioContext: AudioContext | null = null;

/** A short, synthesized beep — no bundled audio asset to license/maintain. */
export function playNotificationSound(): void {
  try {
    const Ctor = window.AudioContext || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return;
    audioContext ??= new Ctor();
    if (audioContext.state === "suspended") void audioContext.resume();
    const oscillator = audioContext.createOscillator();
    const gain = audioContext.createGain();
    oscillator.type = "sine";
    oscillator.frequency.value = 880;
    gain.gain.setValueAtTime(0.001, audioContext.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.15, audioContext.currentTime + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.001, audioContext.currentTime + 0.25);
    oscillator.connect(gain);
    gain.connect(audioContext.destination);
    oscillator.start();
    oscillator.stop(audioContext.currentTime + 0.26);
  } catch {
    // Audio is a nicety; never let it break notification delivery.
  }
}

export function vibrateForNotification(): void {
  try {
    navigator.vibrate?.(200);
  } catch {
    // Vibration is a nicety; never let it break notification delivery.
  }
}
