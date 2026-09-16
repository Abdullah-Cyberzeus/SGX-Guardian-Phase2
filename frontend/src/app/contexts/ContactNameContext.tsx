import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import contactService, { type Contact } from "../services/contactService";
import { peerService } from "../services/peerService";

interface ContactNameContextValue {
  contacts: Contact[];
  contactNameForDid: (did?: string | null) => string | undefined;
  deviceNameForDid: (did?: string | null) => string | undefined;
  displayForDid: (did?: string | null, fallback?: string) => string;
  refreshContacts: () => Promise<void>;
  upsertContact: (contact: Contact) => void;
  removeContactByDid: (did: string) => void;
}

const emptyValue: ContactNameContextValue = {
  contacts: [],
  contactNameForDid: () => undefined,
  deviceNameForDid: () => undefined,
  displayForDid: (did, fallback) => fallback || did || "",
  refreshContacts: async () => {},
  upsertContact: () => {},
  removeContactByDid: () => {},
};

const ContactNameContext = createContext<ContactNameContextValue>(emptyValue);

function normalizeDid(did?: string | null) {
  return (did || "").trim().toLowerCase();
}

function savedName(contact: Contact) {
  return contact.name?.trim() || contact.alias?.trim() || undefined;
}

function friendlyDeviceName(peer: { displayName?: string; fullName?: string; deviceName?: string; peerId?: string; did?: string; ip?: string }) {
  const blocked = new Set([
    peer.did?.trim().toLowerCase(),
    peer.ip?.trim().toLowerCase(),
    "browser",
    "pwa member device",
  ].filter(Boolean));
  return [peer.displayName, peer.fullName, peer.deviceName, peer.peerId]
    .map((value) => String(value || "").trim())
    .find((value) => value && !blocked.has(value.toLowerCase()) && !value.toLowerCase().startsWith("did:"));
}

export function ContactNameProvider({ children }: { children: ReactNode }) {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [deviceNamesByDid, setDeviceNamesByDid] = useState<Map<string, string>>(new Map());

  const refreshContacts = useCallback(async () => {
    // The backend scopes /contacts to DIDs sharing a Circle with the caller,
    // so this is safe for both admin and member sessions — a member only
    // ever gets back the contacts they're allowed to see.
    const [response, peers] = await Promise.all([
      contactService.list().catch(() => ({ contacts: [] })),
      peerService.getContacts().catch(() => peerService.getAll()).catch(() => []),
    ]);
    try {
      setContacts(response.contacts);
      setDeviceNamesByDid(new Map(peers
        .filter((peer) => peer.did)
        .map((peer) => [normalizeDid(peer.did), friendlyDeviceName(peer)])
        .filter((entry): entry is [string, string] => Boolean(entry[0] && entry[1]))));
    } catch {
      setContacts([]);
      setDeviceNamesByDid(new Map());
    }
  }, []);

  useEffect(() => {
    void refreshContacts();
  }, [refreshContacts]);

  const upsertContact = useCallback((contact: Contact) => {
    const key = normalizeDid(contact.did);
    setContacts((current) => {
      const next = current.filter((item) => normalizeDid(item.did) !== key);
      return [...next, contact].sort((a, b) => (savedName(a) || a.did).localeCompare(savedName(b) || b.did));
    });
  }, []);

  const removeContactByDid = useCallback((did: string) => {
    const key = normalizeDid(did);
    setContacts((current) => current.filter((contact) => normalizeDid(contact.did) !== key));
  }, []);

  const namesByDid = useMemo(() => {
    const map = new Map<string, string>();
    contacts.forEach((contact) => {
      const key = normalizeDid(contact.did);
      const name = savedName(contact);
      if (key && name) map.set(key, name);
    });
    return map;
  }, [contacts]);

  const contactNameForDid = useCallback((did?: string | null) => {
    const key = normalizeDid(did);
    return key ? namesByDid.get(key) : undefined;
  }, [namesByDid]);

  const deviceNameForDid = useCallback((did?: string | null) => {
    const key = normalizeDid(did);
    return key ? deviceNamesByDid.get(key) : undefined;
  }, [deviceNamesByDid]);

  const displayForDid = useCallback((did?: string | null, fallback?: string) => (
    contactNameForDid(did) || deviceNameForDid(did) || fallback || did || ""
  ), [contactNameForDid, deviceNameForDid]);

  const value = useMemo<ContactNameContextValue>(() => ({
    contacts,
    contactNameForDid,
    deviceNameForDid,
    displayForDid,
    refreshContacts,
    upsertContact,
    removeContactByDid,
  }), [contacts, contactNameForDid, deviceNameForDid, displayForDid, refreshContacts, upsertContact, removeContactByDid]);

  return <ContactNameContext.Provider value={value}>{children}</ContactNameContext.Provider>;
}

export function useContactNames() {
  return useContext(ContactNameContext);
}
