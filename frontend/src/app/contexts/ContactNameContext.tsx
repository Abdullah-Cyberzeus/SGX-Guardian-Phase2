import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import contactService, { type Contact } from "../services/contactService";

interface ContactNameContextValue {
  contacts: Contact[];
  contactNameForDid: (did?: string | null) => string | undefined;
  displayForDid: (did?: string | null, fallback?: string) => string;
  refreshContacts: () => Promise<void>;
  upsertContact: (contact: Contact) => void;
  removeContactByDid: (did: string) => void;
}

const emptyValue: ContactNameContextValue = {
  contacts: [],
  contactNameForDid: () => undefined,
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

export function ContactNameProvider({ children }: { children: ReactNode }) {
  const [contacts, setContacts] = useState<Contact[]>([]);

  const refreshContacts = useCallback(async () => {
    try {
      const response = await contactService.list();
      setContacts(response.contacts);
    } catch {
      setContacts([]);
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

  const displayForDid = useCallback((did?: string | null, fallback?: string) => (
    contactNameForDid(did) || fallback || did || ""
  ), [contactNameForDid]);

  const value = useMemo<ContactNameContextValue>(() => ({
    contacts,
    contactNameForDid,
    displayForDid,
    refreshContacts,
    upsertContact,
    removeContactByDid,
  }), [contacts, contactNameForDid, displayForDid, refreshContacts, upsertContact, removeContactByDid]);

  return <ContactNameContext.Provider value={value}>{children}</ContactNameContext.Provider>;
}

export function useContactNames() {
  return useContext(ContactNameContext);
}
