import api from "./api";

export interface Contact {
  did: string;
  name?: string;
  alias?: string;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface ContactInput {
  did: string;
  name?: string;
  alias?: string;
  notes?: string;
}

export interface ContactsResponse {
  contacts: Contact[];
  total: number;
  timestamp: string;
}

export interface ContactMutationResponse {
  success: boolean;
  contact: Contact;
}

export const contactService = {
  list: () => api.get<ContactsResponse>("/contacts"),
  get: (did: string) => api.get<Contact>(`/contacts/${encodeURIComponent(did)}`),
  create: (data: ContactInput) => api.post<ContactMutationResponse>("/contacts", data),
  update: (did: string, data: Partial<Omit<ContactInput, "did">>) =>
    api.patch<ContactMutationResponse>(`/contacts/${encodeURIComponent(did)}`, data),
  remove: (did: string) =>
    api.delete<{ success: boolean; did: string }>(`/contacts/${encodeURIComponent(did)}`),
};

export default contactService;
