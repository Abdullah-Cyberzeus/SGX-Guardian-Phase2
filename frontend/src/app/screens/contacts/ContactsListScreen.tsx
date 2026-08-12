import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  Check,
  Copy,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  UserRound,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "../../components/PageHeader";
import { useContactNames } from "../../contexts/ContactNameContext";
import contactService, { type Contact } from "../../services/contactService";

interface FormState {
  did: string;
  name: string;
  alias: string;
  notes: string;
}

const emptyForm: FormState = { did: "", name: "", alias: "", notes: "" };

function displayName(contact: Contact) {
  return contact.name || contact.alias || contact.did;
}

function formatWhen(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
}

export function ContactsListScreen() {
  const { refreshContacts, upsertContact, removeContactByDid } = useContactNames();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [query, setQuery] = useState("");
  const [form, setForm] = useState<FormState>(emptyForm);
  const [editingDid, setEditingDid] = useState<string | null>(null);
  const [copiedDid, setCopiedDid] = useState<string | null>(null);

  const load = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const response = await contactService.list();
      setContacts(response.contacts);
    } catch (cause) {
      toast.error("Contacts could not be loaded", {
        description: cause instanceof Error ? cause.message : undefined,
      });
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return contacts;
    return contacts.filter((contact) =>
      `${contact.did} ${contact.name ?? ""} ${contact.alias ?? ""} ${contact.notes ?? ""}`
        .toLowerCase()
        .includes(needle),
    );
  }, [contacts, query]);

  const resetForm = () => {
    setForm(emptyForm);
    setEditingDid(null);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const did = form.did.trim();
    if (!did.startsWith("did:")) {
      toast.error("Enter a valid DID", { description: "DIDs must start with did:." });
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim() || undefined,
        alias: form.alias.trim() || undefined,
        notes: form.notes.trim() || undefined,
      };
      const response = editingDid
        ? await contactService.update(editingDid, payload)
        : await contactService.create({ did, ...payload });
      setContacts((items) => {
        const next = items.filter((item) => item.did !== response.contact.did);
        return [...next, response.contact].sort((a, b) => displayName(a).localeCompare(displayName(b)));
      });
      upsertContact(response.contact);
      void refreshContacts();
      toast.success(editingDid ? "Contact updated" : "Contact saved");
      resetForm();
    } catch (cause) {
      toast.error(editingDid ? "Contact was not updated" : "Contact was not saved", {
        description: cause instanceof Error ? cause.message : undefined,
      });
    } finally {
      setSaving(false);
    }
  };

  const edit = (contact: Contact) => {
    setEditingDid(contact.did);
    setForm({
      did: contact.did,
      name: contact.name ?? "",
      alias: contact.alias ?? "",
      notes: contact.notes ?? "",
    });
  };

  const remove = async (contact: Contact) => {
    if (!window.confirm(`Remove ${displayName(contact)} from contacts?`)) return;
    try {
      await contactService.remove(contact.did);
      setContacts((items) => items.filter((item) => item.did !== contact.did));
      if (editingDid === contact.did) resetForm();
      removeContactByDid(contact.did);
      void refreshContacts();
      toast.success("Contact removed");
    } catch (cause) {
      toast.error("Contact was not removed", {
        description: cause instanceof Error ? cause.message : undefined,
      });
    }
  };

  const copyDid = async (did: string) => {
    try {
      await navigator.clipboard.writeText(did);
      setCopiedDid(did);
      window.setTimeout(() => setCopiedDid((current) => (current === did ? null : current)), 1400);
    } catch {
      toast.error("DID could not be copied");
    }
  };

  const refresh = async () => {
    setRefreshing(true);
    await load(true);
    setRefreshing(false);
  };

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Contacts"
        subtitle={`${contacts.length} saved DID contact${contacts.length === 1 ? "" : "s"}`}
        right={
          <button
            aria-label="Refresh contacts"
            onClick={() => void refresh()}
            className="grid h-10 w-10 place-items-center rounded-full hover:bg-muted"
          >
            <RefreshCw size={18} className={refreshing ? "animate-spin" : ""} />
          </button>
        }
      />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto grid w-full max-w-5xl gap-4 p-4 md:grid-cols-[360px_1fr] md:p-6">
          <form
            onSubmit={(event) => void submit(event)}
            className="self-start rounded-lg border border-border bg-card p-4"
          >
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold">{editingDid ? "Edit contact" : "Add contact"}</h3>
                <p className="text-xs text-muted-foreground">Save a trusted identity by DID.</p>
              </div>
              {editingDid && (
                <button
                  type="button"
                  aria-label="Cancel edit"
                  onClick={resetForm}
                  className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted"
                >
                  <X size={16} />
                </button>
              )}
            </div>

            <label className="mb-3 block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">DID</span>
              <input
                value={form.did}
                onChange={(event) => setForm((current) => ({ ...current, did: event.target.value }))}
                disabled={Boolean(editingDid) || saving}
                placeholder="did:guardian:..."
                className="h-11 w-full rounded-md border border-border bg-input-background px-3 text-sm outline-none disabled:opacity-60"
              />
            </label>

            <label className="mb-3 block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Name</span>
              <input
                value={form.name}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                disabled={saving}
                placeholder="Display name"
                className="h-11 w-full rounded-md border border-border bg-input-background px-3 text-sm outline-none"
              />
            </label>

            <label className="mb-3 block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Alias</span>
              <input
                value={form.alias}
                onChange={(event) => setForm((current) => ({ ...current, alias: event.target.value }))}
                disabled={saving}
                placeholder="Optional alias"
                className="h-11 w-full rounded-md border border-border bg-input-background px-3 text-sm outline-none"
              />
            </label>

            <label className="mb-4 block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Notes</span>
              <textarea
                value={form.notes}
                onChange={(event) => setForm((current) => ({ ...current, notes: event.target.value }))}
                disabled={saving}
                placeholder="Optional notes"
                rows={4}
                className="w-full resize-none rounded-md border border-border bg-input-background px-3 py-2 text-sm outline-none"
              />
            </label>

            <button
              type="submit"
              disabled={saving || !form.did.trim()}
              className="flex h-11 w-full items-center justify-center gap-2 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground disabled:opacity-50"
            >
              {saving ? <Loader2 size={17} className="animate-spin" /> : editingDid ? <Check size={17} /> : <Plus size={17} />}
              {editingDid ? "Save changes" : "Save contact"}
            </button>
          </form>

          <section className="min-w-0">
            <div className="mb-3 flex h-11 items-center gap-2 rounded-full border border-border bg-input-background px-4">
              <Search size={17} className="text-muted-foreground" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search contacts"
                className="min-w-0 flex-1 bg-transparent text-sm outline-none"
              />
            </div>

            <div className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-card">
              {loading && (
                <div className="flex items-center justify-center gap-2 p-12 text-sm text-muted-foreground">
                  <Loader2 size={20} className="animate-spin" /> Loading contacts...
                </div>
              )}
              {!loading && visible.length === 0 && (
                <div className="flex flex-col items-center gap-3 p-12 text-center">
                  <UserRound size={40} className="text-muted-foreground" />
                  <p className="text-sm font-semibold">{query ? "No contacts found" : "No contacts yet"}</p>
                  <p className="max-w-sm text-xs text-muted-foreground">
                    Add a contact by DID to keep a local Guardian address book without changing peer or chat behavior.
                  </p>
                </div>
              )}
              {visible.map((contact) => (
                <div key={contact.did} className="flex gap-3 px-4 py-4 md:px-5">
                  <div className="grid h-11 w-11 shrink-0 place-items-center rounded-full bg-primary/15 text-primary">
                    <UserRound size={19} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex min-w-0 items-center gap-2">
                      <p className="truncate text-sm font-semibold">{displayName(contact)}</p>
                      {contact.name && contact.alias && (
                        <span className="shrink-0 rounded-full border border-border px-2 py-0.5 text-[10px] text-muted-foreground">
                          {contact.alias}
                        </span>
                      )}
                    </div>
                    <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{contact.did}</p>
                    {contact.notes && <p className="mt-2 line-clamp-2 text-xs text-muted-foreground">{contact.notes}</p>}
                    <p className="mt-2 text-[10px] text-muted-foreground">Updated {formatWhen(contact.updated_at)}</p>
                  </div>
                  <div className="flex shrink-0 items-start gap-1">
                    <button
                      type="button"
                      aria-label="Copy DID"
                      title="Copy DID"
                      onClick={() => void copyDid(contact.did)}
                      className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted"
                    >
                      {copiedDid === contact.did ? <Check size={16} /> : <Copy size={16} />}
                    </button>
                    <button
                      type="button"
                      aria-label="Edit contact"
                      title="Edit contact"
                      onClick={() => edit(contact)}
                      className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted"
                    >
                      <Pencil size={16} />
                    </button>
                    <button
                      type="button"
                      aria-label="Remove contact"
                      title="Remove contact"
                      onClick={() => void remove(contact)}
                      className="grid h-9 w-9 place-items-center rounded-full hover:bg-muted"
                    >
                      <Trash2 size={16} className="text-destructive" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
