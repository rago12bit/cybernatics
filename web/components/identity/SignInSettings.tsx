"use client";

import { useCallback, useEffect, useId, useState, type FormEvent } from "react";
import {
  ApiError, createScimToken, createSsoProvider, deleteSsoProvider, listScimTokens, listSsoProviders, revokeScimToken,
  testSsoProvider, updateSsoProvider,
} from "@/lib/api";
import { OVERRIDE_ROLES, type OverrideRole, type SsoProvider, type SsoProviderInput, type TokenView } from "@/lib/identity";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import "./identity.css";

/* Sign-in and provisioning (Week 75): the organization's identity providers -- OIDC (Google
 * Workspace, Entra ID, Okta, Keycloak...) or SAML -- with what to paste into the provider on its
 * side, and the SCIM tokens the provider creates and removes people with. */

function message(e: unknown, fallback: string): string {
  if (e instanceof ApiError) return (e.data as { message?: string } | undefined)?.message ?? e.message;
  return fallback;
}

function Copy({ label, value }: { label: string; value: string }) {
  const id = useId();
  return (
    <div className="idn-copy">
      <label htmlFor={id}>{label}</label>
      <input id={id} readOnly value={value} onFocus={(e) => e.currentTarget.select()} />
    </div>
  );
}

export function SignInSettings() {
  const [providers, setProviders] = useState<SsoProvider[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [said, setSaid] = useState("");
  const [editing, setEditing] = useState<SsoProvider | "oidc" | "saml" | null>(null);
  const [tests, setTests] = useState<Record<string, { ok: boolean; message: string }>>({});

  const load = useCallback(() => {
    listSsoProviders().then((p) => { setProviders(p); setError(null); }, (e) => setError(message(e, "Could not load the sign-in settings.")));
  }, []);
  useEffect(load, [load]);

  async function test(p: SsoProvider) {
    try { const t = await testSsoProvider(p.id); setTests((cur) => ({ ...cur, [p.id]: t })); }
    catch (e) { setTests((cur) => ({ ...cur, [p.id]: { ok: false, message: message(e, "Could not test it.") } })); }
  }
  async function toggle(p: SsoProvider) {
    try { await updateSsoProvider(p.id, { enabled: !p.enabled }); load(); setSaid(`${p.name} is ${p.enabled ? "off" : "on"}.`); }
    catch (e) { setError(message(e, "Could not save.")); }
  }
  async function remove(p: SsoProvider) {
    try { await deleteSsoProvider(p.id); load(); setSaid(`${p.name} is removed. People who signed in with it keep their accounts.`); }
    catch (e) { setError(message(e, "Could not remove it.")); }
  }

  return (
    <div className="idn">
      <section aria-labelledby="idn-sso-h" className="idn-section">
        <h2 id="idn-sso-h">Single sign-on</h2>
        <p className="idn-muted">People sign in with your identity provider. Each provider vouches for some email domains; the sign-in page sends people with those emails to it.</p>
        <div className="idn-actions">
          <Button type="button" variant="primary" onClick={() => setEditing("oidc")}>Add an OIDC provider</Button>
          <Button type="button" onClick={() => setEditing("saml")}>Add a SAML provider</Button>
        </div>
        <p role="status" className="idn-said">{said}</p>
        {error && <p role="alert" className="idn-error">{error}</p>}
        {providers?.length === 0 && <p className="idn-empty">No identity provider yet: people sign in with API tokens.</p>}
        <ul className="idn-providers">
          {providers?.map((p) => (
            <li key={p.id} className="idn-provider">
              <div className="idn-provider-head">
                <h3>{p.name} <span className="idn-tag">{p.kind.toUpperCase()}</span>{!p.enabled && <span className="idn-tag off">off</span>}</h3>
                <div className="idn-actions">
                  <Button type="button" onClick={() => test(p)}>Test</Button>
                  <Button type="button" onClick={() => setEditing(p)}>Change</Button>
                  <Button type="button" onClick={() => toggle(p)}>{p.enabled ? "Turn off" : "Turn on"}</Button>
                  <Button type="button" onClick={() => remove(p)} aria-label={`Remove ${p.name}`}>Remove</Button>
                </div>
              </div>
              {tests[p.id] && <p role="status" className={tests[p.id]!.ok ? "idn-ok" : "idn-error"}>{tests[p.id]!.message}</p>}
              <p className="idn-muted">Signs in {p.email_domains.join(", ")}. {p.auto_create ? `A first sign-in creates the account, as ${p.default_role}.` : "Only people already added (or provisioned) can sign in."}
                {p.kind === "oidc" && p.secret_store === "database" && " The client secret is stored in the database, not encrypted: set up OpenBao to keep it there."}</p>
              {p.oidc && <Copy label="Redirect URI (give this to the provider)" value={p.oidc.redirect_uri} />}
              {p.saml && <>
                <Copy label="Entity ID (audience)" value={p.saml.sp_entity_id} />
                <Copy label="Assertion consumer service URL" value={p.saml.acs_url} />
                <p className="idn-muted">The provider must sign its assertions. Our metadata: <a href={p.saml.sp_entity_id}>{p.saml.sp_entity_id}</a></p>
              </>}
            </li>
          ))}
        </ul>
      </section>
      <ScimSection />
      {editing && <ProviderForm current={typeof editing === "string" ? null : editing} kind={typeof editing === "string" ? editing : editing.kind}
        onClose={() => setEditing(null)} onSaved={(p) => { setEditing(null); load(); setSaid(`${p.name} is saved.`); }} />}
    </div>
  );
}

function ProviderForm({ current, kind, onClose, onSaved }: {
  current: SsoProvider | null; kind: "oidc" | "saml"; onClose: () => void; onSaved: (p: SsoProvider) => void;
}) {
  const id = useId();
  const [f, setF] = useState<SsoProviderInput>(() => ({
    name: current?.name ?? "", email_domains: current?.email_domains ?? [], auto_create: current?.auto_create ?? false,
    default_role: current?.default_role ?? "member", issuer: current?.oidc?.issuer ?? "", client_id: current?.oidc?.client_id ?? "",
    trust_email: current?.oidc?.trust_email ?? false, idp_entity_id: current?.saml?.idp_entity_id ?? "", sso_url: current?.saml?.sso_url ?? "",
  }));
  const [domains, setDomains] = useState((current?.email_domains ?? []).join(", "));
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (patch: SsoProviderInput) => setF((cur) => ({ ...cur, ...patch }));
  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    const body: SsoProviderInput = { ...f, kind, email_domains: domains.split(/[\s,]+/).filter(Boolean) };
    if (kind === "saml") { delete body.issuer; delete body.client_id; delete body.trust_email; }
    else { delete body.idp_entity_id; delete body.sso_url; }
    for (const k of ["client_secret", "idp_cert", "idp_metadata_xml"] as const) if (!body[k]) delete body[k];
    try { onSaved(current ? await updateSsoProvider(current.id, body) : await createSsoProvider(body)); }
    catch (err) {
      const d = err instanceof ApiError ? (err.data as { field?: string; message?: string } | undefined) : undefined;
      setError({ field: d?.field, message: d?.message ?? message(err, "Could not save.") });
    } finally { setBusy(false); }
  }
  const field = (name: keyof SsoProviderInput, label: string, hint?: string, type = "text") => (
    <>
      <label htmlFor={`${id}-${name}`}>{label}</label>
      <input id={`${id}-${name}`} type={type} value={String(f[name] ?? "")} onChange={(e) => set({ [name]: e.target.value })}
        aria-invalid={error?.field === name || undefined} aria-describedby={hint ? `${id}-${name}-h` : undefined} autoComplete="off" />
      {hint && <p id={`${id}-${name}-h`} className="idn-muted idn-small">{hint}</p>}
    </>
  );
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`${current ? "Change" : "Add"} ${kind === "oidc" ? "an OIDC" : "a SAML"} provider`}
      description={kind === "oidc" ? "Bulwark reads the provider's own description from its issuer and checks every sign-in against it." : "Paste the provider's metadata, or its entity ID, sign-in URL and signing certificate."}>
      <form onSubmit={save} className="idn-form">
        {field("name", "Name people see", "e.g. Acme SSO")}
        {kind === "oidc" ? <>
          {field("issuer", "Issuer", "e.g. https://accounts.google.com, https://login.microsoftonline.com/<tenant>/v2.0, https://acme.okta.com")}
          {field("client_id", "Client ID")}
          {field("client_secret", current?.has_secret ? "Client secret (leave empty to keep it)" : "Client secret", undefined, "password")}
          <label className="idn-check"><input type="checkbox" checked={Boolean(f.trust_email)} onChange={(e) => set({ trust_email: e.target.checked })} />Trust the provider&apos;s emails without an email_verified claim (Entra ID sends none)</label>
        </> : <>
          <label htmlFor={`${id}-md`}>Provider metadata (XML)</label>
          <textarea id={`${id}-md`} rows={4} value={f.idp_metadata_xml ?? ""} onChange={(e) => set({ idp_metadata_xml: e.target.value })} aria-invalid={error?.field === "idp_metadata_xml" || undefined} />
          {field("idp_entity_id", "Or: the provider's entity ID")}
          {field("sso_url", "Its sign-in URL (HTTP-Redirect)")}
          <label htmlFor={`${id}-cert`}>{current?.saml?.has_certificate ? "Its signing certificate (leave empty to keep it)" : "Its signing certificate (PEM)"}</label>
          <textarea id={`${id}-cert`} rows={3} value={f.idp_cert ?? ""} onChange={(e) => set({ idp_cert: e.target.value })} aria-invalid={error?.field === "idp_cert" || undefined} />
        </>}
        <label htmlFor={`${id}-dom`}>Email domains it signs in</label>
        <input id={`${id}-dom`} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="acme.com, acme.co.uk" aria-invalid={error?.field === "email_domains" || undefined} />
        <label className="idn-check"><input type="checkbox" checked={Boolean(f.auto_create)} onChange={(e) => set({ auto_create: e.target.checked })} />A first sign-in creates the account</label>
        {f.auto_create && <>
          <label htmlFor={`${id}-role`}>New accounts are</label>
          <select id={`${id}-role`} value={f.default_role} onChange={(e) => set({ default_role: e.target.value as OverrideRole })}>
            {OVERRIDE_ROLES.map(([r, l]) => <option key={r} value={r}>{l}</option>)}
          </select>
        </>}
        {error && <p role="alert" className="idn-error">{error.message}</p>}
        <div className="idn-actions">
          <Button type="submit" variant="primary" disabled={busy}>{busy ? "Checking…" : "Save"}</Button>
          <Button type="button" onClick={onClose}>Cancel</Button>
        </div>
      </form>
    </Dialog>
  );
}

function ScimSection() {
  const id = useId();
  const [data, setData] = useState<{ base_url: string; tokens: TokenView[] } | null>(null);
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => { listScimTokens().then(setData, (e) => setError(message(e, "Could not load SCIM tokens."))); }, []);
  useEffect(load, [load]);
  async function make(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try { const t = await createScimToken(name.trim()); setFresh(t.token); setName(""); load(); }
    catch (err) { setError(message(err, "Could not make a token.")); }
  }
  async function revoke(t: TokenView) {
    try { await revokeScimToken(t.id); load(); } catch (err) { setError(message(err, "Could not revoke it.")); }
  }
  const live = data?.tokens.filter((t) => !t.revoked_at) ?? [];
  return (
    <section aria-labelledby="idn-scim-h" className="idn-section">
      <h2 id="idn-scim-h">Provisioning (SCIM)</h2>
      <p className="idn-muted">Your identity provider adds people, changes them, and turns them off here. Someone it turns off is signed out everywhere at once, and their tokens stop working.</p>
      {data && <Copy label="SCIM base URL" value={data.base_url} />}
      <form onSubmit={make} className="idn-inline">
        <label htmlFor={`${id}-n`}>New token for</label>
        <input id={`${id}-n`} value={name} onChange={(e) => setName(e.target.value)} placeholder="Okta" />
        <Button type="submit" disabled={!name.trim()}>Make a SCIM token</Button>
      </form>
      {fresh && (
        <div className="idn-fresh" role="status">
          <Copy label="The token: give it to your identity provider now. It is shown only once." value={fresh} />
          <Button type="button" onClick={() => setFresh(null)}>I have copied it</Button>
        </div>
      )}
      {error && <p role="alert" className="idn-error">{error}</p>}
      {live.length > 0 && (
        <ul className="idn-overrides">
          {live.map((t) => (
            <li key={t.id}>{t.name} <span className="idn-muted">({t.prefix}…, last used {t.last_used_at ? t.last_used_at.slice(0, 10) : "never"})</span>{" "}
              <button type="button" className="idn-link" onClick={() => revoke(t)} aria-label={`Revoke the SCIM token ${t.name}`}>Revoke</button></li>
          ))}
        </ul>
      )}
    </section>
  );
}
