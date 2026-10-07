/* People, roles, single sign-on and tokens (Week 75). Mirrors core/identity. */

export type OrgRole = "admin" | "member" | "viewer" | "none";
export type OverrideRole = "admin" | "member" | "viewer";
export const ORG_ROLES: [OrgRole, string, string][] = [
  ["admin", "Admin", "Everything, including people, roles and sign-in"],
  ["member", "Member", "Scan, triage, import, fix"],
  ["viewer", "Viewer", "Read only"],
  ["none", "Only granted projects", "Sees only the projects and business units given below"],
];
export const OVERRIDE_ROLES: [OverrideRole, string][] = [["admin", "Admin"], ["member", "Member"], ["viewer", "Viewer"]];
export const roleLabel = (r: string) => ORG_ROLES.find(([v]) => v === r)?.[1] ?? r;

export interface RoleOverrideView { id: string; target_type: "project" | "portfolio"; target_id: string; role: OverrideRole }
export interface UserView {
  id: string;
  email: string;
  name: string;
  role: OrgRole;
  active: boolean;
  source: string;
  external_id: string | null;
  created_at: string;
  last_login_at: string | null;
  disabled_at: string | null;
  deprovisioned_at: string | null;
  /** Who a `/fix` comment on a pull request is from (Week 76). Set by an admin only. */
  github_login: string | null;
  actor: string;
  roles: RoleOverrideView[];
}

export interface SsoChoice { id: string; name: string; kind: "oidc" | "saml" }
export interface SsoProvider {
  id: string;
  kind: "oidc" | "saml";
  name: string;
  enabled: boolean;
  email_domains: string[];
  auto_create: boolean;
  default_role: OverrideRole;
  secret_store: "openbao" | "database" | "none";
  has_secret: boolean;
  updated_at: string;
  updated_by: string;
  oidc?: { issuer: string; client_id: string; trust_email: boolean; redirect_uri: string };
  saml?: { idp_entity_id: string; sso_url: string; has_certificate: boolean; sp_entity_id: string; acs_url: string };
}
export interface SsoProviderInput {
  kind?: "oidc" | "saml";
  name?: string;
  email_domains?: string[];
  auto_create?: boolean;
  default_role?: OverrideRole;
  enabled?: boolean;
  issuer?: string;
  client_id?: string;
  client_secret?: string;
  trust_email?: boolean;
  idp_metadata_xml?: string;
  idp_entity_id?: string;
  sso_url?: string;
  idp_cert?: string;
}

export interface TokenView {
  id: string;
  name: string;
  prefix: string;
  scopes?: string[];
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}
export const TOKEN_SCOPES: [string, string][] = [
  ["scans:read", "Read scans and Issues"], ["scans:write", "Scan, triage and change Issues"],
  ["ingest:read", "Read imports"], ["ingest:write", "Import reports"],
  ["fixes:read", "Read verified fixes"], ["fixes:write", "Request verified fixes"],
  ["rules:write", "Write automation rules"], ["org:admin", "Run the organization"],
];

/** What the sign-in page says for each `?error=` the API can send back. */
export const SIGNIN_ERRORS: Record<string, string> = {
  expired: "That sign-in took too long. Start again.",
  denied: "Your identity provider did not sign you in.",
  invalid: "That sign-in could not be checked, so it was refused. Start again; if it keeps happening, ask your admin.",
  no_account: "You have no account here yet. Ask an admin to add you.",
  disabled: "Your account is turned off. Ask an admin.",
  domain: "Your identity provider does not sign in that email's domain here.",
  provider: "Single sign-on is not working right now. Ask your admin, or use an API token.",
};
