import { sql, withDbContext } from "@/lib/neon";
import { authenticateOAuthClient, OAuthError, issuer, sha256Base64Url, signJwt, verifyAccessToken, identityClaims } from "./provider.server";

export async function exchangeRefreshToken(input: { token: string; clientId: string; clientSecret: string | null; ip: string | null; requestedScope?: string | null }) {
  const client = await authenticateOAuthClient(input.clientId, input.clientSecret, input.ip);
  const next = crypto.randomUUID() + crypto.randomUUID();
  const rows = await sql`select * from public.rotate_oauth_refresh(${await sha256Base64Url(input.token)},${client.clientId},${await sha256Base64Url(next)})`;
  const row = rows[0];
  if (!row || row["result"] !== "ok") throw new OAuthError("invalid_grant", "Refresh token is ongeldig of hergebruikt.");
  // The rest acts for this member (owner-scoped claims and tokens); the token
  // endpoint itself has no session.
  return withDbContext({ userId: String(row["user_id"]), workspaceId: null }, async () => {
  const now = Math.floor(Date.now()/1000);
  // OIDC: a refresh request may narrow the scope set, never widen it or name
  // scopes outside the whitelist — anything else is invalid_scope (Cluster C).
  const { resolveRefreshScopes } = await import("./scope-rules");
  const requested = input.requestedScope?.split(" ").filter(Boolean) ?? null;
  const resolved = resolveRefreshScopes(requested, row["scopes"] as string[]);
  if (!resolved.ok) throw new OAuthError("invalid_scope", `Deze scope is niet toegekend: ${resolved.unknown}.`);
  const scopes = resolved.scopes;
  // Agent grants are ephemeral: at most one hour per access token.
  const { agentTokenTtl } = await import("@/lib/agent/agent-scopes");
  const ttl = agentTokenTtl(client.accessTokenTtl, scopes);
  // Re-derive the subject: rows from before the vault may hold a legacy value (even a raw id).
  const { resolveScopedSubject } = await import("./subject-vault.server");
  const subject = (await resolveScopedSubject(client, String(row["user_id"]))).sub;
  const token = await signJwt({ iss: issuer(), sub: subject, aud: client.clientId, iat: now, exp: now+ttl, scope: scopes.join(" "), token_use: "access", jti: crypto.randomUUID() });
  const claims = await identityClaims(String(row["user_id"]), scopes, { handleSync: client.handleSyncEnabled, clientId: client.clientId });
  const { HANDLE_RESERVATION_CLAIM, HANDLE_RESERVATION_SCOPE } = await import("./handle-reservation");
  if (scopes.includes(HANDLE_RESERVATION_SCOPE)) {
    const { handleReservationClaim } = await import("./handle-reservation.server");
    claims[HANDLE_RESERVATION_CLAIM] = await handleReservationClaim(String(row["user_id"]), client.clientId, subject);
  }
  const idToken = await signJwt({ iss: issuer(), sub: subject, aud: client.clientId, iat: now, exp: now+ttl, token_use: "id",
    ...(row["auth_time"] ? { auth_time: Math.floor(new Date(String(row["auth_time"])).getTime()/1000) } : {}), ...(row["acr"] ? { acr: row["acr"] } : {}), ...claims });
  // The family lock and status check are repeated when persisting the access token.
  const batch = await sql.transaction([
    sql`select pg_advisory_xact_lock(hashtextextended(${String(row["family_id"])},0))`,
    sql`insert into public.oauth_access_tokens(token_hash,client_id,user_id,subject,scopes,family_id,expires_at)
      select ${await sha256Base64Url(token)},${client.clientId},${row["user_id"]},${subject},${scopes},${row["family_id"]},${new Date((now+ttl)*1000).toISOString()}
      where not exists(select 1 from public.oauth_refresh_tokens r where r.family_id=${row["family_id"]} and r.revoked_at is not null)
      returning token_hash`,
  ]);
  if (!batch[1]?.length) throw new OAuthError("invalid_grant", "Refreshfamilie is ingetrokken.");
  return { access_token: token, id_token: idToken, refresh_token: next, token_type: "Bearer", expires_in: ttl, scope: scopes.join(" ") };
  });
}

export async function revokeOAuthToken(token: string, clientId: string) {
  const hash = await sha256Base64Url(token);
  // No member context at the revocation endpoint: one database step (db/0228).
  await sql`select public.rout_oauth_token_revoke(${hash}, ${clientId})`;
}

export async function introspectOAuthToken(token: string, clientId: string) {
  try {
    const verified = await verifyAccessToken(token);
    if (verified.clientId !== clientId) return { active: false };
    // Revoked, expired or consent-withdrawn tokens are never reported active.
    const rows = await sql`select * from public.rout_oauth_access_token_introspect(${await sha256Base64Url(token)}, ${clientId})`;
    const row = rows[0];
    if (!row) return { active: false };
    return { active: true, client_id: clientId, sub: verified.sub, scope: verified.scopes.join(" "), token_type: "Bearer", iss: issuer(),
      exp: Math.floor(new Date(String(row["expires_at"])).getTime()/1000), iat: Math.floor(new Date(String(row["created_at"])).getTime()/1000) };
  } catch {
    const rows = await sql`select * from public.rout_oauth_refresh_token_introspect(${await sha256Base64Url(token)}, ${clientId})`;
    const row = rows[0];
    if (!row) return { active: false };
    const { scopedSubjectForClientId } = await import("./subject-vault.server");
    const sub = await scopedSubjectForClientId(String(row["user_id"]), clientId);
    return { active: true, client_id: clientId, sub, scope: (row["scopes"] as string[]).join(" "), token_type: "refresh_token", exp: Math.floor(new Date(String(row["expires_at"])).getTime()/1000) };
  }
}