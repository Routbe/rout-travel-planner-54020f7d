/**
 * Sign-in by recovery, server side. Members are found by e-mail exactly like
 * the sign-in bridge (neon_auth user -> rout_resolve_account in that context);
 * every later read runs in the member's own context.
 */
import { sql, withDbContext } from "@/lib/neon";

export const RECOVERY_CHALLENGE_PREFIX = "rout-recovery:";
export const RECOVERY_CHALLENGE_TTL_MS = 5 * 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function resolveMemberByEmail(email: string): Promise<string | null> {
  const clean = email.trim().toLowerCase();
  const auth = (await sql`select u.id::text as id from neon_auth."user" u where lower(u.email) = ${clean} limit 1`) as { id: string }[];
  const authId = auth[0]?.id;
  if (!authId || !UUID.test(authId)) return null;
  const resolved = (await withDbContext({ userId: authId, workspaceId: null }, () =>
    sql`select user_id::text as user_id from public.rout_resolve_account(${clean})`,
  )) as { user_id: string }[];
  const memberId = resolved[0]?.user_id ?? authId;
  return UUID.test(memberId) ? memberId : null;
}

export type CeremonyRow = {
  ceremony_id: string;
  key_id: string;
  sealed_master: string;
  device_shard: string;
  paper_shard: string;
  server_shard: string;
  device_credential: string;
};

/** The member's ceremony and login key, read in the member's own context. */
export async function ceremonyForMember(memberId: string): Promise<{ row: CeremonyRow; loginKey: string } | null> {
  return withDbContext({ userId: memberId, workspaceId: null }, async () => {
    const rows = (await sql`select * from public.rout_recovery_ceremony_get()`) as CeremonyRow[];
    const key = (await sql`select public.rout_recovery_ceremony_login_key() as k`) as { k: string | null }[];
    const row = rows[0];
    const loginKey = key[0]?.k;
    return row && loginKey ? { row, loginKey } : null;
  });
}

/** The sign-in account behind an active member, or null. */
export async function authIdForMember(memberId: string): Promise<string | null> {
  const rows = (await withDbContext({ userId: memberId, workspaceId: null }, () =>
    sql`select coalesce(auth_user_id::text, user_metadata->>'neon_auth_id') as auth_id from public.users where id = ${memberId}::uuid and coalesce(is_disabled, false) = false limit 1`,
  )) as { auth_id: string | null }[];
  const id = rows[0]?.auth_id;
  return id && UUID.test(id) ? id : null;
}

export function newChallenge(): string {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
