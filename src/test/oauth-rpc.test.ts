// @vitest-environment node
/**
 * db/0228 + db/0230 over the real SQL (PGlite, as rout_app): the ROUT ID tables
 * are closed to the app role; codes, consents, signing keys, test users, review
 * requests and the developer log only move through the database functions, which
 * bind every action to the caller in the transaction context.
 */
import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ALICE = "00000000-0000-4000-8000-00000000000a"; // app owner
const BOB = "00000000-0000-4000-8000-00000000000b"; // end user
const EVE = "00000000-0000-4000-8000-00000000000e"; // stranger
const ADMIN = "00000000-0000-4000-8000-0000000000ad";
const APP_ROW = "00000000-0000-4000-8000-0000000000c1";
const APP = "app_alice";
const TESTING_APP = "app_testing";
const REDIRECT = "https://alice.example/callback";
const b64url = (v: string) => createHash("sha256").update(v).digest("base64url");
let db: PGlite;

type Row = Record<string, unknown>;
async function asApp(user: string | null, query: string, params: unknown[] = [], purge = ""): Promise<Row[]> {
  await db.query("select set_config('rout.current_user_id', $1, false), set_config('rout.user_id', $1, false), set_config('rout.purge_user_id', $2, false)", [user ?? "", purge]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<Row>(query, params)).rows;
  } finally {
    await db.exec("reset role");
  }
}
const issue = (user: string | null, code: string, opts: { redirect?: string; challenge?: string; ttl?: number; client?: string } = {}) =>
  asApp(user, "select public.rout_oauth_code_issue($1, $2, $3, $4, $5, null, null, false, $6) as ok",
    [b64url(code), opts.client ?? APP, opts.redirect ?? REDIRECT, ["openid", "profile"], opts.challenge ?? "", opts.ttl ?? 60]).then((r) => r[0]?.["ok"]);
const consume = (code: string, verifier: string | null, client = APP, redirect = REDIRECT) =>
  asApp(null, "select * from public.rout_oauth_code_consume($1, $2, $3, $4)", [b64url(code), client, redirect, verifier]).then((r) => r[0]!);

beforeAll(async () => {
  db = new PGlite({ extensions: { pgcrypto } });
  await db.exec(`create role rout_app;
    create function public.rout_current_user_id() returns uuid language sql stable
      as $$ select nullif(current_setting('rout.current_user_id', true), '')::uuid $$;
    create table public.account_deletions (user_id uuid primary key, cancelled_at timestamptz, completed_at timestamptz, purge_after timestamptz not null);
    create function public.rout_purge_due(p_user uuid) returns boolean language sql stable security definer as $$
      select exists (select 1 from public.account_deletions d where d.user_id = p_user and d.cancelled_at is null
        and d.completed_at is null and d.purge_after <= now()) and current_setting('rout.purge_user_id', true) = p_user::text $$;
    create table public.user_roles (user_id uuid not null, role text not null);
    create table public.admin_permissions (user_id uuid not null, permission text not null);
    create table public.admin_bootstrap_tokens (token_hash text primary key, consumed_by uuid);
    create function public.rout_caller_has_admin_permission(p text) returns boolean language sql stable security definer as $$
      select exists (select 1 from public.user_roles r where r.user_id = public.rout_current_user_id() and r.role = 'admin') $$;
    create table public.users (id uuid primary key, email text, is_disabled boolean not null default false, account_status text not null default 'active');
    create table public.profiles (id uuid primary key, username text);
    create table public.workspace_members (workspace_id uuid not null, user_id uuid not null, role text not null);
    create table public.oauth_clients (id uuid primary key, owner_user_id uuid, client_id text unique not null, secret_hash text,
      name text not null, homepage_url text, privacy_url text, support_email text, legal_owner text,
      redirect_uris text[] not null default '{}', scopes text[] not null default '{}', status text not null default 'active',
      publishing_status text not null default 'production', workspace_id uuid, created_at timestamptz not null default now(),
      backchannel_webhook_url text, backchannel_webhook_secret_sealed text, backchannel_webhook_secret_iv text);
    create table public.oauth_auth_codes (code_hash text primary key, client_id text not null, user_id uuid not null,
      redirect_uri text not null, scopes text[] not null default '{}', code_challenge text not null, nonce text,
      expires_at timestamptz not null, consumed_at timestamptz, created_at timestamptz not null default now(),
      acr text, auth_time timestamptz, rich_identity boolean not null default false);
    create table public.oauth_consents (user_id uuid not null, client_id text not null, scopes text[] not null default '{}',
      granted_at timestamptz not null default now(), revoked_at timestamptz, primary key (user_id, client_id));
    create table public.oauth_signing_keys (kid text primary key, public_jwk jsonb not null, private_jwk jsonb,
      created_at timestamptz not null default clock_timestamp(), retired_at timestamptz, revoked_at timestamptz, alg text not null default 'ES256',
      private_jwk_sealed text, private_jwk_iv text, kek_fingerprint text);
    create table public.oauth_client_test_users (id uuid primary key default gen_random_uuid(), client_id text not null,
      identifier text not null, created_at timestamptz not null default now(), unique (client_id, identifier));
    create table public.oauth_client_verification_requests (id uuid primary key default gen_random_uuid(), client_id text not null,
      requested_by uuid not null, status text not null default 'pending', note text, reviewed_by uuid, reviewed_at timestamptz,
      created_at timestamptz not null default now());
    create table public.oauth_debug_events (id uuid primary key default gen_random_uuid(), client_id text not null, endpoint text not null,
      outcome text not null, error_code text, detail jsonb not null default '{}', created_at timestamptz not null default now());
    create table public.oauth_access_tokens (id uuid primary key default gen_random_uuid(), token_hash text unique not null,
      client_id text not null, user_id uuid not null, subject text, scopes text[] not null default '{}', family_id uuid,
      expires_at timestamptz not null, revoked_at timestamptz, created_at timestamptz not null default now());
    create table public.oauth_refresh_tokens (id uuid primary key default gen_random_uuid(), family_id uuid not null,
      token_hash text unique not null, client_id text not null, user_id uuid not null, scopes text[] not null default '{}',
      expires_at timestamptz not null, used_at timestamptz, revoked_at timestamptz, subject text, auth_time timestamptz, acr text,
      created_at timestamptz not null default now());
    insert into public.user_roles values ('${ADMIN}', 'admin');
    insert into public.users (id, email) values ('${ALICE}', 'alice@example.com'), ('${BOB}', 'bob@example.com'), ('${EVE}', 'eve@example.com'), ('${ADMIN}', 'admin@example.com');
    insert into public.profiles values ('${BOB}', 'Bobby');
    insert into public.oauth_clients (id, owner_user_id, client_id, secret_hash, name, redirect_uris)
      values ('${APP_ROW}', '${ALICE}', '${APP}', 'v2$hash', 'Alice App', array['${REDIRECT}']);
    insert into public.oauth_clients (id, owner_user_id, client_id, name, redirect_uris, publishing_status)
      values (gen_random_uuid(), '${ALICE}', '${TESTING_APP}', 'Testing App', array['${REDIRECT}'], 'testing');`);
  // Legacy state on the live database: free access for rout_app on the six tables.
  for (const t of ["oauth_auth_codes", "oauth_consents", "oauth_signing_keys", "oauth_client_test_users",
    "oauth_client_verification_requests", "oauth_debug_events"]) {
    await db.exec(`grant select, insert, update, delete on public.${t} to rout_app;
      alter table public.${t} enable row level security;
      create policy rout_server on public.${t} to rout_app using (true) with check (true);`);
  }
  for (const t of ["oauth_access_tokens", "oauth_refresh_tokens"]) {
    await db.exec(`grant select, insert, update on public.${t} to rout_app; alter table public.${t} enable row level security;
      create policy owner on public.${t} to rout_app using (user_id::text = current_setting('rout.user_id', true))
        with check (user_id::text = current_setting('rout.user_id', true));`);
  }
  await db.exec("grant select on public.oauth_clients, public.users, public.profiles to rout_app; alter table public.oauth_clients enable row level security; create policy rout_owner on public.oauth_clients to rout_app using (owner_user_id = public.rout_current_user_id());");
  // 0230 waits in db-pending/ until the deployed code uses the 0228 functions.
  for (const f of ["db/0228_oauth_rpc.sql", "db/0230_oauth_lockdown.sql"]) {
    await db.exec(readFileSync(new URL(`../../${f}`, import.meta.url), "utf8"));
  }
}, 30_000);
afterAll(async () => db?.close());

describe("db/0230 closes the ROUT ID tables", () => {
  it("refuses every direct read of codes, keys, test users, reviews and the developer log", async () => {
    for (const t of ["oauth_auth_codes", "oauth_signing_keys", "oauth_client_test_users", "oauth_client_verification_requests", "oauth_debug_events"]) {
      await expect(asApp(ALICE, `select * from public.${t}`)).rejects.toThrow(/permission denied/);
    }
  });

  it("refuses writing a consent directly, even for oneself", async () => {
    await expect(asApp(BOB, `insert into public.oauth_consents (user_id, client_id) values ('${BOB}', '${APP}')`)).rejects.toThrow(/permission denied/);
  });
});

describe("authorization codes", () => {
  it("are issued only for a signed-in member, an active app and a registered redirect URI", async () => {
    await expect(issue(null, "c-none")).rejects.toThrow(/forbidden/);
    expect(await issue(BOB, "c-bad-redirect", { redirect: "https://evil.example/cb" })).toBe(false);
    expect(await issue(BOB, "c-ok")).toBe(true);
    const owner = (await db.query<Row>("select user_id from public.oauth_auth_codes where code_hash = $1", [b64url("c-ok")])).rows[0];
    expect(owner?.["user_id"]).toBe(BOB);
  });

  it("live at most 10 minutes, whatever the caller asks", async () => {
    await issue(BOB, "c-long", { ttl: 99_999 });
    const r = (await db.query<Row>("select extract(epoch from expires_at - created_at)::int as s from public.oauth_auth_codes where code_hash = $1", [b64url("c-long")])).rows[0];
    expect(Number(r?.["s"])).toBeLessThanOrEqual(601);
  });

  it("are single use and return the member only once", async () => {
    const first = await consume("c-ok", null);
    expect(first["result"]).toBe("ok");
    expect(first["user_id"]).toBe(BOB);
    expect((await consume("c-ok", null))["result"]).toBe("invalid");
  });

  it("check PKCE in the database and burn the code on a wrong verifier", async () => {
    const verifier = "v".repeat(50);
    await issue(BOB, "c-pkce", { challenge: b64url(verifier) });
    expect((await consume("c-pkce", "wrong-verifier"))["result"]).toBe("pkce_failed");
    expect((await consume("c-pkce", verifier))["result"]).toBe("invalid");
    await issue(BOB, "c-pkce2", { challenge: b64url(verifier) });
    expect((await consume("c-pkce2", null))["result"]).toBe("pkce_missing");
    await issue(BOB, "c-pkce3", { challenge: b64url(verifier) });
    const ok = await consume("c-pkce3", verifier);
    expect(ok["result"]).toBe("ok");
    expect(ok["has_pkce"]).toBe(true);
  });

  it("refuse another app and another redirect URI", async () => {
    await issue(BOB, "c-other");
    expect((await consume("c-other", null, TESTING_APP))["result"]).toBe("client_mismatch");
    await issue(BOB, "c-redir");
    expect((await consume("c-redir", null, APP, "https://alice.example/other"))["result"]).toBe("redirect_mismatch");
  });
});

describe("consents and tokens", () => {
  it("merge scopes for the signed-in member and stay private to them", async () => {
    await asApp(BOB, "select public.rout_oauth_consent_grant($1, $2)", [APP, ["openid"]]);
    await asApp(BOB, "select public.rout_oauth_consent_grant($1, $2)", [APP, ["email"]]);
    expect((await asApp(BOB, "select scopes from public.oauth_consents"))[0]?.["scopes"]).toEqual(["email", "openid"]);
    expect(await asApp(EVE, "select * from public.oauth_consents")).toEqual([]);
    expect((await asApp(null, "select public.rout_oauth_consent_active($1::uuid, $2, 'email') as a", [BOB, APP]))[0]?.["a"]).toBe(true);
  });

  it("let only the member revoke their own consent", async () => {
    await asApp(EVE, `update public.oauth_consents set revoked_at = now() where user_id = '${BOB}'`);
    expect((await db.query<Row>("select revoked_at from public.oauth_consents where user_id = $1", [BOB])).rows[0]?.["revoked_at"]).toBeNull();
    await expect(asApp(BOB, `update public.oauth_consents set scopes = '{admin}' where user_id = '${BOB}'`)).rejects.toThrow(/permission denied/);
  });

  it("verify a bearer token without a member context and stop after revocation", async () => {
    await db.query("insert into public.oauth_access_tokens (token_hash, client_id, user_id, subject, expires_at) values ('tok', $1, $2, 'sub-bob', now() + interval '1 hour')", [APP, BOB]);
    const check = () => asApp(null, "select public.rout_oauth_access_token_check('tok', 'sub-bob', $1) as u", [APP]).then((r) => r[0]?.["u"]);
    expect(await check()).toBe(BOB);
    expect(await asApp(null, "select * from public.oauth_access_tokens")).toEqual([]);
    await asApp(null, "select public.rout_oauth_token_revoke('tok', $1)", [APP]);
    expect(await check()).toBeNull();
  });

  it("let the account purge delete consents only when the deletion is due", async () => {
    await asApp(null, `delete from public.oauth_consents where user_id = '${BOB}'`, [], BOB);
    expect((await db.query("select * from public.oauth_consents where user_id = $1", [BOB])).rows).toHaveLength(1);
    await db.query("insert into public.account_deletions values ($1, null, null, now() - interval '1 minute')", [BOB]);
    await asApp(null, `delete from public.oauth_consents where user_id = '${BOB}'`, [], BOB);
    expect((await db.query("select * from public.oauth_consents where user_id = $1", [BOB])).rows).toHaveLength(0);
    await db.query("delete from public.account_deletions");
  });
});

describe("developer console functions", () => {
  it("refuse members who do not manage the app", async () => {
    await expect(asApp(EVE, "select public.rout_oauth_test_users_list($1)", [APP])).rejects.toThrow(/forbidden/);
    await expect(asApp(EVE, "select * from public.rout_oauth_client_code_stats($1)", [APP])).rejects.toThrow(/forbidden/);
    await expect(asApp(EVE, "select public.rout_oauth_verification_request($1, 'x')", [APP])).rejects.toThrow(/forbidden/);
  });

  it("cap test users and let a listed test user into a testing app", async () => {
    expect(await asApp(BOB, "select public.rout_oauth_user_may_use($1) as ok", [TESTING_APP]).then((r) => r[0]?.["ok"])).toBe(false);
    expect((await asApp(ALICE, "select public.rout_oauth_test_user_add($1, 'BOBBY', 1) as r", [TESTING_APP]))[0]?.["r"]).toBe("ok");
    expect((await asApp(ALICE, "select public.rout_oauth_test_user_add($1, 'carol@example.com', 1) as r", [TESTING_APP]))[0]?.["r"]).toBe("limit");
    expect(await asApp(BOB, "select public.rout_oauth_user_may_use($1) as ok", [TESTING_APP]).then((r) => r[0]?.["ok"])).toBe(true);
    expect(await asApp(EVE, "select public.rout_oauth_user_may_use($1) as ok", [TESTING_APP]).then((r) => r[0]?.["ok"])).toBe(false);
  });

  it("allow one open review request per app", async () => {
    expect((await asApp(ALICE, "select public.rout_oauth_verification_request($1, 'please') as r", [APP]))[0]?.["r"]).toBe("ok");
    expect((await asApp(ALICE, "select public.rout_oauth_verification_request($1, 'again') as r", [APP]))[0]?.["r"]).toBe("exists");
  });

  it("show the developer log only for apps the caller manages", async () => {
    await asApp(null, "select public.rout_oauth_debug_log($1, 'token', 'error', 'invalid_grant', '{}'::jsonb)", [APP]);
    await asApp(null, "select public.rout_oauth_debug_log($1, 'bogus', 'error', null, '{}'::jsonb)", [APP]);
    expect(await asApp(ALICE, "select * from public.rout_oauth_debug_list($1, true)", [APP])).toHaveLength(1);
    expect(await asApp(EVE, "select * from public.rout_oauth_debug_activity($1)", [[APP]])).toEqual([]);
  });
});

describe("admin functions", () => {
  it("refuse non-admins", async () => {
    await expect(asApp(ALICE, "select * from public.rout_oauth_admin_apps()")).rejects.toThrow(/forbidden/);
    await expect(asApp(ALICE, "select * from public.rout_oauth_admin_app_decide($1::uuid, 'block')", [APP_ROW])).rejects.toThrow(/forbidden/);
    await expect(asApp(ALICE, "select * from public.rout_oauth_verification_pending()")).rejects.toThrow(/forbidden/);
  });

  it("let an admin block an app, which also burns its open codes", async () => {
    await issue(BOB, "c-before-block");
    const r = await asApp(ADMIN, "select * from public.rout_oauth_admin_app_decide($1::uuid, 'block')", [APP_ROW]);
    expect(r[0]?.["client_id"]).toBe(APP);
    expect((await consume("c-before-block", null))["result"]).toBe("invalid");
    expect(await issue(BOB, "c-after-block")).toBe(false);
    await asApp(ADMIN, "select * from public.rout_oauth_admin_app_decide($1::uuid, 'unblock')", [APP_ROW]);
  });
});

describe("signing keys", () => {
  const pub = JSON.stringify({ kty: "EC", crv: "P-256", x: "x", y: "y" });
  it("only accept sealed keys and retire older ones in the same step", async () => {
    await expect(asApp(null, "select public.rout_oauth_signing_key_rotate('k0', $1::jsonb, null, null, null, 'ES256')", [pub])).rejects.toThrow(/invalid_signing_key/);
    await expect(asApp(null, "select public.rout_oauth_signing_key_rotate('k0', $1::jsonb, 's', 'iv', 'fp', 'ES256')", [JSON.stringify({ d: "secret" })])).rejects.toThrow(/invalid_signing_key/);
    await asApp(null, "select public.rout_oauth_signing_key_rotate('k1', $1::jsonb, 's1', 'iv1', 'fp', 'ES256')", [pub]);
    await asApp(null, "select public.rout_oauth_signing_key_rotate('k2', $1::jsonb, 's2', 'iv2', 'fp', 'ES256')", [pub]);
    const keys = await asApp(null, "select kid, retired_at from public.rout_oauth_signing_keys_list()");
    expect(keys.find((k) => k["kid"] === "k1")?.["retired_at"]).not.toBeNull();
    expect(keys.find((k) => k["kid"] === "k2")?.["retired_at"]).toBeNull();
  });

  it("wipe private parts of retired keys only", async () => {
    expect((await asApp(null, "select public.rout_oauth_signing_keys_wipe($1) as n", [["k1", "k2"]]))[0]?.["n"]).toBe(1);
    const k2 = (await db.query<Row>("select private_jwk_sealed from public.oauth_signing_keys where kid = 'k2'")).rows[0];
    expect(k2?.["private_jwk_sealed"]).toBe("s2");
  });
});

describe("account purge of codes", () => {
  it("deletes a member's codes only when their deletion is due, and never reveals codes", async () => {
    await issue(EVE, "c-eve");
    await asApp(null, `delete from public.oauth_auth_codes where user_id = '${EVE}'`, [], EVE);
    expect((await db.query("select * from public.oauth_auth_codes where user_id = $1", [EVE])).rows).toHaveLength(1);
    await db.query("insert into public.account_deletions values ($1, null, null, now() - interval '1 minute')", [EVE]);
    await expect(asApp(null, "select code_hash from public.oauth_auth_codes", [], EVE)).rejects.toThrow(/permission denied/);
    await asApp(null, `delete from public.oauth_auth_codes where user_id = '${EVE}'`, [], EVE);
    expect((await db.query("select * from public.oauth_auth_codes where user_id = $1", [EVE])).rows).toHaveLength(0);
    await db.query("delete from public.account_deletions");
  });
});
