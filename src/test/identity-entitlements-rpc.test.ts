// @vitest-environment node
/**
 * db/0236 + db/0237 over the real SQL (PGlite, as rout_app): identity,
 * credential and entitlement tables are closed to the app role. Covers the
 * owner's rules: the Plus credit cannot be spent twice, the Didit cap holds,
 * referrals keep one inviter, merge tickets are found only by exact hash, and
 * identity labels stay with their own member.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { earlyVerifiedGrants } from "@/lib/entitlement-engine";

let db: PGlite;
type Row = Record<string, unknown>;
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const OLD = "33333333-3333-4333-8333-333333333333";
const WS = "44444444-4444-4444-8444-444444444444";
const ACC_A = "55555555-5555-4555-8555-555555555555";
const ACC_B = "66666666-6666-4666-8666-666666666666";
const H1 = "a".repeat(43) + "=";
const H2 = "b".repeat(43) + "=";

async function asApp(query: string, params: unknown[] = [], opts: { user?: string; admin?: boolean } = {}): Promise<Row[]> {
  await db.query("select set_config('rout.current_user_id', $1, false), set_config('test.admin', $2, false)",
    [opts.user ?? "", opts.admin ? "on" : "off"]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<Row>(query, params)).rows;
  } finally {
    await db.exec("reset role");
  }
}
const owner = async (query: string, params: unknown[] = []) => (await db.query<Row>(query, params)).rows;
const one = async (query: string, params: unknown[] = [], opts = {}) => Object.values((await asApp(query, params, opts))[0] ?? {})[0];
const denied = (p: Promise<unknown>) => expect(p).rejects.toThrow(/permission denied/);

const TABLES = ["credential_issue_requests", "credential_issuer_blocks", "identity_labels", "account_merge_tickets",
  "api_keys", "reserved_handles", "badges", "entitlement_overrides", "referrals", "didit_monthly_usage"];

beforeAll(async () => {
  db = new PGlite();
  await db.exec(`create role rout_app; create schema neon_auth;
    create function public.rout_current_user_id() returns uuid language sql stable as $$ select nullif(current_setting('rout.current_user_id', true), '')::uuid $$;
    create function public.rout_caller_is_admin() returns boolean language sql stable as $$ select current_setting('test.admin', true) = 'on' $$;
    create table public.workspace_members (workspace_id uuid, user_id uuid, role text);
    create function public.rout_is_workspace_member(ws uuid) returns boolean language sql stable security definer as $$
      select exists (select 1 from public.workspace_members m where m.workspace_id = ws and m.user_id = public.rout_current_user_id()) $$;
    grant execute on all functions in schema public to rout_app;
    create table neon_auth.account (id uuid primary key, "providerId" text not null, "userId" uuid not null);
    create table public.users (id uuid primary key, auth_user_id uuid, created_at timestamptz not null default now());
    create table public.profiles (id uuid primary key, verified boolean not null default false, is_early_verified boolean not null default false);
    create table public.credential_issue_requests (issuer_id uuid, request_key text, badge_id uuid, recipient_id uuid, created_at timestamptz default now());
    create table public.credential_issuer_blocks (recipient_id uuid, issuer_id uuid, created_at timestamptz default now());
    create table public.identity_labels (account_id text primary key, provider text not null, label text not null, updated_at timestamptz not null default now());
    create table public.account_merge_tickets (id uuid primary key default gen_random_uuid(), primary_user_id uuid not null, pin_hash text not null,
      token_hash text not null, expires_at timestamptz not null, used_at timestamptz, secondary_user_id uuid, created_at timestamptz not null default now(), preview_user_id uuid);
    create table public.api_keys (id uuid primary key default gen_random_uuid(), user_id uuid not null, name text not null, key_hash text not null,
      key_prefix text not null, scopes text[] not null default '{}', rate_limit int not null default 60, request_count int not null default 0,
      last_used_at timestamptz, revoked_at timestamptz, created_at timestamptz not null default now(), updated_at timestamptz not null default now(), workspace_id uuid);
    create table public.reserved_handles (handle text primary key, reason text not null, label text, created_at timestamptz not null default now());
    create table public.badges (id uuid primary key default gen_random_uuid(), slug text unique not null, name text not null);
    create table public.entitlement_overrides (id uuid primary key default gen_random_uuid(), scope_type text not null, scope_id uuid not null,
      entitlement_key text not null, value text not null, granted_by text not null default 'system', created_at timestamptz not null default now());
    create unique index on public.entitlement_overrides (scope_type, scope_id, entitlement_key);
    create table public.referrals (id uuid primary key default gen_random_uuid(), inviter_id uuid not null, invitee_id uuid not null unique,
      verified boolean not null default false, created_at timestamptz not null default now(), verified_at timestamptz);
    create table public.didit_monthly_usage (month date primary key, success_count int not null);
    create function public.grant_early_verified_promo() returns trigger language plpgsql as $$
    begin
      if new.verified and not coalesce(old.verified, false) then
        new.is_early_verified := true;
        insert into public.entitlement_overrides (scope_type, scope_id, entitlement_key, value, granted_by)
        values ('user', new.id, 'PRO_FOR_LIFE', 'true', 'early_verified_promo'), ('user', new.id, 'INCLUDED_PLUS_WORKSPACE', '1', 'early_verified_promo')
        on conflict (scope_type, scope_id, entitlement_key) do nothing;
      end if;
      return new;
    end $$;
    create trigger profiles_early_verified_promo before update of verified on public.profiles for each row execute function public.grant_early_verified_promo();
    grant select, update on public.profiles to rout_app;
    insert into public.users (id, auth_user_id) values ('${A}', '${A}'), ('${B}', '${B}');
    insert into public.users (id, created_at) values ('${OLD}', now() - interval '2 days');
    insert into public.profiles (id) values ('${A}'), ('${B}');
    insert into neon_auth.account values ('${ACC_A}', 'google', '${A}'), ('${ACC_B}', 'github', '${B}');
    insert into public.workspace_members values ('${WS}', '${A}', 'owner');
    insert into public.badges (slug, name) values ('verified', 'Verified');
    insert into public.reserved_handles (handle, reason) values ('admin', 'system');`);
  for (const t of TABLES) {
    await db.exec(`grant select, insert, update, delete on public.${t} to rout_app;
      alter table public.${t} enable row level security;
      create policy rout_server on public.${t} to rout_app using (true) with check (true);`);
  }
  for (const f of ["db/0236_identity_entitlements_rpc.sql", "db/0237_identity_entitlements_lockdown.sql"]) {
    await db.exec(readFileSync(new URL(`../../${f}`, import.meta.url), "utf8"));
  }
}, 30_000);
afterAll(async () => db?.close());

describe("tables are closed to the app role", () => {
  it("refuses direct access except the public catalogues and the owner's api keys", async () => {
    for (const t of ["credential_issue_requests", "credential_issuer_blocks", "identity_labels", "account_merge_tickets",
      "entitlement_overrides", "referrals", "didit_monthly_usage"]) await denied(asApp(`select * from public.${t}`));
    expect(await asApp("select slug from public.badges")).toHaveLength(1);
    expect(await asApp("select handle from public.reserved_handles")).toHaveLength(1);
    await denied(asApp("insert into public.badges (slug, name) values ('x', 'X')"));
    await denied(asApp("delete from public.reserved_handles"));
  });

  it("a member sees and manages only their own api keys", async () => {
    await asApp("insert into public.api_keys (user_id, name, key_hash, key_prefix) values ($1, 'k', 'h', 'p')", [A], { user: A });
    await expect(asApp("insert into public.api_keys (user_id, name, key_hash, key_prefix) values ($1, 'k', 'h', 'p')", [B], { user: A }))
      .rejects.toThrow(/row-level security/);
    await expect(asApp("insert into public.api_keys (user_id, name, key_hash, key_prefix, workspace_id) values ($1, 'k', 'h', 'p', $2)", [B, WS], { user: B }))
      .rejects.toThrow(/row-level security/);
    expect(await asApp("select id from public.api_keys", [], { user: B })).toHaveLength(0);
    expect(await asApp("update public.api_keys set revoked_at = now() returning id", [], { user: B })).toHaveLength(0);
    expect(await asApp("update public.api_keys set revoked_at = now() returning id", [], { user: A })).toHaveLength(1);
    await denied(asApp("update public.api_keys set key_hash = 'x'", [], { user: A }));
  });
});

describe("entitlements", () => {
  it("the verified trigger still grants after the lockdown", async () => {
    await asApp("update public.profiles set verified = true where id = $1", [A]);
    const rows = await asApp("select entitlement_key, value from public.rout_entitlement_overrides('user', $1::uuid) order by 1", [A]);
    expect(rows).toEqual(earlyVerifiedGrants(A).map((g) => ({ entitlement_key: g.entitlement_key, value: g.value })).sort((x, y) => x.entitlement_key.localeCompare(y.entitlement_key)));
    expect(await one("select public.rout_workspace_owner_pro_for_life($1::uuid)", [WS])).toBe(true);
  });

  it("the early-verified grant needs a verified member", async () => {
    expect(await one("select public.rout_entitlement_grant_early_verified($1::uuid)", [B])).toBe(false);
    expect(await asApp("select * from public.rout_entitlement_overrides('user', $1::uuid)", [B])).toHaveLength(0);
  });

  it("the single Plus credit is spent once, only on an owned workspace", async () => {
    expect(await one("select public.rout_entitlement_redeem_plus($1::uuid, $2::uuid)", [B, WS])).toBe("forbidden");
    expect(await one("select public.rout_entitlement_redeem_plus($1::uuid, $2::uuid)", [A, WS])).toBe("ok");
    expect(await one("select public.rout_entitlement_redeem_plus($1::uuid, $2::uuid)", [A, WS])).toBe("no_credit");
    expect(await asApp("select value from public.rout_entitlement_overrides('workspace', $1::uuid)", [WS])).toEqual([{ value: "plus" }]);
  });
});

describe("referrals", () => {
  it("one inviter per member, never yourself, only for a new account", async () => {
    expect(await one("select public.rout_referral_claim($1::uuid, $1::uuid)", [B])).toBe(false);
    expect(await one("select public.rout_referral_claim($1::uuid, $2::uuid)", [A, OLD])).toBe(false);
    expect(await one("select public.rout_referral_claim($1::uuid, $2::uuid)", [A, B])).toBe(true);
    expect(await one("select public.rout_referral_claim($1::uuid, $2::uuid)", [OLD, B])).toBe(false);
    expect(await one("select public.rout_referral_mark_verified($1::uuid)", [B])).toBe(A);
    expect(await one("select public.rout_referral_mark_verified($1::uuid)", [B])).toBeNull();
    expect((await asApp("select invited, verified_invites from public.rout_referral_counts($1::uuid)", [A]))[0]).toEqual({ invited: 1, verified_invites: 1 });
  });
});

describe("Didit monthly cap", () => {
  it("counts up to the limit and releases", async () => {
    expect(await one("select public.rout_didit_usage_bump(2)")).toBe(true);
    expect(await one("select public.rout_didit_usage_bump(2)")).toBe(true);
    expect(await one("select public.rout_didit_usage_bump(2)")).toBe(false);
    await asApp("select public.rout_didit_usage_release()");
    expect(await one("select public.rout_didit_usage_count()")).toBe(1);
  });
});

describe("identity labels", () => {
  it("only the account's own member or an admin reads and writes its label", async () => {
    expect(await one("select public.rout_identity_label_put($1, 'google', 'a@example.test')", [ACC_A], { user: A })).toBe(true);
    expect(await one("select public.rout_identity_label_put($1, 'github', 'stolen')", [ACC_B], { user: A })).toBe(false);
    expect(await asApp("select label from public.rout_identity_labels_get($1::text[])", [[ACC_A, ACC_B]], { user: A })).toEqual([{ label: "a@example.test" }]);
    expect(await asApp("select label from public.rout_identity_labels_get($1::text[])", [[ACC_A]], { user: B })).toHaveLength(0);
    expect(await asApp("select label from public.rout_identity_labels_get($1::text[])", [[ACC_A]], { admin: true })).toHaveLength(1);
  });
});

describe("account merge tickets", () => {
  it("one live ticket per member, found only by exact hash, bound to the first previewer", async () => {
    await asApp("select * from public.rout_merge_ticket_create($1::uuid, $2, $3, 5)", [A, H1, H2]);
    const [t] = await asApp("select * from public.rout_merge_ticket_create($1::uuid, $2, $3, 5)", [A, H2, H1]);
    expect((await owner("select count(*)::int as n from public.account_merge_tickets where used_at is null"))[0]!["n"]).toBe(1);
    expect(await asApp("select id from public.rout_merge_ticket_find($1)", ["%"])).toHaveLength(0);
    expect((await asApp("select id from public.rout_merge_ticket_find($1)", [H1]))[0]!["id"]).toBe(t!["id"]);
    expect(await one("select public.rout_merge_ticket_bind($1::uuid, $2::uuid)", [t!["id"], A])).toBe(false);
    expect(await one("select public.rout_merge_ticket_bind($1::uuid, $2::uuid)", [t!["id"], B])).toBe(true);
    expect(await one("select public.rout_merge_ticket_bind($1::uuid, $2::uuid)", [t!["id"], OLD])).toBe(false);
    await expect(asApp("select * from public.rout_merge_ticket_create($1::uuid, 'short', $2, 5)", [A, H2])).rejects.toThrow(/invalid ticket/);
  });
});
