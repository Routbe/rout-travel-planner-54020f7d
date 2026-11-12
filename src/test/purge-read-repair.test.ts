// @vitest-environment node
/**
 * db/0228 repair section over the real SQL (PGlite, as rout_app): the account
 * purge can read and delete a member's first-admin token and role rows only
 * while that member's deletion is due; nobody else can read them.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const BOB = "00000000-0000-4000-8000-00000000000b";
let db: PGlite;

async function asApp(purge: string, query: string) {
  await db.query("select set_config('rout.current_user_id', '', false), set_config('rout.purge_user_id', $1, false)", [purge]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<Record<string, unknown>>(query)).rows;
  } finally {
    await db.exec("reset role");
  }
}

beforeAll(async () => {
  db = new PGlite();
  await db.exec(`create role rout_app;
    create table public.account_deletions (user_id uuid primary key, cancelled_at timestamptz, completed_at timestamptz, purge_after timestamptz not null);
    create function public.rout_purge_due(p_user uuid) returns boolean language sql stable security definer as $$
      select exists (select 1 from public.account_deletions d where d.user_id = p_user and d.cancelled_at is null
        and d.completed_at is null and d.purge_after <= now()) and current_setting('rout.purge_user_id', true) = p_user::text $$;
    create table public.admin_bootstrap_tokens (token_hash text primary key, consumed_by uuid);
    create table public.user_roles (user_id uuid not null, role text not null);
    create table public.admin_permissions (user_id uuid not null, permission text not null);
    alter table public.admin_bootstrap_tokens enable row level security;
    alter table public.user_roles enable row level security;
    alter table public.admin_permissions enable row level security;
    grant delete on public.admin_bootstrap_tokens to rout_app;
    grant select, delete on public.user_roles, public.admin_permissions to rout_app;
    create policy rout_owner_purge on public.admin_bootstrap_tokens for delete to rout_app using (public.rout_purge_due(consumed_by));
    create policy rout_owner_purge on public.user_roles for delete to rout_app using (public.rout_purge_due(user_id));
    create policy rout_owner_purge on public.admin_permissions for delete to rout_app using (public.rout_purge_due(user_id));
    insert into public.admin_bootstrap_tokens values ('h', '${BOB}');
    insert into public.user_roles values ('${BOB}', 'admin');
    insert into public.admin_permissions values ('${BOB}', 'manage_admins');`);
  const rpc = readFileSync(new URL("../../db/0228_oauth_rpc.sql", import.meta.url), "utf8");
  const start = rpc.indexOf("-- ------------------------------------------------------------------ repair: account purge after 0227");
  const end = rpc.indexOf("-- ------------------------------------------------------------------ privileges");
  await db.exec(rpc.slice(start, end));
}, 30_000);
afterAll(async () => db?.close());

describe("account purge after 0227", () => {
  it("cannot touch the rows before the deletion is due", async () => {
    await asApp(BOB, `delete from public.admin_bootstrap_tokens where consumed_by = '${BOB}'`);
    expect((await db.query("select * from public.admin_bootstrap_tokens")).rows).toHaveLength(1);
    expect(await asApp(BOB, "select * from public.user_roles")).toEqual([]);
  });

  it("deletes the token and role rows once due, without exposing the token hash", async () => {
    await db.query("insert into public.account_deletions values ($1, null, null, now() - interval '1 minute')", [BOB]);
    await expect(asApp(BOB, "select token_hash from public.admin_bootstrap_tokens")).rejects.toThrow(/permission denied/);
    await asApp(BOB, `delete from public.admin_bootstrap_tokens where consumed_by = '${BOB}'`);
    await asApp(BOB, `delete from public.user_roles where user_id = '${BOB}'`);
    await asApp(BOB, `delete from public.admin_permissions where user_id = '${BOB}'`);
    for (const t of ["admin_bootstrap_tokens", "user_roles", "admin_permissions"]) {
      expect((await db.query(`select * from public.${t}`)).rows).toHaveLength(0);
    }
  });
});
