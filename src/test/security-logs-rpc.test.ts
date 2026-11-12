// @vitest-environment node
/**
 * db/0234 + db/0235 over the real SQL (PGlite, as rout_app): security
 * logs, webhook bookkeeping and the SEPA review queue are closed to the app role.
 * Writes without a member session go through validating functions, admins read
 * through session-bound policies, and the audit log stays append-only.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

let db: PGlite;
type Row = Record<string, unknown>;
const MEMBER = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const ENDPOINT = "33333333-3333-4333-8333-333333333333";

async function appCount(query: string, params: unknown[], purge: string): Promise<number> {
  await db.query("select set_config('test.admin', 'off', false), set_config('rout.purge_user_id', $1, false)", [purge]);
  await db.exec("set role rout_app");
  try {
    return (await db.query(query, params)).affectedRows ?? 0;
  } finally {
    await db.exec("reset role");
  }
}
async function asApp(query: string, params: unknown[] = [], opts: { admin?: boolean; purge?: string } = {}): Promise<Row[]> {
  await db.query("select set_config('test.admin', $1, false), set_config('rout.purge_user_id', $2, false)",
    [opts.admin ? "on" : "off", opts.purge ?? ""]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<Row>(query, params)).rows;
  } finally {
    await db.exec("reset role");
  }
}
const owner = async (query: string, params: unknown[] = []) => (await db.query<Row>(query, params)).rows;
const denied = (p: Promise<unknown>) => expect(p).rejects.toThrow(/permission denied/);

const TABLES = ["security_audit_logs", "security_events", "webhook_events", "webhook_deliveries", "sepa_review_queue"];

beforeAll(async () => {
  db = new PGlite();
  await db.exec(`create role rout_app;
    create table public.account_deletions (user_id uuid primary key, cancelled_at timestamptz, completed_at timestamptz,
      purge_after timestamptz not null default now());
    create function public.rout_caller_is_admin() returns boolean language sql stable as $$ select current_setting('test.admin', true) = 'on' $$;
    create function public.rout_purge_due(p_user uuid) returns boolean language sql stable security definer as $$
      select p_user is not null and current_setting('rout.purge_user_id', true) = p_user::text
         and exists (select 1 from public.account_deletions d where d.user_id = p_user and d.cancelled_at is null
                       and d.completed_at is null and d.purge_after <= now()) $$;
    grant execute on function public.rout_caller_is_admin() to rout_app;
    grant execute on function public.rout_purge_due(uuid) to rout_app;
    grant select on public.account_deletions to rout_app;
    create table public.security_audit_checkpoints (day date primary key, last_id bigint, last_hash text, row_count bigint, signature text);
    create table public.security_audit_logs (id bigserial primary key, event_type text not null, user_id text, actor_id text,
      ip_hash text, user_agent_hash text, payload_json jsonb not null default '{}', prev_hash text not null, current_hash text not null,
      created_at timestamptz not null default now());
    create function public.security_audit_chain() returns trigger language plpgsql as $$
    declare prev text;
    begin
      select current_hash into prev from public.security_audit_logs order by id desc limit 1;
      new.prev_hash := coalesce(prev, repeat('0', 64));
      new.created_at := date_trunc('milliseconds', coalesce(new.created_at, now()));
      new.current_hash := encode(sha256(convert_to(new.prev_hash || '|' || new.event_type || '|' || coalesce(new.user_id, '')
        || '|' || new.payload_json::text, 'UTF8')), 'hex');
      return new;
    end $$;
    create function public.security_audit_refuse() returns trigger language plpgsql as $$
    begin
      if tg_op = 'DELETE' then
        if current_setting('rout.audit_retention', true) = 'on' and old.created_at < now() - interval '365 days' then return old; end if;
        if current_setting('rout.purge_user_id', true) = old.user_id and exists (select 1 from public.account_deletions d
           where d.user_id::text = old.user_id and d.cancelled_at is null and d.completed_at is null and d.purge_after <= now()) then return old; end if;
      end if;
      raise exception 'security audit tables are append-only (% refused)', tg_op;
    end $$;
    create trigger security_audit_chain before insert on public.security_audit_logs for each row execute function public.security_audit_chain();
    create trigger security_audit_no_update before delete or update on public.security_audit_logs for each row execute function public.security_audit_refuse();
    create table public.security_events (id uuid primary key default gen_random_uuid(), user_id uuid, kind text not null,
      message text not null, severity text not null default 'info', details jsonb not null default '{}', created_at timestamptz not null default now());
    create table public.webhook_events (id text primary key, source text not null, kind text, created_at timestamptz not null default now(),
      status text not null default 'processing', attempts int not null default 1, result text, error text,
      updated_at timestamptz not null default now(), completed_at timestamptz, direction text, http_status int);
    create table public.webhook_endpoints (id uuid primary key, owner_user_id uuid not null, url text not null,
      secret_ciphertext text not null, secret_iv text not null, active boolean not null default true, events text[] not null default '{}');
    create table public.webhook_deliveries (id uuid primary key default gen_random_uuid(), endpoint_id uuid not null references public.webhook_endpoints,
      event_type text not null, payload_json jsonb not null, attempts int not null default 0, next_attempt_at timestamptz not null default now(),
      last_status int, delivered_at timestamptz, failed_at timestamptz, created_at timestamptz not null default now());
    create table public.sepa_review_queue (id uuid primary key default gen_random_uuid(), payment_id uuid, user_id uuid,
      reason text not null default 'name_mismatch', status text not null default 'open', reference text, amount_cents int,
      expected_cents int, payer_name text, holder_name text, match_score numeric, notes text, decided_by uuid, decided_at timestamptz,
      created_at timestamptz not null default now());
    create unique index sepa_review_open_payment on public.sepa_review_queue (payment_id) where status = 'open' and payment_id is not null;
    insert into public.webhook_endpoints values ('${ENDPOINT}', '${MEMBER}', 'https://example.test/hook', 'ct', 'iv', true, '{payment.done}');`);
  for (const t of TABLES) {
    await db.exec(`grant select, insert, update, delete on public.${t} to rout_app;
      alter table public.${t} enable row level security;
      create policy rout_server on public.${t} to rout_app using (true) with check (true);`);
  }
  for (const f of ["db/0234_security_logs_webhooks_rpc.sql", "db/0235_security_logs_lockdown.sql"]) {
    await db.exec(readFileSync(new URL(`../../${f}`, import.meta.url), "utf8"));
  }
}, 30_000);
afterAll(async () => db?.close());

describe("tables are closed to the app role", () => {
  it("refuses direct writes everywhere and reads of events and deliveries", async () => {
    await denied(asApp("select * from public.security_events"));
    await denied(asApp("select * from public.webhook_deliveries"));
    await denied(asApp("insert into public.webhook_events (id, source) values ('x', 'stripe')"));
    await denied(asApp("insert into public.sepa_review_queue (reason) values ('name_mismatch')"));
    await denied(asApp("insert into public.security_audit_logs (event_type, prev_hash, current_hash) values ('x', '', '')"));
    await denied(asApp("update public.security_audit_logs set event_type = 'x'"));
  });

  it("no other database role can call the functions", async () => {
    await db.exec("create role other_login");
    await db.exec("set role other_login");
    try {
      await expect(db.query("select public.rout_audit_write('a', null, null, null, null, '{}')")).rejects.toThrow(/permission denied/);
      await expect(db.query("select * from public.rout_webhook_delivery_due(5)")).rejects.toThrow(/permission denied/);
    } finally {
      await db.exec("reset role");
    }
  });
});

describe("security events", () => {
  it("stores a valid event and rejects bad severity or kind", async () => {
    await asApp("select public.rout_security_event_write($1::uuid, 'admin_override', 'warning', 'Profile updated.', '{\"a\":1}')", [MEMBER]);
    expect((await owner("select kind, severity from public.security_events"))[0]).toEqual({ kind: "admin_override", severity: "warning" });
    await expect(asApp("select public.rout_security_event_write(null, 'x', 'loud', 'm', '{}')")).rejects.toThrow(/invalid security event/);
    await expect(asApp("select public.rout_security_event_write(null, 'Bad Kind', 'info', 'm', '{}')")).rejects.toThrow(/invalid security event/);
  });
});

describe("hash-chained audit log", () => {
  it("chains entries, reports the head, and refuses to change them", async () => {
    await asApp("select public.rout_audit_write('login', $1, $1, null, null, '{}')", [MEMBER]);
    await asApp("select public.rout_audit_write('login', $1, $1, 'abc123', null, '{}')", [OTHER]);
    const rows = await owner("select prev_hash, current_hash from public.security_audit_logs order by id");
    expect(rows[1]!["prev_hash"]).toBe(rows[0]!["current_hash"]);
    const [head] = await asApp("select id::int as id, n::int as n from public.rout_audit_head(current_date)");
    expect(head).toEqual({ id: 2, n: 2 });
    await expect(asApp("select public.rout_audit_write('login', null, null, 'NOT-HEX', null, '{}')")).rejects.toThrow(/invalid audit entry/);
    // Outside a due purge the app sees no rows to delete; the owner hits the append-only trigger.
    expect(await appCount("delete from public.security_audit_logs", [], "")).toBe(0);
    await expect(owner("delete from public.security_audit_logs")).rejects.toThrow(/append-only/);
  });

  it("retention removes only rows older than 365 days", async () => {
    await owner("insert into public.security_audit_logs (event_type, prev_hash, current_hash, created_at) values ('old', '', '', now() - interval '400 days')");
    const [r] = await asApp("select public.rout_audit_purge_expired() as n");
    expect(r!["n"]).toBe(1);
    expect((await owner("select count(*)::int as n from public.security_audit_logs"))[0]!["n"]).toBe(2);
  });

  it("a due account purge deletes only that member's entries", async () => {
    expect(await appCount("delete from public.security_audit_logs where user_id = $1", [MEMBER], MEMBER)).toBe(0);
    await owner("insert into public.account_deletions (user_id, purge_after) values ($1, now() - interval '1 day')", [MEMBER]);
    expect(await appCount("delete from public.security_audit_logs where user_id = $1", [MEMBER], MEMBER)).toBe(1);
    expect(await appCount("delete from public.security_audit_logs where user_id = $1", [OTHER], MEMBER)).toBe(0);
  });
});

describe("inbound webhook idempotency", () => {
  it("claims once, reopens only after a failure", async () => {
    const claim = async () => (await asApp("select public.rout_webhook_event_claim('evt_1', 'stripe', 'checkout.session.completed') as c"))[0]!["c"];
    expect(await claim()).toBe(true);
    expect(await claim()).toBe(false);
    await asApp("select public.rout_webhook_event_finish('evt_1', 'failed', null, 'boom', 500)");
    expect(await claim()).toBe(true);
    await asApp("select public.rout_webhook_event_finish('evt_1', 'done', 'ok', null, 200)");
    expect(await claim()).toBe(false);
    expect((await owner("select attempts, status from public.webhook_events where id = 'evt_1'"))[0]).toEqual({ attempts: 2, status: "done" });
    await expect(asApp("select public.rout_webhook_event_claim('evt_2', 'evil', null)")).rejects.toThrow(/invalid webhook event/);
  });

  it("logs transport metadata once per id; only admins read the log", async () => {
    const rec = async () => (await asApp("select public.rout_webhook_event_record('inbound:ROUT-AB12', 'banking', 'payment_email', 'inbound', null, 'processing') as r"))[0]!["r"];
    expect(await rec()).toBe(true);
    expect(await rec()).toBe(false);
    expect(await asApp("select id from public.webhook_events")).toHaveLength(0);
    expect((await asApp("select id from public.webhook_events", [], { admin: true })).length).toBe(2);
  });
});

describe("outbound deliveries", () => {
  it("queues for subscribed endpoints and records each attempt", async () => {
    expect((await asApp("select public.rout_webhook_delivery_enqueue($1::uuid, 'payment.done', '{}') as n", [MEMBER]))[0]!["n"]).toBe(1);
    expect((await asApp("select public.rout_webhook_delivery_enqueue($1::uuid, 'other.event', '{}') as n", [MEMBER]))[0]!["n"]).toBe(0);
    const due = await asApp("select id, url from public.rout_webhook_delivery_due(10)");
    expect(due).toHaveLength(1);
    const id = due[0]!["id"];
    expect((await asApp("select public.rout_webhook_delivery_result($1::uuid, 503, 'retry', 60) as a", [id]))[0]!["a"]).toBe(1);
    expect(await asApp("select id from public.rout_webhook_delivery_due(10)")).toHaveLength(0);
    await owner("update public.webhook_deliveries set next_attempt_at = now()");
    expect((await asApp("select public.rout_webhook_delivery_result($1::uuid, 200, 'delivered', null) as a", [id]))[0]!["a"]).toBe(2);
    expect((await asApp("select public.rout_webhook_delivery_result($1::uuid, 200, 'delivered', null) as a", [id]))[0]!["a"]).toBeNull();
  });
});

describe("SEPA review queue", () => {
  it("keeps one open review per payment; only admins read and decide", async () => {
    const q = "select public.rout_sepa_review_queue($1::uuid, $2::uuid, 'name_mismatch', 'ROUT-1', 500, 500, 'J. Doe', 'Jan Doe', 0.6, null) as id";
    const pay = "44444444-4444-4444-8444-444444444444";
    const a = (await asApp(q, [pay, MEMBER]))[0]!["id"];
    const b = (await asApp(q, [pay, MEMBER]))[0]!["id"];
    expect(a).toBe(b);
    expect(await asApp("select id from public.sepa_review_queue")).toHaveLength(0);
    expect(await asApp("update public.sepa_review_queue set status = 'approved' returning id")).toHaveLength(0);
    expect(await asApp("update public.sepa_review_queue set status = 'approved', decided_at = now() returning id", [], { admin: true })).toHaveLength(1);
    await denied(asApp("update public.sepa_review_queue set amount_cents = 1", [], { admin: true }));
  });

  it("a due purge deletes the member's reviews", async () => {
    expect(await appCount("delete from public.sepa_review_queue where user_id = $1", [MEMBER], MEMBER)).toBe(1);
  });
});
