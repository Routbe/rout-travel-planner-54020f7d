// @vitest-environment node
/**
 * db/0238 + db/0240 and their contracts db/0239 + 0241 over the real SQL
 * (PGlite, as rout_app): the last 14 tables with free app access are closed.
 * Covers the owner's rules: one poll vote per voter, QR scans and link clicks
 * visible only to their owner (or colleagues/admins), forms only for profiles
 * that show them, a booking or contact outcome decided once, background jobs
 * never claimed twice, confirmation-mail limits and admin-only switches.
 */
import { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

let db: PGlite;
type Row = Record<string, unknown>;
const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const C = "33333333-3333-4333-8333-333333333333";
const WS = "44444444-4444-4444-8444-444444444444";
const QA = "55555555-5555-4555-8555-555555555555";
const QW = "66666666-6666-4666-8666-666666666666";
const KEY = "a".repeat(64);

async function asApp(query: string, params: unknown[] = [], opts: { user?: string; admin?: boolean; purge?: string } = {}): Promise<Row[]> {
  await db.query("select set_config('rout.current_user_id', $1, false), set_config('test.admin', $2, false), set_config('test.purge', $3, false)",
    [opts.user ?? "", opts.admin ? "on" : "off", opts.purge ?? ""]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<Row>(query, params)).rows;
  } finally {
    await db.exec("reset role");
  }
}
const one = async (query: string, params: unknown[] = [], opts = {}) => Object.values((await asApp(query, params, opts))[0] ?? {})[0];
const owner = async (query: string, params: unknown[] = []) => (await db.query<Row>(query, params)).rows;
const denied = (p: Promise<unknown>) => expect(p).rejects.toThrow(/permission denied/);

const TABLES = ["links", "profile_link_clicks", "qr_scans", "poll_votes", "showcase_profiles", "lead_captures",
  "contact_submissions", "onboarding_drafts", "availability_jobs", "booking_requests", "alias_sync_jobs",
  "forwarding_confirmation_sends", "ambient_weather_cache", "platform_integration_switches"];

beforeAll(async () => {
  db = new PGlite();
  await db.exec(`create role rout_app;
    create function public.rout_current_user_id() returns uuid language sql stable as $$ select nullif(current_setting('rout.current_user_id', true), '')::uuid $$;
    create function public.rout_caller_is_admin() returns boolean language sql stable as $$ select current_setting('test.admin', true) = 'on' $$;
    create function public.rout_caller_has_admin_permission(p text) returns boolean language sql stable as $$ select current_setting('test.admin', true) = 'on' $$;
    create function public.rout_purge_due(p uuid) returns boolean language sql stable as $$ select current_setting('test.purge', true) = p::text $$;
    create table public.workspace_members (workspace_id uuid, user_id uuid, role text);
    create function public.rout_is_workspace_member(ws uuid) returns boolean language sql stable security definer as $$
      select exists (select 1 from public.workspace_members m where m.workspace_id = ws and m.user_id = public.rout_current_user_id()) $$;
    grant execute on all functions in schema public to rout_app;
    create table public.users (id uuid primary key, email text);
    create table public.profiles (id uuid primary key, username text, blocks jsonb not null default '[]');
    create table public.alias_profiles (user_id uuid, handle text);
    create table public.tracked_qrs (id uuid primary key, user_id uuid, workspace_id uuid, dashboard_token text);
    create table public.user_integrations (provider text);
    create table public.links (id uuid primary key default gen_random_uuid(), profile_id uuid not null, title text not null, url text not null,
      position int not null default 0, workspace_id uuid);
    create table public.profile_link_clicks (id bigserial primary key, profile_user_id uuid, handle text not null, block_id text not null,
      label text, space text not null default 'alias', visitor_hash text, created_at timestamptz not null default now());
    create table public.qr_scans (id uuid primary key default gen_random_uuid(), tracked_qr_id uuid not null references public.tracked_qrs(id) on delete cascade,
      scanned_at timestamptz not null default now(), country text, device text, browser text, os text);
    create table public.poll_votes (id uuid primary key default gen_random_uuid(), poll_key text not null, option_index int not null check (option_index >= 0 and option_index < 6),
      voter_key text not null, created_at timestamptz not null default now(), unique (poll_key, voter_key));
    create table public.showcase_profiles (id uuid primary key default gen_random_uuid(), handle text not null unique, display_name text not null,
      sort_order int not null default 0, position int not null default 0, created_at timestamptz not null default now());
    create table public.lead_captures (id uuid primary key default gen_random_uuid(), handle text not null, name text, email text not null, message text,
      created_at timestamptz not null default now());
    create table public.contact_submissions (id uuid primary key default gen_random_uuid(), name text not null, email text not null, subject text not null,
      message text not null, locale text not null default 'en', status text not null default 'pending', error_detail text, sender_hash text,
      created_at timestamptz not null default now(), updated_at timestamptz not null default now(), portal_category text, category text, priority text,
      meta jsonb, attachment_key text, attachment_name text, attachment_size bigint, attachment_mime text);
    create table public.onboarding_drafts (email text primary key, draft jsonb not null, updated_at timestamptz not null default now());
    create table public.availability_jobs (user_id uuid primary key, reason text not null, run_after timestamptz not null default now(), attempts int not null default 0);
    create table public.booking_requests (id uuid primary key default gen_random_uuid(), profile_id uuid not null, guest_name text not null, guest_email text not null,
      preferred_date date not null, preferred_time text not null, guest_message text, duration_minutes int not null default 30, title text,
      status text not null default 'pending', created_at timestamptz not null default now(), updated_at timestamptz not null default now());
    create table public.alias_sync_jobs (id uuid primary key default gen_random_uuid(), user_id uuid not null, action text not null, status text not null default 'pending',
      attempts int not null default 0, max_attempts int not null default 5, payload jsonb not null default '{}', last_error text,
      created_at timestamptz not null default now(), updated_at timestamptz not null default now());
    create table public.forwarding_confirmation_sends (id bigserial primary key, user_id uuid not null, recipient text not null, sent_at timestamptz not null default now());
    create table public.ambient_weather_cache (city_key text primary key, state text, checked_at timestamptz, refresh_after timestamptz not null default now());
    create table public.platform_integration_switches (provider text primary key, mode text not null default 'on', note text, updated_by uuid,
      updated_at timestamptz not null default now());
    insert into public.users values ('${A}', 'a@example.com'), ('${B}', 'b@example.com'), ('${C}', 'c@example.com');
    insert into public.profiles values
      ('${A}', 'anna', '[{"kind":"contact_form","value":"{}"},{"kind":"booking_request","value":"{}"}]'),
      ('${B}', 'bert', '[{"kind":"contact_form","hidden":true}]'),
      ('${C}', 'cleo', '[]');
    insert into public.alias_profiles values ('${C}', 'cleo.alias');
    insert into public.workspace_members values ('${WS}', '${A}', 'owner'), ('${WS}', '${C}', 'member');
    insert into public.tracked_qrs values ('${QA}', '${A}', null, 'tok-a'), ('${QW}', '${A}', '${WS}', 'tok-w');
    insert into public.platform_integration_switches (provider, mode, note) values ('spotify', 'paused', 'internal note');`);
  for (const t of TABLES) {
    await db.exec(`grant select, insert, update, delete on public.${t} to rout_app;
      alter table public.${t} enable row level security;
      create policy rout_server on public.${t} to rout_app using (true) with check (true);`);
  }
  await db.exec("grant usage on sequence public.profile_link_clicks_id_seq, public.forwarding_confirmation_sends_id_seq to rout_app");
  for (const f of ["db/0238_public_profiles_stats_rpc.sql", "db/0239_public_profiles_stats_lockdown.sql",
    "db/0240_agenda_jobs_cache_rpc.sql", "db/0241_agenda_jobs_cache_lockdown.sql"]) {
    await db.exec(readFileSync(new URL(`../../${f}`, import.meta.url), "utf8"));
  }
  await owner(`insert into public.qr_scans (tracked_qr_id) values ('${QA}'), ('${QA}'), ('${QW}')`);
  await owner(`insert into public.links (profile_id, title, url) values ('${A}', 'a', 'https://a'), ('${B}', 'b', 'https://b')`);
}, 30_000);
afterAll(async () => db?.close());

describe("tables are closed to the app role", () => {
  it("refuses every direct write and the job, cache and draft tables entirely", async () => {
    for (const t of ["poll_votes", "onboarding_drafts", "availability_jobs", "alias_sync_jobs", "forwarding_confirmation_sends", "ambient_weather_cache"])
      await denied(asApp(`select * from public.${t}`, [], { user: A }));
    await denied(asApp(`insert into public.qr_scans (tracked_qr_id) values ('${QA}')`, [], { user: A }));
    await denied(asApp("insert into public.profile_link_clicks (handle, block_id) values ('anna', 'x')"));
    await denied(asApp("insert into public.lead_captures (handle, email) values ('anna', 'x@y.z')"));
    await denied(asApp("insert into public.contact_submissions (name, email, subject, message) values ('n', 'e@x', 's', 'm')"));
    await denied(asApp("insert into public.showcase_profiles (handle, display_name) values ('x', 'x')", [], { admin: true }));
    await denied(asApp("update public.booking_requests set status = 'accepted'", [], { user: A }));
    await denied(asApp("insert into public.platform_integration_switches (provider) values ('x')", [], { admin: true }));
  });
});

describe("batch 8: public profiles and statistics", () => {
  it("QR scans are visible to the code's owner, workspace colleagues and admins only", async () => {
    expect(await asApp("select id from public.qr_scans", [], { user: A })).toHaveLength(3);
    expect(await asApp("select id from public.qr_scans", [], { user: C })).toHaveLength(1);
    expect(await asApp("select id from public.qr_scans", [], { user: B })).toHaveLength(0);
    expect(await asApp("select id from public.qr_scans")).toHaveLength(0);
    expect(await asApp("select id from public.qr_scans", [], { admin: true })).toHaveLength(3);
    expect(await asApp("delete from public.qr_scans returning id", [], { user: B })).toHaveLength(0);
  });

  it("links are read and deleted only by their owner", async () => {
    expect(await asApp("select title from public.links", [], { user: A })).toEqual([{ title: "a" }]);
    expect(await asApp("delete from public.links where profile_id = $1 returning id", [B], { user: A })).toHaveLength(0);
    await denied(asApp("update public.links set title = 'x'", [], { user: A }));
  });

  it("link clicks are attributed by the database from the handle and read by the owner only", async () => {
    expect(await one("select public.rout_link_click_record('ANNA', 'b1', 'Site', 'root', 'h1')")).toBe(true);
    expect(await one("select public.rout_link_click_record('cleo.alias', 'b2', null, 'alias', 'h2')")).toBe(true);
    expect(await one("select public.rout_link_click_record('nobody', 'b3', null, 'root', 'h3')")).toBe(false);
    await expect(asApp("select public.rout_link_click_record('anna', 'b1', null, 'elsewhere', 'h')")).rejects.toThrow(/invalid link click/);
    expect(await asApp("select block_id from public.profile_link_clicks", [], { user: A })).toEqual([{ block_id: "b1" }]);
    expect(await asApp("select block_id from public.profile_link_clicks", [], { user: B })).toHaveLength(0);
  });

  it("a voter counts once per poll and only real options are accepted", async () => {
    const voter = "f".repeat(64);
    await asApp("select * from public.rout_poll_vote('anna:p1', 2, $1)", [voter]);
    const again = await asApp("select option_index, n from public.rout_poll_vote('anna:p1', 3, $1)", [voter]);
    expect(again).toEqual([{ option_index: 2, n: 1 }]);
    await expect(asApp("select * from public.rout_poll_vote('anna:p1', 6, $1)", ["e".repeat(64)])).rejects.toThrow(/invalid poll vote/);
    await expect(asApp("select * from public.rout_poll_vote('anna:p1', 1, 'client-chosen')")).rejects.toThrow(/invalid poll vote/);
    expect(await asApp("select option_index, n from public.rout_poll_tally('anna:p1')")).toEqual([{ option_index: 2, n: 1 }]);
  });

  it("only an admin replaces the showcase, and the list stays readable for everyone", async () => {
    await expect(asApp("select public.rout_showcase_replace(array['anna'])", [], { user: A })).rejects.toThrow(/admin only/);
    expect(await one("select public.rout_showcase_replace(array['anna', 'bert'])", [], { admin: true })).toBe(2);
    expect(await asApp("select handle from public.showcase_profiles order by position")).toEqual([{ handle: "anna" }, { handle: "bert" }]);
    await expect(asApp("select public.rout_showcase_replace(array['Bad Handle'])", [], { admin: true })).rejects.toThrow(/invalid showcase handle/);
    expect(await asApp("select handle from public.showcase_profiles")).toHaveLength(2);
  });

  it("leads reach only a visible contact form and only that profile owner reads them", async () => {
    await asApp("select public.rout_lead_capture_insert('anna', 'Guest', 'g@example.com', 'hi')");
    await expect(asApp("select public.rout_lead_capture_insert('bert', null, 'g@example.com', 'hi')")).rejects.toThrow(/no contact form/);
    await expect(asApp("select public.rout_lead_capture_insert('cleo', null, 'g@example.com', 'hi')")).rejects.toThrow(/no contact form/);
    expect(await asApp("select name from public.lead_captures", [], { user: A })).toEqual([{ name: "Guest" }]);
    expect(await asApp("select name from public.lead_captures", [], { user: B })).toHaveLength(0);
  });

  it("a contact submission gets its delivery outcome once and only admins read the inbox", async () => {
    const id = await one(`select public.rout_contact_submission_create('Name', 'n@example.com', 'Subj', 'Msg', 'nl', null,
      'general', 'Algemeen', 'Normaal', '{}'::jsonb, null, null, null, null)`);
    expect(await one("select public.rout_contact_submission_finish($1::uuid, 'sent', null)", [id])).toBe(true);
    expect(await one("select public.rout_contact_submission_finish($1::uuid, 'failed', 'later')", [id])).toBe(false);
    expect(await asApp("select status from public.contact_submissions", [], { user: A })).toHaveLength(0);
    expect(await asApp("select status from public.contact_submissions", [], { admin: true })).toEqual([{ status: "sent" }]);
  });

  it("onboarding drafts open only by exact key and a purge deletes only for a due account", async () => {
    await asApp(`select public.rout_onboarding_draft_put('a@example.com', '{"step":1}'::jsonb)`);
    await asApp(`select public.rout_onboarding_draft_put('token:abcdefgh', '{"step":2}'::jsonb)`);
    expect(await one("select public.rout_onboarding_draft_get('a@example.com')")).toEqual({ step: 1 });
    expect(await one("select public.rout_onboarding_draft_get('%')")).toBeNull();
    await expect(asApp(`select public.rout_onboarding_draft_put('A@Example.com', '{}'::jsonb)`)).rejects.toThrow(/invalid onboarding draft/);
    expect(await one("select public.rout_onboarding_drafts_purge($1::uuid)", [A])).toBe(0);
    expect(await one("select public.rout_onboarding_drafts_purge($1::uuid)", [A], { purge: A })).toBe(1);
    expect(await one("select public.rout_onboarding_draft_get('token:abcdefgh')")).toEqual({ step: 2 });
  });
});

describe("batch 9: agenda, jobs and caches", () => {
  it("a due availability job is claimed once and retries stop after five attempts", async () => {
    await asApp("select public.rout_availability_enqueue($1::uuid, 'booking_action', 0, true)", [A]);
    await asApp("select public.rout_availability_enqueue($1::uuid, 'calendar_sync', 0, false)", [A]);
    const first = await asApp("select user_id, attempts from public.rout_availability_claim_due(10)");
    expect(first).toEqual([{ user_id: A, attempts: 0 }]);
    expect(await asApp("select user_id from public.rout_availability_claim_due(10)")).toHaveLength(0);
    expect(await one("select public.rout_availability_retry($1::uuid, 4)", [A])).toBe(true);
    expect(await one("select public.rout_availability_retry($1::uuid, 5)", [B])).toBe(false);
  });

  it("a booking request needs a visible booking form and is decided once", async () => {
    const id = await one("select public.rout_booking_request_create($1::uuid, 'Guest', 'g@example.com', '2026-12-01', '10:30', null, 30, 'Intro')", [A]);
    await expect(asApp("select public.rout_booking_request_create($1::uuid, 'Guest', 'g@example.com', '2026-12-01', '10:30', null, 30, 'x')", [B]))
      .rejects.toThrow(/no booking form/);
    expect(await asApp("select guest_name from public.rout_booking_request_resolve($1::uuid, 'accept')", [id])).toEqual([{ guest_name: "Guest" }]);
    expect(await asApp("select id from public.rout_booking_request_resolve($1::uuid, 'decline')", [id])).toHaveLength(0);
    expect(await asApp("select status from public.booking_requests", [], { user: A })).toEqual([{ status: "accepted" }]);
    expect(await asApp("select status from public.booking_requests", [], { user: B })).toHaveLength(0);
  });

  it("alias jobs are finished only while pending and requeued per member", async () => {
    const job = await one(`select public.rout_alias_job_enqueue($1::uuid, 'provision', '{}'::jsonb, 3)`, [A]);
    await expect(asApp(`select public.rout_alias_job_enqueue($1::uuid, 'drop_table', '{}'::jsonb, 3)`, [A])).rejects.toThrow(/invalid alias job/);
    expect(await asApp("select id from public.rout_alias_jobs_pending(10)")).toHaveLength(1);
    expect(await one("select public.rout_alias_job_finish($1::uuid, 'failed', 3, 'boom')", [job])).toBe(true);
    expect(await one("select public.rout_alias_job_finish($1::uuid, 'done', 4, null)", [job])).toBe(false);
    expect(await one("select public.rout_alias_job_requeue_user($1::uuid)", [A])).toBe(true);
    expect(await one("select public.rout_alias_job_requeue_user($1::uuid)", [B])).toBe(false);
    expect(await asApp("select status, count from public.rout_alias_queue_summary()")).toEqual([{ status: "pending", count: 1 }]);
  });

  it("confirmation mails hold the per-member and per-recipient limits", async () => {
    const check = (user: string, to: string) => one("select public.rout_forwarding_send_check($1::uuid, $2, 3, 5, 2)", [user, to]);
    expect(await check(A, "x@example.com")).toBeNull();
    expect(await check(A, "X@example.com")).toBeNull();
    expect(await check(B, "x@example.com")).toBe("rate_limited_recipient");
    expect(await check(A, "y@example.com")).toBeNull();
    expect(await check(A, "z@example.com")).toBe("rate_limited_user");
  });

  it("one visitor at a time leases a city refresh and only known weather states are stored", async () => {
    expect(await one("select public.rout_weather_cache_lease($1)", [KEY])).toBe(true);
    expect(await one("select public.rout_weather_cache_lease($1)", [KEY])).toBe(false);
    expect(await one("select public.rout_weather_cache_store($1, 'Rain')", [KEY])).toBe(true);
    await expect(asApp("select public.rout_weather_cache_store($1, 'Sunny')", [KEY])).rejects.toThrow(/invalid weather state/);
    expect(await asApp("select state from public.rout_weather_cache_read($1)", [KEY])).toEqual([{ state: "Rain" }]);
  });

  it("everyone reads provider and mode; only an integrations admin sees notes and changes switches", async () => {
    expect(await asApp("select provider, mode from public.platform_integration_switches")).toEqual([{ provider: "spotify", mode: "paused" }]);
    await denied(asApp("select note from public.platform_integration_switches"));
    await expect(asApp("select public.rout_integration_switch_set('spotify', 'off', null)", [], { user: A })).rejects.toThrow(/admin only/);
    await expect(asApp("select * from public.rout_integration_switches_admin_list()", [], { user: A })).rejects.toThrow(/admin only/);
    await asApp("select public.rout_integration_switch_set('spotify', 'off', 'outage')", [], { user: A, admin: true });
    expect(await asApp("select mode, note, updated_by_email from public.rout_integration_switches_admin_list()", [], { user: A, admin: true }))
      .toEqual([{ mode: "off", note: "outage", updated_by_email: "a@example.com" }]);
  });
});
