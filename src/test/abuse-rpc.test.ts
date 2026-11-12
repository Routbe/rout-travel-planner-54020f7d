// @vitest-environment node
/**
 * db/0232 + db/0233 over the real SQL (PGlite, as rout_app): after the
 * lockdown the anti-abuse stores and the session-less sign-in tables are closed
 * to the app role. Covers the owner's rules: atomic rate limiting with window
 * cleanup, ALTCHA proofs burned once, one-time codes with a wrong-try counter,
 * and per-key access only (nothing can be listed in bulk).
 */
import { PGlite } from "@electric-sql/pglite";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

let db: PGlite;
type Row = Record<string, unknown>;
const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

async function asApp(query: string, params: unknown[] = []): Promise<Row[]> {
  await db.exec("set role rout_app");
  try {
    return (await db.query<Row>(query, params)).rows;
  } finally {
    await db.exec("reset role");
  }
}
const denied = (p: Promise<unknown>) => expect(p).rejects.toThrow(/permission denied/);

const TABLES = ["altcha_used", "signin_throttle", "rate_limits", "upload_rate_limits", "login_codes",
  "fediverse_email_otp", "telegram_verify_sessions", "mastodon_app_registrations"];

beforeAll(async () => {
  db = new PGlite();
  await db.exec(`create role rout_app;
    create table public.altcha_used (signature text primary key, expires_at timestamptz not null);
    create table public.signin_throttle (identity_hash text primary key, failures int not null default 0,
      window_started_at timestamptz not null default now(), locked_until timestamptz);
    create table public.rate_limits (bucket text not null, window_start timestamptz not null, hits int not null default 0,
      primary key (bucket, window_start));
    create table public.upload_rate_limits (client_ip text primary key, upload_count int not null default 0,
      window_start timestamptz not null default now(), updated_at timestamptz not null default now());
    create table public.login_codes (id bigserial primary key, email_hash text not null, code_hash text not null, link text not null,
      expires_at timestamptz not null, created_at timestamptz not null default now());
    create table public.fediverse_email_otp (pending_key text primary key, email text not null, code_hash text not null,
      attempts int not null default 0, locked_until timestamptz, expires_at timestamptz not null, created_at timestamptz not null default now());
    create table public.telegram_verify_sessions (chat_id bigint primary key, phone_enc text not null, expires_at timestamptz not null);
    create table public.mastodon_app_registrations (instance text not null, redirect_uri text not null, client_id text not null,
      client_secret text not null, created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
      primary key (instance, redirect_uri));
    insert into public.signin_throttle (identity_hash, failures) values ('${sha("x")}', 4);`);
  // Legacy state on the live database: free access for rout_app.
  for (const t of TABLES) {
    await db.exec(`grant select, insert, update, delete on public.${t} to rout_app;
      alter table public.${t} enable row level security;
      create policy rout_server on public.${t} to rout_app using (true) with check (true);`);
  }
  await db.exec("grant usage on sequence public.login_codes_id_seq to rout_app");
  for (const f of ["db/0232_abuse_and_stateless_auth_rpc.sql", "db/0233_abuse_lockdown.sql"]) {
    await db.exec(readFileSync(new URL(`../../${f}`, import.meta.url), "utf8"));
  }
}, 30_000);
afterAll(async () => db?.close());

describe("tables are closed to the app role", () => {
  it("refuses direct reads and writes on all eight tables", async () => {
    for (const t of TABLES) await denied(asApp(`select * from public.${t}`));
    await denied(asApp("insert into public.altcha_used values ('a', now() + interval '1 minute')"));
    await denied(asApp("delete from public.rate_limits"));
  });

  it("no other database role can call the functions", async () => {
    await db.exec("create role other_login");
    await db.exec("set role other_login");
    try {
      await expect(db.query("select * from public.rout_rate_limit_check_and_increment('a:b', 60)")).rejects.toThrow(/permission denied/);
      await expect(db.query("select * from public.rout_mastodon_app_get('a', 'b')")).rejects.toThrow(/permission denied/);
    } finally {
      await db.exec("reset role");
    }
  });
});

describe("rate limits", () => {
  it("counts atomically per window and returns the previous window", async () => {
    const first = await asApp("select * from public.rout_rate_limit_check_and_increment('login:abc', 60)");
    const second = await asApp("select * from public.rout_rate_limit_check_and_increment('login:abc', 60)");
    expect(first[0]).toMatchObject({ hits: 1, prev: 0 });
    expect(second[0]).toMatchObject({ hits: 2, prev: 0 });
    expect(Number(second[0]!["now_ms"])).toBeGreaterThan(0);
  });

  it("reads the previous window and removes older windows of the bucket", async () => {
    await db.exec(`insert into public.rate_limits values
      ('old:b', to_timestamp(floor(extract(epoch from now()) / 60) * 60) - interval '60 seconds', 7),
      ('old:b', to_timestamp(floor(extract(epoch from now()) / 60) * 60) - interval '600 seconds', 9)`);
    const r = await asApp("select * from public.rout_rate_limit_check_and_increment('old:b', 60)");
    expect(r[0]).toMatchObject({ hits: 1, prev: 7 });
    const left = await db.query<Row>("select count(*)::int as n from public.rate_limits where bucket = 'old:b'");
    expect(left.rows[0]!["n"]).toBe(2);
  });

  it("peeking never increments and invalid buckets are refused", async () => {
    expect((await asApp("select public.rout_rate_limit_peek('login:abc', 120) as n"))[0]!["n"]).toBe(2);
    expect((await asApp("select public.rout_rate_limit_peek('login:abc', 120) as n"))[0]!["n"]).toBe(2);
    await expect(asApp("select * from public.rout_rate_limit_check_and_increment('has space', 60)")).rejects.toThrow(/invalid/);
    await expect(asApp("select * from public.rout_rate_limit_check_and_increment('a:b', 0)")).rejects.toThrow(/invalid/);
  });
});

describe("ALTCHA proofs", () => {
  const sig = sha("proof-1");
  it("burns a signature exactly once", async () => {
    expect((await asApp("select public.rout_altcha_verify_and_burn($1, now() + interval '5 minutes') as r", [sig]))[0]!["r"]).toBe("ok");
    expect((await asApp("select public.rout_altcha_verify_and_burn($1, now() + interval '5 minutes') as r", [sig]))[0]!["r"]).toBe("replayed");
  });

  it("refuses expired, far-future and malformed proofs", async () => {
    expect((await asApp("select public.rout_altcha_verify_and_burn($1, now() - interval '1 second') as r", [sha("p2")]))[0]!["r"]).toBe("expired");
    expect((await asApp("select public.rout_altcha_verify_and_burn($1, now() + interval '2 days') as r", [sha("p3")]))[0]!["r"]).toBe("invalid");
    expect((await asApp("select public.rout_altcha_verify_and_burn('xyz', now() + interval '1 minute') as r"))[0]!["r"]).toBe("invalid");
  });

  it("purges expired rows and reports the store as ready", async () => {
    await db.exec(`insert into public.altcha_used values ('${sha("gone")}', now() - interval '1 minute')`);
    expect((await asApp("select public.rout_altcha_purge() as n"))[0]!["n"]).toBe(1);
    expect((await asApp("select public.rout_altcha_store_ready() as ok"))[0]!["ok"]).toBe(true);
  });

  it("returns the recent failure count of one identity only", async () => {
    expect((await asApp("select public.rout_signin_throttle_failures($1) as n", [sha("x")]))[0]!["n"]).toBe(4);
    expect((await asApp("select public.rout_signin_throttle_failures($1) as n", [sha("y")]))[0]!["n"]).toBe(0);
  });
});

describe("login codes", () => {
  const e = sha("member@example.com");
  const issue = (code: string) =>
    asApp("select public.rout_stateless_otp_issue('login_code', $1, $2, 'https://rout.be/magic', 900) as r", [e, sha(`${e}:${code}`)]);
  const verify = (code: string) => asApp("select * from public.rout_stateless_otp_verify('login_code', $1, $2)", [e, code]);

  it("redeems the right code once", async () => {
    await issue("123456");
    expect((await verify("123456"))[0]).toMatchObject({ outcome: "ok", payload: "https://rout.be/magic" });
    expect((await verify("123456"))[0]).toMatchObject({ outcome: "missing", payload: null });
  });

  it("five wrong codes burn the code, even the right one afterwards", async () => {
    await issue("654321");
    for (let i = 1; i <= 4; i += 1) expect((await verify("000000"))[0]).toMatchObject({ outcome: "wrong", attempts_left: 5 - i });
    expect((await verify("000000"))[0]).toMatchObject({ outcome: "locked" });
    expect((await verify("654321"))[0]).toMatchObject({ outcome: "missing" });
  });
});

describe("fediverse e-mail codes", () => {
  const key = sha("bluesky|did:plc:1|alice|/dashboard");
  const email = "alice@example.com";
  const issue = (code: string) =>
    asApp("select public.rout_stateless_otp_issue('fediverse', $1, $2, $3, 600) as r", [key, sha(`${key}|${email}|${code}`), email]);
  const verify = (code: string) => asApp("select * from public.rout_stateless_otp_verify('fediverse', $1, $2)", [key, code]);

  it("accepts the code hashed by the app and returns the e-mail once", async () => {
    expect((await issue("111111"))[0]!["r"]).toBe("issued");
    expect((await verify("111111"))[0]).toMatchObject({ outcome: "ok", payload: email });
    expect((await verify("111111"))[0]).toMatchObject({ outcome: "missing" });
  });

  it("locks after three wrong tries and a new code cannot lift the lock", async () => {
    await issue("222222");
    expect((await verify("000000"))[0]).toMatchObject({ outcome: "wrong", attempts_left: 2 });
    expect((await verify("000000"))[0]).toMatchObject({ outcome: "wrong", attempts_left: 1 });
    expect((await verify("000000"))[0]).toMatchObject({ outcome: "locked", attempts_left: 0 });
    expect((await verify("222222"))[0]).toMatchObject({ outcome: "locked" });
    expect((await issue("333333"))[0]!["r"]).toBe("locked");
  });

  it("refuses an expired code", async () => {
    const k2 = sha("mastodon|2|bob|/");
    await asApp("select public.rout_stateless_otp_issue('fediverse', $1, $2, 'bob@example.com', 600)", [k2, sha(`${k2}|bob@example.com|444444`)]);
    await db.exec(`update public.fediverse_email_otp set expires_at = now() - interval '1 second' where pending_key = '${k2}'`);
    expect((await asApp("select * from public.rout_stateless_otp_verify('fediverse', $1, '444444')", [k2]))[0]).toMatchObject({ outcome: "expired" });
  });
});

describe("Telegram and Mastodon", () => {
  it("keeps one encrypted phone per chat for 15 minutes", async () => {
    await asApp("select public.rout_telegram_contact_remember(42, 'enc-phone')");
    expect((await asApp("select public.rout_telegram_contact_get(42) as p"))[0]!["p"]).toBe("enc-phone");
    expect((await asApp("select public.rout_telegram_contact_get(43) as p"))[0]!["p"]).toBeNull();
    await db.exec("update public.telegram_verify_sessions set expires_at = now() - interval '1 second' where chat_id = 42");
    expect((await asApp("select public.rout_telegram_contact_get(42) as p"))[0]!["p"]).toBeNull();
    await asApp("select public.rout_telegram_contact_forget(42)");
    expect((await db.query<Row>("select count(*)::int as n from public.telegram_verify_sessions")).rows[0]!["n"]).toBe(0);
  });

  it("stores one app registration per instance and redirect, readable only by that exact pair", async () => {
    expect((await asApp("select public.rout_mastodon_app_put('mastodon.social', 'https://rout.be/cb', 'cid', 'csecret') as ok"))[0]!["ok"]).toBe(true);
    expect((await asApp("select public.rout_mastodon_app_put('mastodon.social', 'https://rout.be/cb', 'other', 'other') as ok"))[0]!["ok"]).toBe(false);
    expect(await asApp("select * from public.rout_mastodon_app_get('mastodon.social', 'https://rout.be/cb')")).toEqual([{ client_id: "cid", client_secret: "csecret" }]);
    expect(await asApp("select * from public.rout_mastodon_app_get('mastodon.social', 'https://evil.example/cb')")).toEqual([]);
    await expect(asApp("select public.rout_mastodon_app_put('Bad Host', 'https://rout.be/cb', 'a', 'b')")).rejects.toThrow(/invalid/);
  });
});
