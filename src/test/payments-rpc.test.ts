// @vitest-environment node
/**
 * db/0229 + db/0231 over the real SQL (PGlite, as rout_app): after the
 * lockdown the payment, gift-card, promo and pricing tables are closed to the
 * app role; money only moves through the database functions. Covers the rules
 * the owner asked for: no double spend of gift cards or promo codes, webhooks
 * without a member session only reach narrow service functions, and payment
 * keys of creators never come back in bulk.
 */
import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ALICE = "00000000-0000-4000-8000-00000000000a"; // member / creator
const BOB = "00000000-0000-4000-8000-00000000000b"; // other member
const ADMIN = "00000000-0000-4000-8000-0000000000ad";
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
const denied = (p: Promise<unknown>) => expect(p).rejects.toThrow(/permission denied|required|must be/);

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
    create function public.rout_has_role(p_user uuid, p_role text) returns boolean language sql stable security definer as $$
      select p_user is not null and exists (select 1 from public.user_roles r where r.user_id = p_user and r.role = p_role) $$;
    create table public.profiles (id uuid primary key, username text, verified boolean, is_banned boolean, is_suspended boolean,
      status text default 'active', is_business boolean default false);
    create table public.tip_settings (user_id uuid primary key, enabled boolean not null default false);
    create table public.pricing_settings (id int primary key default 1 check (id = 1), verification_base_cents int not null default 399,
      fee_card_cents int not null default 999, fee_bunq_cents int not null default 499, fee_sepa_cents int not null default 0,
      min_donation_cents int not null default 100, updated_at timestamptz not null default now(), updated_by uuid);
    create table public.promo_codes (id uuid primary key default gen_random_uuid(), code text unique not null, label text,
      percent_off int not null default 0, amount_off_cents int not null default 0, max_redemptions int, redeemed_count int not null default 0,
      active boolean not null default true, expires_at timestamptz, created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(), max_discount_cents int, last_redeemed_at timestamptz);
    create table public.promo_code_events (id uuid primary key default gen_random_uuid(), code text not null, event text not null,
      detail text, created_at timestamptz not null default now());
    create table public.gift_cards (id uuid primary key default gen_random_uuid(), code text unique not null,
      amount_cents int not null check (amount_cents between 500 and 50000), currency text not null default 'EUR',
      purchaser_user_id uuid, purchaser_email text not null, purchaser_name text, recipient_email text, recipient_name text,
      message text, design text not null default 'classic', physical_delivery boolean not null default false,
      ship_name text, ship_line1 text, ship_postal_code text, ship_city text, ship_country text,
      status text not null default 'pending', stripe_reference text, invoice_number text, paid_at timestamptz, delivered_at timestamptz,
      created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
      fulfilment_status text not null default 'not_applicable', tracking_code text, packaged_at timestamptz, shipped_at timestamptz);
    create table public.psp_credentials (user_id uuid not null, provider text not null, ciphertext text not null, iv text not null,
      last4 text not null, mode text not null default 'live', verified_at timestamptz not null default now(), publishable_key text,
      primary key (user_id, provider));
    create table public.verification_payments (id uuid primary key default gen_random_uuid(), user_id uuid not null, tier text not null,
      amount_cents int not null, currency text not null default 'EUR', donation_cents int not null default 0,
      donation_plan text not null default 'none', provider text not null default 'manual', provider_ref text, reference_code text,
      status text not null default 'pending', created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
      expires_at timestamptz, last_scanned_at timestamptz);
    insert into public.user_roles values ('${ADMIN}', 'admin');
    insert into public.profiles (id, username, verified, is_business) values ('${ALICE}', 'alice', true, true), ('${BOB}', 'bob', true, false);
    insert into public.tip_settings values ('${ALICE}', true), ('${BOB}', true);
    insert into public.pricing_settings (id) values (1);
    insert into public.psp_credentials (user_id, provider, ciphertext, iv, last4, publishable_key)
      values ('${ALICE}', 'stripe', 'sealed-a', 'iv-a', '1234', 'pk_live_a'), ('${BOB}', 'mollie', 'sealed-b', 'iv-b', '9999', null);`);
  // Legacy state on the live database: free access for rout_app on the six tables.
  for (const t of ["gift_cards", "promo_codes", "promo_code_events", "pricing_settings", "psp_credentials", "verification_payments"]) {
    await db.exec(`grant select, insert, update, delete on public.${t} to rout_app;
      alter table public.${t} enable row level security;
      create policy rout_server on public.${t} to rout_app using (true) with check (true);`);
  }
  for (const f of ["db/0229_payments_and_promos_rpc.sql", "db/0231_payments_lockdown.sql"]) {
    await db.exec(readFileSync(new URL(`../../${f}`, import.meta.url), "utf8"));
  }
}, 30_000);
afterAll(async () => db?.close());

describe("tables are closed to the app role", () => {
  it("refuses direct reads and writes on gift cards, promo codes, events and pricing", async () => {
    for (const t of ["gift_cards", "promo_codes", "promo_code_events", "pricing_settings"]) {
      await denied(asApp(ADMIN, `select * from public.${t}`));
    }
    await denied(asApp(ADMIN, "update public.promo_codes set redeemed_count = 0"));
    await denied(asApp(null, "insert into public.verification_payments (user_id, tier, amount_cents) values ($1, 'x', 0)", [ALICE]));
  });

  it("never lets the app read a sealed payment key column", async () => {
    await denied(asApp(ALICE, "select ciphertext from public.psp_credentials"));
    const own = await asApp(ALICE, "select provider, last4 from public.psp_credentials");
    expect(own).toEqual([{ provider: "stripe", last4: "1234" }]);
  });

  it("no other database role can call the payment functions", async () => {
    await db.exec("create role other_login");
    for (const call of [
      "select public.rout_gift_card_activate(gen_random_uuid(), null, 1, null, null)",
      "select * from public.rout_promo_redeem('X')",
      "select public.rout_vp_claim_paid(gen_random_uuid(), 'pi_x')",
      "select * from public.rout_psp_tip_credential(gen_random_uuid(), 'stripe')",
    ]) {
      await db.exec("set role other_login");
      try {
        await expect(db.query(call)).rejects.toThrow(/permission denied/);
      } finally {
        await db.exec("reset role");
      }
    }
  });
});

describe("pricing", () => {
  it("is readable by anyone, writable only by an admin", async () => {
    const [row] = await asApp(null, "select public.rout_pricing_get() as p");
    expect((row!["p"] as Row)["verification_base_cents"]).toBe(399);
    await denied(asApp(ALICE, "select public.rout_pricing_set(1, 1, 1, 1, 1)"));
    await asApp(ADMIN, "select public.rout_pricing_set(499, 999, 499, 0, 100)");
    const [after] = await asApp(null, "select public.rout_pricing_get() as p");
    expect((after!["p"] as Row)["verification_base_cents"]).toBe(499);
  });
});

describe("promo codes", () => {
  it("only admins create codes", async () => {
    await denied(asApp(ALICE, "select public.rout_promo_admin_save('FREE', null, 100, 0, null, 1, null, false)"));
    const [r] = await asApp(ADMIN, "select public.rout_promo_admin_save('TWICE', 'test', 50, 0, null, 2, null, false) as ok");
    expect(r!["ok"]).toBe(true);
    const [dup] = await asApp(ADMIN, "select public.rout_promo_admin_save('TWICE', 'x', 90, 0, null, 9, null, false) as ok");
    expect(dup!["ok"]).toBe(false);
  });

  it("a code with 2 uses can be redeemed exactly twice", async () => {
    const one = await asApp(ALICE, "select * from public.rout_promo_redeem('TWICE')");
    const two = await asApp(BOB, "select * from public.rout_promo_redeem('TWICE')");
    const three = await asApp(BOB, "select * from public.rout_promo_redeem('TWICE')");
    expect(one).toHaveLength(1);
    expect(two[0]).toMatchObject({ redeemed_count: 2, max_redemptions: 2 });
    expect(three).toHaveLength(0);
    expect(await asApp(ALICE, "select * from public.rout_promo_lookup('TWICE')")).toHaveLength(0);
  });

  it("lookups answer only for one exact, still valid code", async () => {
    await asApp(ADMIN, "select public.rout_promo_admin_save('SPRING', null, 10, 0, null, null, null, false)");
    expect(await asApp(null, "select * from public.rout_promo_lookup('SPRING')")).toHaveLength(1);
    expect(await asApp(null, "select * from public.rout_promo_lookup('SPR%')")).toHaveLength(0);
  });
});

describe("gift cards", () => {
  let giftId = "";
  it("a member cannot buy in another member's name", async () => {
    await denied(asApp(ALICE, "select public.rout_gift_card_create('G-1', 2500, $1, 'b@x.be', null, null, null, null, null, false, null, null, null, null, null)", [BOB]));
    const [r] = await asApp(null, "select public.rout_gift_card_create('G-1', 2500, null, 'buyer@x.be', 'Buyer', 'r@x.be', 'Rita', 'hi', null, false, null, null, null, null, null) as id");
    giftId = String(r!["id"]);
    const [again] = await asApp(null, "select public.rout_gift_card_create('G-1', 2500, null, 'buyer@x.be', null, null, null, null, null, false, null, null, null, null, null) as id");
    expect(again!["id"]).toBeNull();
  });

  it("is not public before payment and refuses a wrong paid amount", async () => {
    const [r] = await asApp(null, "select public.rout_gift_card_public('G-1') as c");
    expect(r!["c"]).toBeNull();
    const [m] = await asApp(null, "select public.rout_gift_card_activate($1, 'pi_x', 1, null, 100) as r", [giftId]);
    expect((m!["r"] as Row)["outcome"]).toBe("amount_mismatch");
  });

  it("activates once: a second webhook delivery does nothing", async () => {
    const [a] = await asApp(null, "select public.rout_gift_card_activate($1, 'pi_x', 1, null, 2500) as r", [giftId]);
    const [b] = await asApp(null, "select public.rout_gift_card_activate($1, 'pi_x', 1, null, 2500) as r", [giftId]);
    expect((a!["r"] as Row)["outcome"]).toBe("activated");
    expect((b!["r"] as Row)["outcome"]).toBe("duplicate");
  });

  it("the gift code can be spent once", async () => {
    expect(await asApp(ALICE, "select * from public.rout_promo_redeem('G-1')")).toHaveLength(1);
    expect(await asApp(BOB, "select * from public.rout_promo_redeem('G-1')")).toHaveLength(0);
    const [r] = await asApp(null, "select public.rout_gift_card_public('G-1') as c");
    const card = r!["c"] as Row;
    expect(card["redeemed"]).toBe(true);
    expect(card).not.toHaveProperty("purchaser_email");
    expect(card).not.toHaveProperty("recipient_email");
  });

  it("recipient details and shipments are admin-only", async () => {
    await denied(asApp(ALICE, "select * from public.rout_gift_card_recipient('G-1')"));
    const [r] = await asApp(ADMIN, "select * from public.rout_gift_card_recipient('G-1')");
    expect(r!["recipient_email"]).toBe("r@x.be");
    await denied(asApp(ALICE, "select * from public.rout_gift_shipments(false)"));
  });
});

describe("creator payment keys", () => {
  it("the sealed key comes back only for a business creator with an active tip page", async () => {
    expect(await asApp(null, "select * from public.rout_psp_tip_credential($1, 'stripe')", [ALICE])).toEqual([
      { ciphertext: "sealed-a", iv: "iv-a", publishable_key: "pk_live_a" },
    ]);
    expect(await asApp(null, "select * from public.rout_psp_tip_credential($1, 'mollie')", [BOB])).toHaveLength(0);
    expect(await asApp(null, "select * from public.rout_psp_public_providers($1) as p", [BOB])).toHaveLength(0);
  });

  it("members save and delete only their own keys", async () => {
    await denied(asApp(null, "select public.rout_psp_save('mollie', 'c', 'i', '0000', 'live', null)"));
    await asApp(BOB, "select public.rout_psp_save('stripe', 'c', 'i', 'abcd5678', 'test', 'pk_test_b')");
    expect(await asApp(BOB, "select provider, last4 from public.psp_credentials order by provider")).toEqual([
      { provider: "mollie", last4: "9999" }, { provider: "stripe", last4: "5678" },
    ]);
    const [d] = await asApp(BOB, "select public.rout_psp_delete('stripe') as ok");
    expect(d!["ok"]).toBe(true);
    expect(await asApp(ALICE, "select provider from public.psp_credentials where user_id = $1", [BOB])).toHaveLength(0);
  });

  it("a due account purge may delete the keys", async () => {
    await db.exec(`insert into public.account_deletions values ('${BOB}', null, null, now() - interval '1 day')`);
    await asApp(null, "delete from public.psp_credentials where user_id = $1", [BOB], BOB);
    const left = await db.query("select count(*)::int as n from public.psp_credentials where user_id = $1", [BOB]);
    expect(left.rows[0]).toEqual({ n: 0 });
  });
});

describe("verification payments", () => {
  let payId = "";
  it("a member opens a pending payment only for themselves", async () => {
    await denied(asApp(null, "select public.rout_vp_open('stripe', 399, 0, 'none', 'ROUT-1234')"));
    const [r] = await asApp(ALICE, "select public.rout_vp_open('stripe', 399, 0, 'none', 'ROUT-1234') as p");
    const p = r!["p"] as Row;
    payId = String(p["id"]);
    expect(p).toMatchObject({ user_id: ALICE, status: "pending", amount_cents: 399 });
    expect(await asApp(BOB, "select id from public.verification_payments")).toHaveLength(0);
    expect(await asApp(ALICE, "select id from public.verification_payments")).toHaveLength(1);
  });

  it("another member cannot attach a reference, reprice or fail it", async () => {
    const [a] = await asApp(BOB, "select public.rout_vp_attach_ref($1, 'pi_abc') as ok", [payId]);
    const [b] = await asApp(BOB, "select public.rout_vp_reprice($1, 0, 0, 'none') as ok", [payId]);
    const [c] = await asApp(BOB, "select public.rout_vp_fail_own($1) as ok", [payId]);
    expect([a!["ok"], b!["ok"], c!["ok"]]).toEqual([false, false, false]);
    const [own] = await asApp(ALICE, "select public.rout_vp_attach_ref($1, 'pi_abc') as ok", [payId]);
    expect(own!["ok"]).toBe(true);
  });

  it("a webhook without session claims paid exactly once", async () => {
    const [first] = await asApp(null, "select public.rout_vp_claim_paid($1, 'pi_abc') as ok", [payId]);
    const [second] = await asApp(null, "select public.rout_vp_claim_paid($1, 'pi_abc') as ok", [payId]);
    expect([first!["ok"], second!["ok"]]).toEqual([true, false]);
  });

  it("status updates never set paid and a paid payment only moves to refunded", async () => {
    await expect(asApp(null, "select public.rout_vp_mark($1, 'paid', null)", [payId])).rejects.toThrow(/invalid payment status/);
    const [kept] = await asApp(null, "select public.rout_vp_mark($1, 'failed', null) as r", [payId]);
    expect(kept!["r"]).toBe("paid");
    const [ref] = await asApp(null, "select public.rout_vp_mark($1, 'refunded', null) as r", [payId]);
    expect(ref!["r"]).toBe("updated");
    const [again] = await asApp(null, "select public.rout_vp_claim_paid($1, 'pi_abc') as ok", [payId]);
    expect(again!["ok"]).toBe(false);
  });

  it("admins read and update through their session, members cannot", async () => {
    expect(await asApp(ADMIN, "select id from public.verification_payments")).toHaveLength(1);
    await asApp(BOB, "update public.verification_payments set status = 'paid'");
    const [row] = await asApp(ADMIN, "select status from public.verification_payments where id = $1", [payId]);
    expect(row!["status"]).toBe("refunded");
  });

  it("the transfer scan expires open transfers after 7 days", async () => {
    await db.exec(`insert into public.verification_payments (user_id, tier, amount_cents, provider, reference_code, created_at)
      values ('${BOB}', 'early_believer', 399, 'sepa', 'ROUT-5555', now() - interval '8 days'),
             ('${BOB}', 'early_believer', 399, 'sepa', 'ROUT-6666', now() - interval '1 day')`);
    const [r] = await asApp(null, "select public.rout_vp_transfer_scan() as s");
    expect(r!["s"]).toEqual({ scanned: 2, expired: 1 });
    const cand = await asApp(null, "select public.rout_vp_sepa_candidates(399) as p");
    expect(cand).toHaveLength(2); // expired + still open, never the paid/refunded one
    const [seq] = await asApp(null, "select public.rout_vp_paid_sequence(now()) as n");
    expect(seq!["n"]).toBe(0);
  });
});
