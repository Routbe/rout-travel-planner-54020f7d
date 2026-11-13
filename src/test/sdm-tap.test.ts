// @vitest-environment node
/**
 * db/0245 ROUT Card taps end to end over the real SQL (PGlite, as rout_app):
 * unlinkable tap URLs, AN10922 per-card keys, replay, lockout, single-use
 * grants and no table rights.
 */
import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { cbc, cmac } from "@noble/ciphers/aes.js";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { cardDivInput, diversifyAes128 } from "@/lib/crypto-enclave/sdm-verifier";
import { deriveVaultKek } from "@/lib/vault/server-kek";
import { createSdmBatch, createSdmFleetKey, importSdmManifest, publicCardProof, verifyCardTap } from "@/lib/vault/sdm-tap.server";
import { LocalPostgresVaultAdapter, VaultDeniedError, type VaultSqlExecutor } from "@/lib/vault/vault-port.server";

const ADMIN = "00000000-0000-4000-8000-0000000000ad";
const MEMBER = "00000000-0000-4000-8000-0000000000e1";
const KEK = "K".repeat(32) + "7x".repeat(32);
let db: PGlite;

const asApp: VaultSqlExecutor = async (userId, query, params) => {
  await db.query("select set_config('rout.current_user_id', $1, false)", [userId]);
  await db.exec("set role rout_app");
  try {
    return (await db.query<Record<string, unknown>>(query, [...params])).rows;
  } finally {
    await db.exec("reset role");
  }
};
const port = new LocalPostgresVaultAdapter(asApp);
const kek = deriveVaultKek(KEK);
const deps = { port, kek };
const hex = (b: ArrayLike<number>) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
const bytes = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => Number.parseInt(x, 16));

// Known key material so the test can act as the card.
const META = new Uint8Array(16).fill(0x31);
const UID_INDEX = new Uint8Array(32).fill(0x32);
const MASTER = new Uint8Array(16).fill(0x33);
const queue = (...parts: Uint8Array[]) => (n: number) => {
  const next = parts.shift();
  if (!next || next.length !== n) throw new Error("unexpected random request");
  return next.slice();
};
let fleetId = "";
let batchId = "";

/** The URL parameters a personalised card would produce. */
function tap(uidHex: string, counter: number) {
  const uid = bytes(uidHex);
  const plain = new Uint8Array(16);
  plain[0] = 0xc7;
  plain.set(uid, 1);
  plain.set([counter & 0xff, (counter >> 8) & 0xff, (counter >> 16) & 0xff], 8);
  const p = cbc(META, new Uint8Array(16), { disablePadding: true }).encrypt(plain);
  const fileKey = diversifyAes128(MASTER, cardDivInput(uid, bytes(batchId.replace(/-/g, ""))));
  const sv2 = Uint8Array.from([0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80, ...uid, ...plain.slice(8, 11)]);
  const full = cmac(new Uint8Array(0), cmac(sv2, fileKey));
  return { p: hex(p), m: hex(Array.from({ length: 8 }, (_, i) => full[2 * i + 1] ?? 0)) };
}
const forged = (t: { p: string; m: string }) => ({ ...t, m: `${t.m.slice(0, 15)}${t.m.endsWith("0") ? "1" : "0"}` });

beforeAll(async () => {
  db = new PGlite({ extensions: { pgcrypto } });
  await db.exec(`create extension pgcrypto; create role rout_app; create table public.users (id uuid primary key);
    insert into public.users values ('${ADMIN}'), ('${MEMBER}');
    create function public.rout_is_admin_member(p_user uuid) returns boolean language sql stable as $$ select p_user = '${ADMIN}'::uuid $$;`);
  for (const f of ["0221_vault_enclave_isolation.sql", "0222_vault_server_keys.sql", "0224_sdm_recovery_gate.sql", "0245_sdm_tap.sql"]) {
    await db.exec(readFileSync(new URL(`../../db/${f}`, import.meta.url), "utf8"));
  }
  fleetId = await createSdmFleetKey(ADMIN, { ...deps, random: queue(META, UID_INDEX) });
  batchId = await createSdmBatch(ADMIN, fleetId, "Test batch 1", { ...deps, random: queue(MASTER) });
  const n = await importSdmManifest(ADMIN, fleetId, batchId, [{ uid: "04A1B2C3D4E5F6" }, { uid: "04A1B2C3D4E5F7" }, { uid: "04A1B2C3D4E5F8" }], deps);
  expect(n).toBe(3);
}, 60_000);
afterAll(async () => db?.close());
beforeEach(async () => {
  await db.exec("delete from vault_enclave.sdm_tap_attempts");
});

describe("ROUT Card tap", () => {
  it("proves a genuine card from PICCData and CMAC alone, and never twice for the same tap", async () => {
    const t = tap("04A1B2C3D4E5F6", 5);
    expect(await publicCardProof(t, deps)).toBe("unactivated");
    await expect(publicCardProof(t, deps)).rejects.toThrow(VaultDeniedError);
    await expect(publicCardProof(tap("04A1B2C3D4E5F6", 4), deps)).rejects.toThrow(VaultDeniedError);
    expect(await publicCardProof(tap("04A1B2C3D4E5F6", 6), deps)).toBe("unactivated");
  });

  it("gives two taps of one card unrelated URLs", () => {
    const a = tap("04A1B2C3D4E5F7", 1);
    const b = tap("04A1B2C3D4E5F7", 2);
    expect(a.p).not.toBe(b.p);
    expect(a.m).not.toBe(b.m);
  });

  it("refuses a forged MAC, a card not in the manifest and another card's key", async () => {
    await expect(publicCardProof(forged(tap("04A1B2C3D4E5F7", 1)), deps)).rejects.toThrow(VaultDeniedError);
    await expect(publicCardProof(tap("04FFFFFFFFFFFF", 1), deps)).rejects.toThrow(VaultDeniedError);
    // Card F8's PICCData with card F7's MAC: the per-card AN10922 key differs.
    const f8 = tap("04A1B2C3D4E5F8", 3);
    const f7 = tap("04A1B2C3D4E5F7", 3);
    await expect(publicCardProof({ p: f8.p, m: f7.m }, deps)).rejects.toThrow(VaultDeniedError);
    await expect(publicCardProof({ p: "zz", m: "00" }, deps)).rejects.toThrow(VaultDeniedError);
  });

  it("locks a card after 5 failed taps in 10 minutes, even for a valid tap, and reopens after the window", async () => {
    for (let i = 0; i < 5; i++) await expect(publicCardProof(forged(tap("04A1B2C3D4E5F8", 10 + i)), deps)).rejects.toThrow(VaultDeniedError);
    await expect(publicCardProof(tap("04A1B2C3D4E5F8", 20), deps)).rejects.toThrow(VaultDeniedError);
    const r = await db.query<{ reason: string }>("select reason from vault_enclave.audit_logs order by seq desc limit 1");
    expect(r.rows[0]?.reason).toBe("card_locked");
    await db.exec("update vault_enclave.sdm_tap_attempts set started_at = started_at - interval '11 minutes'");
    expect(await publicCardProof(tap("04A1B2C3D4E5F8", 21), deps)).toBe("unactivated");
  });

  it("spends a grant once, for one purpose; step_up needs the card's owner and grants expire after 120 s", async () => {
    const g1 = await verifyCardTap(tap("04A1B2C3D4E5F7", 30), deps);
    expect(g1).toMatch(/^tap_[0-9a-f]{64}$/);
    expect(await port.consumeSdmTap({ userId: MEMBER }, g1, "step_up")).toBeNull();
    expect(await port.consumeSdmTap(null, g1, "public_proof")).toBeNull();
    await db.query("update vault_enclave.sdm_batch_cards set owner_user_id = $1", [MEMBER]);
    const g2 = await verifyCardTap(tap("04A1B2C3D4E5F7", 31), deps);
    expect(await port.consumeSdmTap({ userId: MEMBER }, g2, "step_up")).toBe("active");
    const g3 = await verifyCardTap(tap("04A1B2C3D4E5F7", 32), deps);
    await db.exec("update vault_enclave.sdm_tap_grants set expires_at = now() - interval '1 second' where consumed_at is null");
    expect(await port.consumeSdmTap(null, g3, "public_proof")).toBeNull();
    await db.exec("update vault_enclave.sdm_batch_cards set owner_user_id = null");
  });

  it("binds a verdict to the same tap bytes within 60 s", async () => {
    const t = tap("04A1B2C3D4E5F6", 40);
    const tb = { piccData: bytes(t.p), cmac: bytes(t.m) };
    const fleet = (await port.sdmFleetKeys())[0];
    expect(fleet?.fleetId).toBe(fleetId);
    // Any 32-byte hash that is not a card is refused before an attempt exists.
    await expect(port.beginSdmTap(fleetId, new Uint8Array(32), tb)).rejects.toThrow(VaultDeniedError);
    const stored = await db.query<{ h: Uint8Array }>("select uid_hash as h from vault_enclave.sdm_batch_cards order by created_at limit 1");
    const c = await port.beginSdmTap(fleetId, stored.rows[0]!.h, tb);
    expect(await port.confirmSdmTap(c.attemptId, { piccData: tb.piccData, cmac: new Uint8Array(8) }, true, 40)).toBeNull();
    const c2 = await port.beginSdmTap(fleetId, stored.rows[0]!.h, tb);
    await db.query("update vault_enclave.sdm_tap_attempts set started_at = started_at - interval '61 seconds' where attempt_id = $1", [c2.attemptId]);
    expect(await port.confirmSdmTap(c2.attemptId, tb, true, 40)).toBeNull();
  });
});

describe("db/0245 permissions", () => {
  it("gives rout_app no table rights", async () => {
    for (const t of ["sdm_fleet_keys", "sdm_batches", "sdm_batch_cards", "sdm_tap_attempts", "sdm_tap_grants"]) {
      await expect(asApp(ADMIN, `select * from vault_enclave.${t}`, [])).rejects.toThrow(/permission denied/);
    }
    await expect(asApp(ADMIN, "select vault_enclave.sdm_ref_free('x')", [])).rejects.toThrow(/permission denied/);
  });

  it("lets only an admin register fleet keys, batches and manifests", async () => {
    await expect(createSdmFleetKey(MEMBER, deps)).rejects.toThrow(VaultDeniedError);
    await expect(createSdmBatch(MEMBER, fleetId, "x", deps)).rejects.toThrow(VaultDeniedError);
    await expect(importSdmManifest(MEMBER, fleetId, batchId, [{ uid: "04000000000001" }], deps)).rejects.toThrow(VaultDeniedError);
    const stored = await db.query<{ n: number }>("select count(*)::int as n from vault_enclave.sdm_batch_cards");
    expect(stored.rows[0]?.n).toBe(3);
  });

  it("never stores a raw UID or a usable grant", async () => {
    const cards = await db.query<{ h: Uint8Array }>("select uid_hash as h from vault_enclave.sdm_batch_cards");
    for (const r of cards.rows) expect(hex(r.h)).not.toContain("04A1B2C3D4E5");
    const g = await verifyCardTap(tap("04A1B2C3D4E5F6", 50), deps);
    const rows = await db.query<{ d: Uint8Array }>("select grant_digest as d from vault_enclave.sdm_tap_grants");
    for (const r of rows.rows) expect(hex(r.d).toLowerCase()).not.toContain(g.slice(4, 20));
  });

  it("keeps every tap decision on the intact hash chain", async () => {
    const r = await db.query<{ ok: boolean; n: number }>(
      "select vault_enclave.verify_audit_chain() as ok, (select count(*)::int from vault_enclave.audit_logs where action like 'sdm_tap_%') as n",
    );
    expect(r.rows[0]?.n).toBeGreaterThan(20);
    expect(r.rows[0]?.ok).toBe(true);
  });
});
