/**
 * ROUT Card taps (db/0245): NXP NTAG 424 DNA SUN/SDM, unlinkable.
 *
 * Tap URL: https://rout.be/t?p=<PICCData, 32 hex>&m=<CMAC, 16 hex>. No card id
 * or batch id: PICCData differs on every tap.
 *
 *   1. The active fleet keys (K_SDMMetaRead + UID-index key) are opened with
 *      the server vault key; PICCData is decrypted to UID + counter, unverified.
 *   2. vault_enclave.begin_sdm_tap finds the card by HMAC(UID-index key, UID),
 *      checks the lockout and opens a PENDING attempt (a failure until closed);
 *      it returns the card's sealed batch master.
 *   3. K_SDMFileRead = AN10922(batch master, UID || batch id), then the
 *      AN12196 SV2 session key and truncated CMAC are checked (sdm-verifier).
 *   4. vault_enclave.confirm_sdm_tap binds the verdict to the same tap bytes,
 *      within 60 s, with a strictly higher counter, and mints a single-use
 *      tap_ grant (120 s) that one purpose can spend.
 *
 * Every key byte is wiped in `finally`. Every failure is the same
 * VaultDeniedError; reasons stay on the enclave's audit chain. Never log
 * PICCData, CMAC or UID.
 */
import { z } from "zod";
import { cardDivInput, decryptPiccData, diversifyAes128, uidIndex, verifySdmTap } from "@/lib/crypto-enclave/sdm-verifier";
import type { VaultKek } from "./server-kek";
import { openWithServerKey, sealServerToken } from "./server-vault.server";
import type { TapGrant } from "./token-boundary";
import { VaultDeniedError, vaultPort, type IVaultPort, type SdmCardState, type SdmTapBytes, type SdmTapChallenge } from "./vault-port.server";

export const SDM_FLEET_PURPOSE = "card_fleet";
export const SDM_BATCH_PURPOSE = "card_batch";
const FLEET_MAGIC = [0x53, 0x44, 0x46, 0x31] as const; // "SDF1"
const BATCH_MAGIC = [0x53, 0x44, 0x42, 0x31] as const; // "SDB1"
const FLEET_BYTES = 4 + 16 + 32;
const BATCH_BYTES = 4 + 16;

/** `random` is injectable for tests that must act as the card (they need its keys). */
type Deps = { port?: IVaultPort; kek?: VaultKek; random?: (n: number) => Uint8Array };
const randomOf = (deps: Deps) => deps.random ?? ((n: number) => crypto.getRandomValues(new Uint8Array(n)));
const kekOf = (deps: Deps) => (deps.kek ? { kek: deps.kek } : {});

export const CardTapSchema = z
  .object({ p: z.string().regex(/^[0-9A-Fa-f]{32}$/), m: z.string().regex(/^[0-9A-Fa-f]{16}$/) })
  .strict();
export type CardTap = z.infer<typeof CardTapSchema>;

const hexBytes = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
const uuidBytes = (id: string) => hexBytes(id.replace(/-/g, ""));

function withMagic(magic: readonly number[], parts: Uint8Array[], size: number): Uint8Array {
  const out = new Uint8Array(size);
  out.set(magic, 0);
  let at = magic.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  if (at !== size) throw new TypeError("sdm_secret_size");
  return out;
}

/** Views into `plain` (wipe `plain` to wipe them). */
function fleetSecrets(plain: Uint8Array) {
  if (plain.length !== FLEET_BYTES || FLEET_MAGIC.some((m, i) => plain[i] !== m)) throw new VaultDeniedError();
  return { metaReadKey: plain.subarray(4, 20), uidIndexKey: plain.subarray(20, 52) };
}
function batchMaster(plain: Uint8Array): Uint8Array {
  if (plain.length !== BATCH_BYTES || BATCH_MAGIC.some((m, i) => plain[i] !== m)) throw new VaultDeniedError();
  return plain.subarray(4, 20);
}

// ---------------------------------------------------------------- admin side

/** Generates a fleet key inside the server, seals it and registers it (admin). */
export async function createSdmFleetKey(adminId: string, deps: Deps = {}): Promise<string> {
  const port = deps.port ?? vaultPort();
  const plain = withMagic(FLEET_MAGIC, [randomOf(deps)(16), randomOf(deps)(32)], FLEET_BYTES);
  try {
    const ref = await sealServerToken(adminId, "sdm", SDM_FLEET_PURPOSE, plain, { port, ...kekOf(deps) });
    return await port.registerSdmFleetKey({ userId: adminId }, ref);
  } finally {
    plain.fill(0);
  }
}

/** Generates a batch master inside the server, seals it and registers the batch (admin). */
export async function createSdmBatch(adminId: string, fleetId: string, label: string, deps: Deps = {}): Promise<string> {
  const port = deps.port ?? vaultPort();
  const plain = withMagic(BATCH_MAGIC, [randomOf(deps)(16)], BATCH_BYTES);
  try {
    const ref = await sealServerToken(adminId, "sdm", SDM_BATCH_PURPOSE, plain, { port, ...kekOf(deps) });
    return await port.registerSdmBatch({ userId: adminId }, fleetId, ref, label);
  } finally {
    plain.fill(0);
  }
}

async function openFleet<T>(fleet: { ownerUserId: string; envelope: Uint8Array }, deps: Deps, use: (s: ReturnType<typeof fleetSecrets>) => T | Promise<T>): Promise<T> {
  const plain = await openWithServerKey(fleet.ownerUserId, "sdm", SDM_FLEET_PURPOSE, fleet.envelope, { ...(deps.port ? { port: deps.port } : {}), ...kekOf(deps) });
  try {
    return await use(fleetSecrets(plain));
  } finally {
    plain.fill(0);
  }
}

/** Manifest import: raw UIDs (and activation codes) from the station become keyed hashes here. */
export async function importSdmManifest(
  adminId: string,
  fleetId: string,
  batchId: string,
  cards: readonly { uid: string; activationCode?: string }[],
  deps: Deps = {},
): Promise<number> {
  const port = deps.port ?? vaultPort();
  const fleet = (await port.sdmFleetKeys()).find((f) => f.fleetId === fleetId);
  if (!fleet || cards.length < 1 || cards.length > 5000) throw new VaultDeniedError();
  if (cards.some((c) => !/^[0-9A-Fa-f]{14}$/.test(c.uid))) throw new VaultDeniedError();
  const enc = new TextEncoder();
  const activation = await Promise.all(
    cards.map(async (c) => (c.activationCode ? new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(`rout-card-activation:v1:${c.activationCode.trim().toUpperCase()}`))) : null)),
  );
  const hashes = await openFleet(fleet, deps, (s) =>
    cards.map((c) => {
      const uid = hexBytes(c.uid);
      try {
        return uidIndex(s.uidIndexKey, uid);
      } finally {
        uid.fill(0);
      }
    }),
  );
  return port.registerSdmBatchCards({ userId: adminId }, batchId, hashes, activation.some((a) => a) ? activation : null);
}

// ---------------------------------------------------------------- tap side

/** Verifies one tap and returns a fresh single-use tap_ grant. */
export async function verifyCardTap(input: unknown, deps: Deps = {}): Promise<TapGrant> {
  const parsed = CardTapSchema.safeParse(input);
  if (!parsed.success) throw new VaultDeniedError();
  const port = deps.port ?? vaultPort();
  const tap: SdmTapBytes = { piccData: hexBytes(parsed.data.p), cmac: hexBytes(parsed.data.m) };
  const fleets = await port.sdmFleetKeys();

  let challenge: SdmTapChallenge | null = null;
  let metaReadKey: Uint8Array | null = null;
  let uid: Uint8Array | null = null;
  for (const fleet of fleets) {
    try {
      const found = await openFleet(fleet, deps, async (s) => {
        const picc = decryptPiccData(s.metaReadKey, parsed.data.p);
        if (!picc) return null;
        const hash = uidIndex(s.uidIndexKey, picc.uid);
        try {
          const c = await port.beginSdmTap(fleet.fleetId, hash, tap);
          return { c, meta: s.metaReadKey.slice(), uid: picc.uid };
        } catch (e) {
          picc.uid.fill(0);
          throw e;
        } finally {
          hash.fill(0);
        }
      });
      if (found) {
        challenge = found.c;
        metaReadKey = found.meta;
        uid = found.uid;
        break;
      }
    } catch {
      // A wrong fleet (or a denied begin) is not an answer yet: try the next one.
    }
  }
  if (!challenge || !metaReadKey || !uid) throw new VaultDeniedError();

  let plain: Uint8Array | undefined;
  let fileReadKey: Uint8Array | undefined;
  let divInput: Uint8Array | undefined;
  let verified: { readCounter: number } | null = null;
  try {
    plain = await openWithServerKey(challenge.batchOwner, "sdm", SDM_BATCH_PURPOSE, challenge.envelope, { ...(deps.port ? { port: deps.port } : {}), ...kekOf(deps) });
    divInput = cardDivInput(uid, uuidBytes(challenge.batchId));
    fileReadKey = diversifyAes128(batchMaster(plain), divInput);
    verified = verifySdmTap({
      tap: { piccData: parsed.data.p, cmac: parsed.data.m },
      keys: { metaReadKey, fileReadKey },
      lastCounter: challenge.lastCounter,
      expectedUid: toHex(uid),
    });
    const grant = await port.confirmSdmTap(challenge.attemptId, tap, true, verified.readCounter);
    if (!grant) throw new VaultDeniedError();
    return grant;
  } catch {
    if (verified === null) await port.confirmSdmTap(challenge.attemptId, tap, false, null).catch(() => null);
    throw new VaultDeniedError();
  } finally {
    plain?.fill(0);
    fileReadKey?.fill(0);
    divInput?.fill(0);
    metaReadKey.fill(0);
    uid.fill(0);
  }
}

/** A tap for the public "authentic card" check: verified, then spent at once. */
export async function publicCardProof(input: unknown, deps: Deps = {}): Promise<SdmCardState> {
  const port = deps.port ?? vaultPort();
  const grant = await verifyCardTap(input, { ...deps, port });
  const state = await port.consumeSdmTap(null, grant, "public_proof");
  if (!state) throw new VaultDeniedError();
  return state;
}
