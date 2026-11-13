/**
 * Vault port (hexagonal architecture). Application code depends only on
 * IVaultPort; LocalPostgresVaultAdapter is today's implementation and talks
 * exclusively to the SECURITY DEFINER functions of db/0221. A remote enclave
 * adapter (mTLS gRPC to a Rust AMD SEV-SNP service) can implement the same
 * interface 1:1: every method is a single request with plain bytes and
 * strings, the caller is explicit, and no method exposes SQL, rows or sessions.
 *
 * The port moves sealed envelopes only. It never sees plaintext and never
 * decrypts: opening an envelope is the key holder's job (pqc-envelope.ts).
 * Every denial is the same VaultDeniedError; the reason stays in the enclave's
 * audit log.
 */
import { z } from "zod";
import { cleanContextId } from "@/lib/db-context";
import { ENVELOPE_MAX_BYTES } from "@/lib/crypto-enclave/pqc-envelope";
import { isTapGrant, OPAQUE_TOKEN_KINDS, opaqueTokenKind, parseOpaqueToken, type OpaqueToken, type OpaqueTokenKind, type TapGrant } from "./token-boundary";

/** An authenticated member (public user id from the server session, never from input). */
export type VaultCaller = { readonly userId: string };
/** A passkey step-up the server verified; proofId as registered in the enclave. */
export type PasskeyStepUp = { readonly verified: true; readonly proofId: string };
export type VaultEnvelope<K extends OpaqueTokenKind> = { readonly kind: K; readonly envelope: Uint8Array };
/** A server vault recipient key as stored: public parts plus the KEK-wrapped seed (db/0222). */
export type WrappedServerKey = { readonly kid: Uint8Array; readonly publicKey: Uint8Array; readonly wrappedSeed: Uint8Array; readonly kekId: Uint8Array };
/** Raw NTAG 424 DNA SUN tap bytes: encrypted PICCData (16) and truncated CMAC (8). */
export type SdmTapBytes = { readonly piccData: Uint8Array; readonly cmac: Uint8Array };
/** An open recovery attempt (db/0224): counted as a failure until confirmed. */
export type SdmRecoveryChallenge = {
  readonly attemptId: string;
  readonly ownerUserId: string;
  readonly sdmRef: OpaqueToken<"sdm">;
  readonly envelope: Uint8Array;
  readonly lastCounter: number | null;
};

/** A sealed fleet key (K_SDMMetaRead + UID-index key), db/0245. */
export type SdmFleetKey = { readonly fleetId: string; readonly ownerUserId: string; readonly envelope: Uint8Array };
/** An open tap attempt (db/0245): counted as a failure until confirmed. */
export type SdmTapChallenge = {
  readonly attemptId: string;
  readonly batchId: string;
  readonly batchOwner: string;
  readonly envelope: Uint8Array;
  readonly lastCounter: number | null;
};
export type SdmTapPurpose = "public_proof" | "step_up";
export type SdmCardState = "active" | "unactivated";

export interface IVaultPort {
  /** Records a just-verified passkey step-up on the enclave's own clock. */
  registerPasskeyStepUp(caller: VaultCaller, proofId: string): Promise<void>;
  storeToken<K extends OpaqueTokenKind>(caller: VaultCaller, kind: K, envelope: Uint8Array): Promise<OpaqueToken<K>>;
  retrieveToken<K extends OpaqueTokenKind>(caller: VaultCaller, ref: OpaqueToken<K>, stepUp: PasskeyStepUp): Promise<VaultEnvelope<K>>;
  /** The server key that seals new envelopes, or null before the first one exists. */
  activeServerKey(caller: VaultCaller): Promise<WrappedServerKey | null>;
  /** Any server key by id (retired keys included, for older envelopes). */
  serverKey(caller: VaultCaller, kid: Uint8Array): Promise<WrappedServerKey | null>;
  /** Registers the first active key; false when one already exists. */
  registerServerKey(caller: VaultCaller, key: WrappedServerKey): Promise<boolean>;
  /** Links one of the caller's own sdm_ envelopes to a new card; returns the card id. */
  registerSdmCard(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string>;
  /** Pre-authentication: opens a recovery attempt for a card tap (lockout-checked). */
  beginSdmRecovery(cardId: string, tap: SdmTapBytes): Promise<SdmRecoveryChallenge>;
  /** Closes the attempt; true only for a verified tap with a strictly higher counter. */
  confirmSdmRecovery(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<boolean>;
  /** Admin: links one of the caller's own sdm_ envelopes as a fleet key. */
  registerSdmFleetKey(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string>;
  /** Admin: links one of the caller's own sdm_ envelopes as a batch master. */
  registerSdmBatch(caller: VaultCaller, fleetId: string, sdmRef: OpaqueToken<"sdm">, label: string): Promise<string>;
  /** Admin, batch owner: imports a manifest of uid hashes (and optional activation hashes). */
  registerSdmBatchCards(caller: VaultCaller, batchId: string, uidHashes: readonly Uint8Array[], activationHashes: readonly (Uint8Array | null)[] | null): Promise<number>;
  /** Pre-authentication: the active sealed fleet keys. */
  sdmFleetKeys(): Promise<SdmFleetKey[]>;
  /** Pre-authentication: opens a tap attempt for the card behind uidHash (lockout-checked). */
  beginSdmTap(fleetId: string, uidHash: Uint8Array, tap: SdmTapBytes): Promise<SdmTapChallenge>;
  /** Closes the attempt; a single-use tap_ grant only for a verified, strictly newer tap. */
  confirmSdmTap(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<TapGrant | null>;
  /** Spends a tap_ grant once for one purpose; step_up needs the card owner as caller. */
  consumeSdmTap(caller: VaultCaller | null, grant: TapGrant, purpose: SdmTapPurpose): Promise<SdmCardState | null>;
}

export class VaultDeniedError extends Error {
  constructor() {
    super("vault_denied");
    this.name = "VaultDeniedError";
  }
}

/** Runs one statement as `userId` (transaction-scoped context) and returns its rows. */
export type VaultSqlExecutor = (userId: string, query: string, params: readonly unknown[]) => Promise<readonly Record<string, unknown>[]>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX_RE = /^[0-9a-f]*$/;

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !HEX_RE.test(hex)) throw new VaultDeniedError();
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const RegisterRow = z.object({ ok: z.boolean() });
const StoreRow = z.object({ ref: z.string().nullable() });
const RetrieveRow = z.object({
  granted: z.boolean(),
  token_type: z.enum(OPAQUE_TOKEN_KINDS).nullable(),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2).nullable(),
});

const SdmCardRow = z.object({ card_id: z.string().regex(UUID_RE).nullable() });
const SdmRetrieveRow = z.object({
  granted: z.boolean(),
  attempt_id: z.string().regex(UUID_RE).nullable(),
  owner_user_id: z.string().regex(UUID_RE).nullable(),
  sdm_ref: z.string().nullable(),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2).nullable(),
  last_counter: z.number().int().min(0).max(0xfffffe).nullable(),
});
const FleetRow = z.object({
  fleet_id: z.string().regex(UUID_RE),
  owner_user_id: z.string().regex(UUID_RE),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2),
});
const TapBeginRow = z.object({
  granted: z.boolean(),
  attempt_id: z.string().regex(UUID_RE).nullable(),
  batch_id: z.string().regex(UUID_RE).nullable(),
  batch_owner: z.string().regex(UUID_RE).nullable(),
  payload_hex: z.string().max(ENVELOPE_MAX_BYTES * 2).nullable(),
  last_counter: z.number().int().min(0).max(0xfffffe).nullable(),
});
function parseRef(ref: OpaqueToken<"sdm">): string {
  try {
    return parseOpaqueToken(ref, "sdm");
  } catch {
    throw new VaultDeniedError();
  }
}
function uuidOf(rows: readonly Record<string, unknown>[]): string {
  const id = rows[0]?.["id"];
  if (typeof id !== "string" || !UUID_RE.test(id)) throw new VaultDeniedError();
  return id;
}
/** Anonymous (pre-authentication) calls run with an empty caller context. */
const NO_CALLER = "";

function tapHex(tap: SdmTapBytes): [string, string] {
  if (tap.piccData.length !== 16 || tap.cmac.length !== 8) throw new VaultDeniedError();
  return [toHex(tap.piccData), toHex(tap.cmac)];
}

const ServerKeyRow = z.object({
  kid_hex: z.string().length(32),
  public_key_hex: z.string().length(3200),
  wrapped_seed_hex: z.string().length(160),
  kek_id_hex: z.string().length(32),
});
const SERVER_KEY_COLUMNS =
  "encode(kid, 'hex') as kid_hex, encode(public_key, 'hex') as public_key_hex, encode(wrapped_seed, 'hex') as wrapped_seed_hex, encode(kek_id, 'hex') as kek_id_hex";

function serverKeyOf(rows: readonly Record<string, unknown>[]): WrappedServerKey | null {
  if (rows.length === 0) return null;
  const row = ServerKeyRow.safeParse(rows[0]);
  if (!row.success) throw new VaultDeniedError();
  return {
    kid: fromHex(row.data.kid_hex),
    publicKey: fromHex(row.data.public_key_hex),
    wrappedSeed: fromHex(row.data.wrapped_seed_hex),
    kekId: fromHex(row.data.kek_id_hex),
  };
}

function callerId(caller: VaultCaller): string {
  const id = cleanContextId(caller.userId);
  if (!id) throw new VaultDeniedError();
  return id;
}

async function defaultExecutor(userId: string, query: string, params: readonly unknown[]) {
  const { runQuery, withDbContext } = await import("@/lib/neon");
  return (await withDbContext({ userId, workspaceId: null }, () => runQuery(query, [...params]))).rows;
}

export class LocalPostgresVaultAdapter implements IVaultPort {
  constructor(private readonly exec: VaultSqlExecutor = defaultExecutor) {}

  async registerPasskeyStepUp(caller: VaultCaller, proofId: string): Promise<void> {
    if (!UUID_RE.test(proofId)) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_step_up_proof($1::uuid, 'passkey') as ok", [proofId]);
    const row = RegisterRow.safeParse(rows[0]);
    if (!row.success || !row.data.ok) throw new VaultDeniedError();
  }

  async storeToken<K extends OpaqueTokenKind>(caller: VaultCaller, kind: K, envelope: Uint8Array): Promise<OpaqueToken<K>> {
    if (!OPAQUE_TOKEN_KINDS.includes(kind) || envelope.length > ENVELOPE_MAX_BYTES) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.store_opaque_token($1, decode($2, 'hex')) as ref", [kind, toHex(envelope)]);
    const row = StoreRow.safeParse(rows[0]);
    if (!row.success || row.data.ref === null) throw new VaultDeniedError();
    try {
      return parseOpaqueToken(row.data.ref, kind);
    } catch {
      throw new VaultDeniedError();
    }
  }

  async retrieveToken<K extends OpaqueTokenKind>(caller: VaultCaller, ref: OpaqueToken<K>, stepUp: PasskeyStepUp): Promise<VaultEnvelope<K>> {
    const kind = opaqueTokenKind(ref);
    if (stepUp.verified !== true || !UUID_RE.test(stepUp.proofId)) throw new VaultDeniedError();
    const rows = await this.exec(
      callerId(caller),
      "select granted, token_type, encode(encrypted_payload, 'hex') as payload_hex from vault_enclave.retrieve_opaque_token($1, $2, $3::uuid)",
      [ref, true, stepUp.proofId],
    );
    const row = RetrieveRow.safeParse(rows[0]);
    if (!row.success || !row.data.granted || row.data.token_type !== kind || row.data.payload_hex === null) throw new VaultDeniedError();
    return { kind, envelope: fromHex(row.data.payload_hex) };
  }

  async activeServerKey(caller: VaultCaller): Promise<WrappedServerKey | null> {
    return serverKeyOf(await this.exec(callerId(caller), `select ${SERVER_KEY_COLUMNS} from vault_enclave.server_key_active()`, []));
  }

  async serverKey(caller: VaultCaller, kid: Uint8Array): Promise<WrappedServerKey | null> {
    if (kid.length !== 16) throw new VaultDeniedError();
    return serverKeyOf(
      await this.exec(callerId(caller), `select ${SERVER_KEY_COLUMNS} from vault_enclave.server_key_get(decode($1, 'hex'))`, [toHex(kid)]),
    );
  }

  async registerServerKey(caller: VaultCaller, key: WrappedServerKey): Promise<boolean> {
    const rows = await this.exec(
      callerId(caller),
      "select vault_enclave.register_server_key(decode($1, 'hex'), decode($2, 'hex'), decode($3, 'hex'), decode($4, 'hex')) as ok",
      [toHex(key.kid), toHex(key.publicKey), toHex(key.wrappedSeed), toHex(key.kekId)],
    );
    const row = RegisterRow.safeParse(rows[0]);
    if (!row.success) throw new VaultDeniedError();
    return row.data.ok;
  }

  async registerSdmCard(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string> {
    if (opaqueTokenKind(sdmRef) !== "sdm") throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_sdm_card($1)::text as card_id", [sdmRef]);
    const row = SdmCardRow.safeParse(rows[0]);
    if (!row.success || row.data.card_id === null) throw new VaultDeniedError();
    return row.data.card_id;
  }

  async beginSdmRecovery(cardId: string, tap: SdmTapBytes): Promise<SdmRecoveryChallenge> {
    if (!UUID_RE.test(cardId)) throw new VaultDeniedError();
    // Malformed taps still reach the enclave so they count against the lockout.
    const picc = tap.piccData.length <= 64 ? toHex(tap.piccData) : "";
    const mac = tap.cmac.length <= 64 ? toHex(tap.cmac) : "";
    const rows = await this.exec(
      NO_CALLER,
      "select granted, attempt_id::text as attempt_id, owner_user_id::text as owner_user_id, sdm_ref, encode(encrypted_payload, 'hex') as payload_hex, last_counter from vault_enclave.retrieve_sdm_for_recovery($1::uuid, decode($2, 'hex'), decode($3, 'hex'))",
      [cardId, picc, mac],
    );
    const row = SdmRetrieveRow.safeParse(rows[0]);
    if (!row.success || !row.data.granted || !row.data.attempt_id || !row.data.owner_user_id || !row.data.sdm_ref || !row.data.payload_hex) {
      throw new VaultDeniedError();
    }
    let sdmRef: OpaqueToken<"sdm">;
    try {
      sdmRef = parseOpaqueToken(row.data.sdm_ref, "sdm");
    } catch {
      throw new VaultDeniedError();
    }
    return { attemptId: row.data.attempt_id, ownerUserId: row.data.owner_user_id, sdmRef, envelope: fromHex(row.data.payload_hex), lastCounter: row.data.last_counter };
  }

  async confirmSdmRecovery(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<boolean> {
    if (!UUID_RE.test(attemptId)) throw new VaultDeniedError();
    const [picc, mac] = tapHex(tap);
    const counter = readCounter !== null && Number.isInteger(readCounter) && readCounter >= 0 && readCounter <= 0xfffffe ? readCounter : null;
    const rows = await this.exec(
      NO_CALLER,
      "select vault_enclave.confirm_sdm_recovery($1::uuid, decode($2, 'hex'), decode($3, 'hex'), $4, $5::int) as ok",
      [attemptId, picc, mac, verified === true, counter],
    );
    const row = RegisterRow.safeParse(rows[0]);
    return row.success && row.data.ok;
  }

  async registerSdmFleetKey(caller: VaultCaller, sdmRef: OpaqueToken<"sdm">): Promise<string> {
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_sdm_fleet_key($1)::text as id", [parseRef(sdmRef)]);
    return uuidOf(rows);
  }

  async registerSdmBatch(caller: VaultCaller, fleetId: string, sdmRef: OpaqueToken<"sdm">, label: string): Promise<string> {
    if (!UUID_RE.test(fleetId) || typeof label !== "string" || label.length > 80) throw new VaultDeniedError();
    const rows = await this.exec(callerId(caller), "select vault_enclave.register_sdm_batch($1::uuid, $2, $3)::text as id", [fleetId, parseRef(sdmRef), label]);
    return uuidOf(rows);
  }

  async registerSdmBatchCards(caller: VaultCaller, batchId: string, uidHashes: readonly Uint8Array[], activationHashes: readonly (Uint8Array | null)[] | null): Promise<number> {
    if (!UUID_RE.test(batchId) || uidHashes.length < 1 || uidHashes.length > 5000) throw new VaultDeniedError();
    if (uidHashes.some((h) => h.length !== 32)) throw new VaultDeniedError();
    if (activationHashes && (activationHashes.length !== uidHashes.length || activationHashes.some((h) => h !== null && h.length !== 32))) throw new VaultDeniedError();
    // Hex text arrays keep the statement portable across drivers.
    const rows = await this.exec(
      callerId(caller),
      "select vault_enclave.register_sdm_batch_cards($1::uuid, (select array_agg(decode(x, 'hex') order by i) from unnest($2::text[]) with ordinality u(x, i)), (select array_agg(case when x = '' then null else decode(x, 'hex') end order by i) from unnest($3::text[]) with ordinality a(x, i))) as n",
      [batchId, uidHashes.map(toHex), activationHashes ? activationHashes.map((h) => (h ? toHex(h) : "")) : null],
    );
    const row = z.object({ n: z.number().int().min(0).nullable() }).safeParse(rows[0]);
    if (!row.success || row.data.n === null) throw new VaultDeniedError();
    return row.data.n;
  }

  async sdmFleetKeys(): Promise<SdmFleetKey[]> {
    const rows = await this.exec(NO_CALLER, "select fleet_id::text as fleet_id, owner_user_id::text as owner_user_id, encode(encrypted_payload, 'hex') as payload_hex from vault_enclave.sdm_tap_fleet_keys()", []);
    const parsed = z.array(FleetRow).max(4).safeParse(rows);
    if (!parsed.success) throw new VaultDeniedError();
    return parsed.data.map((r) => ({ fleetId: r.fleet_id, ownerUserId: r.owner_user_id, envelope: fromHex(r.payload_hex) }));
  }

  async beginSdmTap(fleetId: string, uidHash: Uint8Array, tap: SdmTapBytes): Promise<SdmTapChallenge> {
    if (!UUID_RE.test(fleetId) || uidHash.length !== 32) throw new VaultDeniedError();
    const [picc, mac] = tapHex(tap);
    const rows = await this.exec(
      NO_CALLER,
      "select granted, attempt_id::text as attempt_id, batch_id::text as batch_id, batch_owner::text as batch_owner, encode(encrypted_payload, 'hex') as payload_hex, last_counter from vault_enclave.begin_sdm_tap($1::uuid, decode($2, 'hex'), decode($3, 'hex'), decode($4, 'hex'))",
      [fleetId, toHex(uidHash), picc, mac],
    );
    const row = TapBeginRow.safeParse(rows[0]);
    if (!row.success || !row.data.granted || !row.data.attempt_id || !row.data.batch_id || !row.data.batch_owner || !row.data.payload_hex) {
      throw new VaultDeniedError();
    }
    return { attemptId: row.data.attempt_id, batchId: row.data.batch_id, batchOwner: row.data.batch_owner, envelope: fromHex(row.data.payload_hex), lastCounter: row.data.last_counter };
  }

  async confirmSdmTap(attemptId: string, tap: SdmTapBytes, verified: boolean, readCounter: number | null): Promise<TapGrant | null> {
    if (!UUID_RE.test(attemptId)) throw new VaultDeniedError();
    const [picc, mac] = tapHex(tap);
    const counter = readCounter !== null && Number.isInteger(readCounter) && readCounter >= 0 && readCounter <= 0xfffffe ? readCounter : null;
    const rows = await this.exec(
      NO_CALLER,
      "select vault_enclave.confirm_sdm_tap($1::uuid, decode($2, 'hex'), decode($3, 'hex'), $4, $5::int) as grant_ref",
      [attemptId, picc, mac, verified === true, counter],
    );
    const ref = rows[0]?.["grant_ref"];
    return isTapGrant(ref) ? ref : null;
  }

  async consumeSdmTap(caller: VaultCaller | null, grant: TapGrant, purpose: SdmTapPurpose): Promise<SdmCardState | null> {
    if (!isTapGrant(grant) || (purpose !== "public_proof" && purpose !== "step_up")) throw new VaultDeniedError();
    const rows = await this.exec(caller ? callerId(caller) : NO_CALLER, "select granted, card_state from vault_enclave.consume_sdm_tap($1, $2)", [grant, purpose]);
    const row = z.object({ granted: z.boolean(), card_state: z.enum(["active", "unactivated"]).nullable() }).safeParse(rows[0]);
    return row.success && row.data.granted && row.data.card_state ? row.data.card_state : null;
  }
}

let port: IVaultPort | undefined;
/** The process-wide vault port. Swap the adapter here, nowhere else. */
export function vaultPort(): IVaultPort {
  port ??= new LocalPostgresVaultAdapter();
  return port;
}

/**
 * Reads a sealed envelope for the signed-in member. Requires the member's
 * fresh passkey step-up for "vault_token_read" (spent once, here and in the enclave).
 */
export async function readVaultEnvelope<K extends OpaqueTokenKind>(userId: string, ref: OpaqueToken<K>): Promise<VaultEnvelope<K>> {
  const { ensureStepUpProof, StepUpRequiredError } = await import("@/lib/auth/step-up.server");
  const { stepUpProofId } = await import("./step-up-proof-id");
  const proof = await ensureStepUpProof(userId, "vault_token_read");
  if (proof.method !== "passkey") throw new StepUpRequiredError();
  return vaultPort().retrieveToken({ userId }, ref, { verified: true, proofId: stepUpProofId(proof.jti) });
}
