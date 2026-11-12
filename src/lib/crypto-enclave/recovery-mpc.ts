/**
 * 2-of-3 Master Key recovery.
 *
 * A fresh 256-bit ceremony key seals the Master Key (XChaCha20-Poly1305, AAD
 * bound to member + ceremony). The ceremony key, not the Master Key, is split
 * with Shamir (shamir-secret-sharing) into three shares, one per factor:
 *
 *   device_prf       key derived from the WebAuthn PRF output of a passkey
 *   paper_guardian   key derived from a 24-word BIP39 phrase kept offline
 *   server_guardian  key derived on the server from ROUT_RECOVERY_FACTOR_SECRET;
 *                    the server can open only this one shard, never two
 *
 * Each share travels only as an `mpc` RVE1 envelope (pqc-envelope.ts, holder
 * "shard_factor") sealed to its own factor, with a context naming member,
 * ceremony and factor: a shard moved to another factor, member or ceremony no
 * longer opens. Any two factors reconstruct; one reveals nothing. Rotating the
 * factors means a new ceremony (new key, new id); the Master Key can stay.
 *
 * Every failure while recovering throws the same RecoveryError. Ceremony keys
 * and shares are wiped in `finally`; callers wipe the Master Key they pass in
 * and the one they get back.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { combine, split } from "shamir-secret-sharing";
import { envelopeKeyId, generateRecipientKeys, keyId, openEnvelope, sealEnvelope, type RecipientKeys } from "./pqc-envelope";

export const RECOVERY_FACTORS = ["device_prf", "paper_guardian", "server_guardian"] as const;
export type RecoveryFactor = (typeof RECOVERY_FACTORS)[number];
export const RECOVERY_THRESHOLD = 2;
export const RECOVERY_SHARES = 3;
const MASTER_KEY_BYTES = 32;
const NONCE_BYTES = 24;
const CEREMONY_ID_BYTES = 16;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type RecoveryCeremony = {
  version: 1;
  ceremonyId: string; // 32 hex
  memberId: string;
  threshold: typeof RECOVERY_THRESHOLD;
  /** nonce (24) || XChaCha20-Poly1305(Master Key). */
  sealedMaster: Uint8Array;
  /** One mpc RVE1 envelope per factor. */
  shards: Readonly<Record<RecoveryFactor, Uint8Array>>;
};

export class RecoveryError extends Error {
  constructor() {
    super("recovery_failed");
    this.name = "RecoveryError";
  }
}

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const wipe = (...arrays: (Uint8Array | undefined)[]) => {
  for (const a of arrays) a?.fill(0);
};

function checkMember(memberId: string) {
  if (!UUID_RE.test(memberId)) throw new TypeError("member_id_invalid");
}
const masterAad = (memberId: string, ceremonyId: string) => enc.encode(`rout.recovery.mpc.master.v1|${memberId}|${ceremonyId}`);
const shardContext = (memberId: string, ceremonyId: string, factor: RecoveryFactor) =>
  `rout.recovery.mpc.shard.v1|${memberId}|${ceremonyId}|${factor}`;

/** Deterministic factor key pair from a 32-byte factor secret (PRF output, card secret, phrase entropy). */
export function factorKeys(factor: RecoveryFactor, factorSecret: Uint8Array, memberId: string): RecipientKeys {
  checkMember(memberId);
  if (factorSecret.length !== 32) throw new TypeError("factor_secret_must_be_32_bytes");
  const seed = hkdf(sha256, factorSecret, enc.encode("rout.recovery.factor.v1"), enc.encode(`${factor}|${memberId}`), 32);
  try {
    return generateRecipientKeys("shard_factor", seed);
  } finally {
    wipe(seed);
  }
}

/** A new offline paper/guardian factor: 24 BIP39 words (256-bit entropy). */
export function createPaperFactor(memberId: string): { mnemonic: string; keys: RecipientKeys } {
  const entropy = randomBytes(32);
  try {
    return { mnemonic: entropyToMnemonic(entropy, wordlist), keys: factorKeys("paper_guardian", entropy, memberId) };
  } finally {
    wipe(entropy);
  }
}

/** Re-derives the paper factor from its words; a mistyped word fails the BIP39 checksum. */
export function paperFactorKeys(mnemonic: string, memberId: string): RecipientKeys {
  const normalized = mnemonic.trim().toLowerCase().split(/\s+/).join(" ");
  if (normalized.split(" ").length !== 24 || !validateMnemonic(normalized, wordlist)) throw new RecoveryError();
  const entropy = mnemonicToEntropy(normalized, wordlist);
  try {
    return factorKeys("paper_guardian", entropy, memberId);
  } finally {
    wipe(entropy);
  }
}

/** A ceremony whose device shard is not sealed yet; holds no secret. */
export type CeremonyDraft = Omit<RecoveryCeremony, "shards"> & { shards: Readonly<Record<Exclude<RecoveryFactor, "device_prf">, Uint8Array>> };

/**
 * First half of a ceremony: seals the Master Key, splits the ceremony key and
 * seals the paper and server shards. The device share comes back raw (one
 * share reveals nothing) so it can be sealed once the passkey is available;
 * the caller must wipe it, normally via completeRecoveryCeremony.
 */
export async function beginRecoveryCeremony(input: {
  masterKey: Uint8Array;
  memberId: string;
  factorPublicKeys: Readonly<Record<Exclude<RecoveryFactor, "device_prf">, Uint8Array>>;
}): Promise<{ draft: CeremonyDraft; deviceShare: Uint8Array }> {
  const { masterKey, memberId, factorPublicKeys } = input;
  checkMember(memberId);
  if (masterKey.length !== MASTER_KEY_BYTES) throw new TypeError("master_key_must_be_32_bytes");
  if (hex(factorPublicKeys.paper_guardian) === hex(factorPublicKeys.server_guardian)) throw new TypeError("factor_keys_must_differ");

  const ceremonyKey = randomBytes(32);
  const ceremonyId = hex(randomBytes(CEREMONY_ID_BYTES));
  let shares: Uint8Array[] = [];
  try {
    const nonce = randomBytes(NONCE_BYTES);
    const body = xchacha20poly1305(ceremonyKey, nonce, masterAad(memberId, ceremonyId)).encrypt(masterKey);
    const sealedMaster = new Uint8Array(NONCE_BYTES + body.length);
    sealedMaster.set(nonce);
    sealedMaster.set(body, NONCE_BYTES);

    shares = await split(ceremonyKey, RECOVERY_SHARES, RECOVERY_THRESHOLD);
    const seal = (factor: Exclude<RecoveryFactor, "device_prf">, share: Uint8Array | undefined) => {
      if (!share) throw new Error("split_failed");
      return sealEnvelope({ kind: "mpc", holder: "shard_factor", recipientPublicKey: factorPublicKeys[factor], plaintext: share, context: shardContext(memberId, ceremonyId, factor) });
    };
    const deviceShare = shares[0];
    if (!deviceShare) throw new Error("split_failed");
    const shards = Object.freeze({ paper_guardian: seal("paper_guardian", shares[1]), server_guardian: seal("server_guardian", shares[2]) });
    shares = shares.slice(1); // the device share is the caller's now; the rest is wiped below
    return { draft: { version: 1, ceremonyId, memberId, threshold: RECOVERY_THRESHOLD, sealedMaster, shards }, deviceShare };
  } finally {
    wipe(ceremonyKey, ...shares);
  }
}

/** Second half: seals the device share to the passkey factor and wipes it. */
export function completeRecoveryCeremony(draft: CeremonyDraft, deviceShare: Uint8Array, devicePublicKey: Uint8Array): RecoveryCeremony {
  try {
    const device = hex(keyId(devicePublicKey));
    if (device === hex(envelopeKeyId(draft.shards.paper_guardian)) || device === hex(envelopeKeyId(draft.shards.server_guardian))) {
      throw new TypeError("factor_keys_must_differ");
    }
    const device_prf = sealEnvelope({
      kind: "mpc",
      holder: "shard_factor",
      recipientPublicKey: devicePublicKey,
      plaintext: deviceShare,
      context: shardContext(draft.memberId, draft.ceremonyId, "device_prf"),
    });
    return { ...draft, shards: Object.freeze({ device_prf, ...draft.shards }) };
  } finally {
    wipe(deviceShare);
  }
}

/** Both halves at once (all three factor public keys known up front). */
export async function createRecoveryCeremony(input: {
  masterKey: Uint8Array;
  memberId: string;
  factorPublicKeys: Readonly<Record<RecoveryFactor, Uint8Array>>;
}): Promise<RecoveryCeremony> {
  const { factorPublicKeys } = input;
  const distinct = new Set(RECOVERY_FACTORS.map((f) => hex(factorPublicKeys[f])));
  if (distinct.size !== RECOVERY_SHARES) throw new TypeError("factor_keys_must_differ");
  const { draft, deviceShare } = await beginRecoveryCeremony({
    masterKey: input.masterKey,
    memberId: input.memberId,
    factorPublicKeys: { paper_guardian: factorPublicKeys.paper_guardian, server_guardian: factorPublicKeys.server_guardian },
  });
  return completeRecoveryCeremony(draft, deviceShare, factorPublicKeys.device_prf);
}

/** Opens one factor's shard; the server uses this for its own factor only. Caller wipes the share. */
export function openFactorShard(ceremony: RecoveryCeremony, memberId: string, factor: RecoveryFactor, secretKey: Uint8Array): Uint8Array {
  try {
    if (ceremony.version !== 1 || ceremony.memberId !== memberId || !/^[0-9a-f]{32}$/.test(ceremony.ceremonyId)) throw new RecoveryError();
    const envelope = ceremony.shards[factor];
    if (!envelope) throw new RecoveryError();
    return openEnvelope({ envelope, expectedKind: "mpc", holder: "shard_factor", secretKey, context: shardContext(memberId, ceremony.ceremonyId, factor) });
  } catch {
    throw new RecoveryError();
  }
}

/** Rebuilds the Master Key from at least two factors' secret keys. */
export async function recoverMasterKey(input: {
  ceremony: RecoveryCeremony;
  memberId: string;
  factorSecretKeys: Partial<Record<RecoveryFactor, Uint8Array>>;
  /** Shares already opened by their holder (the server's own factor). Wiped here. */
  openedShares?: Partial<Record<RecoveryFactor, Uint8Array>>;
}): Promise<Uint8Array> {
  const { ceremony, memberId, factorSecretKeys } = input;
  const opened = input.openedShares ?? {};
  const present = RECOVERY_FACTORS.filter((f) => factorSecretKeys[f] !== undefined && opened[f] === undefined);
  const openedFactors = RECOVERY_FACTORS.filter((f) => opened[f] !== undefined);
  if (present.length + openedFactors.length < RECOVERY_THRESHOLD) {
    wipe(...openedFactors.map((f) => opened[f]));
    throw new RecoveryError();
  }
  const shares: Uint8Array[] = [];
  let ceremonyKey: Uint8Array | undefined;
  try {
    if (ceremony.version !== 1 || ceremony.memberId !== memberId || !/^[0-9a-f]{32}$/.test(ceremony.ceremonyId)) throw new RecoveryError();
    for (const factor of openedFactors) {
      const share = opened[factor];
      if (share) shares.push(share);
    }
    for (const factor of present) {
      const secretKey = factorSecretKeys[factor];
      const envelope = ceremony.shards[factor];
      if (!secretKey || !envelope) throw new RecoveryError();
      shares.push(
        openEnvelope({ envelope, expectedKind: "mpc", holder: "shard_factor", secretKey, context: shardContext(memberId, ceremony.ceremonyId, factor) }),
      );
    }
    ceremonyKey = await combine(shares);
    if (ceremonyKey.length !== 32 || ceremony.sealedMaster.length <= NONCE_BYTES) throw new RecoveryError();
    const nonce = ceremony.sealedMaster.subarray(0, NONCE_BYTES);
    const view = xchacha20poly1305(ceremonyKey, nonce, masterAad(memberId, ceremony.ceremonyId)).decrypt(
      ceremony.sealedMaster.subarray(NONCE_BYTES),
    );
    const master = view.slice();
    wipe(view);
    if (master.length !== MASTER_KEY_BYTES) throw new RecoveryError();
    return master;
  } catch {
    throw new RecoveryError();
  } finally {
    wipe(ceremonyKey, ...shares);
  }
}

/**
 * Ed25519 login key of the Master Key (sign-in by recovery). Only the public
 * key leaves; the caller wipes `secretKey` (the seed).
 */
export function loginKeyFromMaster(masterKey: Uint8Array, memberId: string): { secretKey: Uint8Array; publicKey: Uint8Array } {
  checkMember(memberId);
  if (masterKey.length !== MASTER_KEY_BYTES) throw new TypeError("master_key_must_be_32_bytes");
  const secretKey = hkdf(sha256, masterKey, enc.encode("rout.recovery.login-key.v1"), enc.encode(memberId), 32);
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}
