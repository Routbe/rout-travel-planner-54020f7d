/**
 * ROUT's own factor in the 2-of-3 recovery ceremony ("server_guardian").
 *
 * The factor secret is derived per member from ROUT_RECOVERY_FACTOR_SECRET
 * (read at call time, never at module scope) with HKDF-SHA-256 under its own
 * label, then turned into an RVE1 recipient key by recovery-mpc's factorKeys.
 * The server can open only the shard sealed to this key: one share of the
 * ceremony key, which alone reveals nothing about the Master Key.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { wipe } from "@/lib/crypto/wipe";
import { envelopeKeyId, keyId } from "@/lib/crypto-enclave/pqc-envelope";
import { factorKeys, openFactorShard, type RecoveryCeremony } from "@/lib/crypto-enclave/recovery-mpc";

const SECRET_RE = /^[A-Za-z0-9]{64,512}$/;
const enc = new TextEncoder();

export class RecoveryFactorSecretMissingError extends Error {
  constructor() {
    super("recovery_factor_secret_missing");
    this.name = "RecoveryFactorSecretMissingError";
  }
}

function factorSecret(memberId: string, secret = process.env["ROUT_RECOVERY_FACTOR_SECRET"]): Uint8Array {
  if (!secret || !SECRET_RE.test(secret)) throw new RecoveryFactorSecretMissingError();
  const ikm = enc.encode(secret);
  try {
    return hkdf(sha256, ikm, enc.encode("rout.recovery.server-factor.v1"), enc.encode(memberId), 32);
  } finally {
    wipe(ikm);
  }
}

/** The member's server-factor public key (safe to hand to the browser). */
export function serverFactorPublicKey(memberId: string, secret?: string): Uint8Array {
  const s = factorSecret(memberId, secret);
  try {
    const keys = factorKeys("server_guardian", s, memberId);
    wipe(keys.secretKey);
    return keys.publicKey;
  } finally {
    wipe(s);
  }
}

/** True when the server shard is sealed to this member's server-factor key. */
export function isOwnServerShard(memberId: string, envelope: Uint8Array, secret?: string): boolean {
  const kid = keyId(serverFactorPublicKey(memberId, secret));
  let other: Uint8Array;
  try {
    other = envelopeKeyId(envelope);
  } catch {
    return false;
  }
  if (other.length !== kid.length) return false;
  let d = 0;
  for (let i = 0; i < kid.length; i++) d |= (kid[i] ?? 0) ^ (other[i] ?? 0);
  return d === 0;
}

/** Opens the server's own shard. The caller owns (and must wipe) the returned share. */
export function openServerShard(ceremony: RecoveryCeremony, memberId: string, secret?: string): Uint8Array {
  const s = factorSecret(memberId, secret);
  let sk: Uint8Array | null = null;
  try {
    sk = factorKeys("server_guardian", s, memberId).secretKey;
    return openFactorShard(ceremony, memberId, "server_guardian", sk);
  } finally {
    wipe(s, sk);
  }
}
