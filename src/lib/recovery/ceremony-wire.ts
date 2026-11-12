/**
 * Transport form of a 2-of-3 recovery ceremony: every envelope as standard
 * base64, so it crosses server functions and the database as plain text.
 * Contains only ciphertext; no factor, share or key.
 */
import type { RecoveryCeremony, RecoveryFactor } from "@/lib/crypto-enclave/recovery-mpc";

export type CeremonyWire = {
  ceremonyId: string;
  keyId: string;
  sealedMaster: string;
  shards: Record<RecoveryFactor, string>;
};

export const CEREMONY_ID_RE = /^[0-9a-f]{32}$/;
export const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
export const SHARD_B64_MAX = 6000;
export const MASTER_B64_MAX = 400;

/** Restores with the server's piece per member per hour (fail-closed). */
export const CEREMONY_RESTORES_PER_HOUR = 5;

export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromB64(value: string): Uint8Array {
  if (!B64_RE.test(value)) throw new TypeError("invalid_base64");
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

export function ceremonyToWire(c: RecoveryCeremony, keyId: string): CeremonyWire {
  return {
    ceremonyId: c.ceremonyId,
    keyId,
    sealedMaster: toB64(c.sealedMaster),
    shards: { device_prf: toB64(c.shards.device_prf), paper_guardian: toB64(c.shards.paper_guardian), server_guardian: toB64(c.shards.server_guardian) },
  };
}

export function ceremonyFromWire(w: CeremonyWire, memberId: string): RecoveryCeremony {
  if (!CEREMONY_ID_RE.test(w.ceremonyId)) throw new TypeError("invalid_ceremony");
  return {
    version: 1,
    ceremonyId: w.ceremonyId,
    memberId,
    threshold: 2,
    sealedMaster: fromB64(w.sealedMaster),
    shards: { device_prf: fromB64(w.shards.device_prf), paper_guardian: fromB64(w.shards.paper_guardian), server_guardian: fromB64(w.shards.server_guardian) },
  };
}

/** Number of words typed so far (for enabling a button; the words themselves are not kept). */
export function wordCount(text: string): number {
  const t = text.trim();
  return t ? t.split(/\s+/).length : 0;
}
