/**
 * Sign-in by recovery: what the crypto worker signs and the server verifies.
 *
 * The Ed25519 login key is derived from the Master Key (recovery-mpc's
 * loginKeyFromMaster) and only its public half is stored with the ceremony.
 * Rebuilding the Master Key from any two factors is therefore the only way to
 * sign a server challenge for this member. Browser- and server-safe: no secret.
 */
import { ed25519 } from "@noble/curves/ed25519.js";

const enc = new TextEncoder();
export const RECOVERY_LOGIN_DOMAIN = "rout.recovery.login.v1";
export const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Domain-separated message: a signature for one member and challenge never fits another. */
export function recoveryLoginMessage(memberId: string, challenge: string): Uint8Array {
  if (!UUID_RE.test(memberId) || !CHALLENGE_RE.test(challenge)) throw new TypeError("invalid_login_message");
  return enc.encode(`${RECOVERY_LOGIN_DOMAIN}|${memberId}|${challenge}`);
}

export function verifyRecoveryLogin(publicKey: Uint8Array, memberId: string, challenge: string, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    return ed25519.verify(signature, recoveryLoginMessage(memberId, challenge), publicKey);
  } catch {
    return false;
  }
}
