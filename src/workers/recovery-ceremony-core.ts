/**
 * Message handler for the 2-of-3 recovery ceremony worker. Lives apart from the
 * worker entry so it can be tested in Node. The Master Key is generated and
 * rebuilt here and never leaves this module: replies carry only the sealed
 * ceremony, the paper words the member must write down, and a fingerprint.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  RecoveryError, createPaperFactor, createRecoveryCeremony, factorKeys, paperFactorKeys, recoverMasterKey,
  type RecoveryCeremony, type RecoveryFactor,
} from "@/lib/crypto-enclave/recovery-mpc";

export type CeremonyRequest =
  | { id: number; op: "create"; memberId: string; devicePrf: Uint8Array; cardSecret: Uint8Array }
  | { id: number; op: "recover"; memberId: string; ceremony: RecoveryCeremony; devicePrf?: Uint8Array; cardSecret?: Uint8Array; paperWords?: string }
  | { id: number; op: "wipe" };

export type CeremonyResponse =
  | { id: number; ok: true; ceremony?: RecoveryCeremony; paperWords?: string; fingerprint?: string }
  | { id: number; ok: false; error: "recovery_failed" | "invalid_request" };

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
let held: Uint8Array | null = null;
const hold = (k: Uint8Array) => { held?.fill(0); held = k; return hex(sha256(k)).slice(0, 16); };

/** Fingerprint of the key currently held in worker memory, for tests. */
export const heldFingerprint = () => (held ? hex(sha256(held)).slice(0, 16) : null);

export async function handleCeremony(req: CeremonyRequest): Promise<CeremonyResponse> {
  const wipeIn: (Uint8Array | undefined)[] = [];
  try {
    if (req.op === "wipe") { held?.fill(0); held = null; return { id: req.id, ok: true }; }
    if (req.op === "create") {
      wipeIn.push(req.devicePrf, req.cardSecret);
      const master = randomBytes(32);
      const paper = createPaperFactor(req.memberId);
      const ceremony = await createRecoveryCeremony({
        masterKey: master, memberId: req.memberId,
        factorPublicKeys: {
          device_prf: factorKeys("device_prf", req.devicePrf, req.memberId).publicKey,
          nfc_card: factorKeys("nfc_card", req.cardSecret, req.memberId).publicKey,
          paper_guardian: paper.keys.publicKey,
        },
      });
      paper.keys.secretKey.fill(0);
      return { id: req.id, ok: true, ceremony, paperWords: paper.mnemonic, fingerprint: hold(master) };
    }
    if (req.op === "recover") {
      wipeIn.push(req.devicePrf, req.cardSecret);
      const keys: Partial<Record<RecoveryFactor, Uint8Array>> = {};
      if (req.devicePrf) keys.device_prf = factorKeys("device_prf", req.devicePrf, req.memberId).secretKey;
      if (req.cardSecret) keys.nfc_card = factorKeys("nfc_card", req.cardSecret, req.memberId).secretKey;
      if (req.paperWords) keys.paper_guardian = paperFactorKeys(req.paperWords, req.memberId).secretKey;
      try {
        const master = await recoverMasterKey({ ceremony: req.ceremony, memberId: req.memberId, factorSecretKeys: keys });
        return { id: req.id, ok: true, fingerprint: hold(master) };
      } finally {
        Object.values(keys).forEach((k) => k?.fill(0));
      }
    }
    return { id: (req as { id: number }).id, ok: false, error: "invalid_request" };
  } catch (e) {
    return { id: req.id, ok: false, error: e instanceof RecoveryError ? "recovery_failed" : "invalid_request" };
  } finally {
    for (const b of wipeIn) b?.fill(0);
  }
}
