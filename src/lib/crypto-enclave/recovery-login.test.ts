// @vitest-environment node
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { forgetDeviceKey, loadDeviceKey } from "@/lib/e2ee/device-key";
import { openServerShard, serverFactorPublicKey } from "@/lib/recovery/server-factor.server";
import { verifyRecoveryLogin } from "@/lib/recovery/recovery-login";
import { runEnclaveOp } from "./enclave-core";
import type { EnclaveOp, EnclaveOps } from "./protocol";
import type { RecoveryCeremony } from "./recovery-mpc";

const SECRET = "A".repeat(32) + "b".repeat(32);
const CHALLENGE = "c".repeat(43);
const prfOf = (n: number) => new Uint8Array(32).fill(n);

async function call<K extends EnclaveOp>(op: K, args: EnclaveOps[K]["req"]): Promise<EnclaveOps[K]["res"]> {
  const r = await runEnclaveOp(op, args);
  if (!r.ok) throw new Error(r.code);
  return r.result as EnclaveOps[K]["res"];
}
const code = async (op: EnclaveOp, args: unknown) => {
  const r = await runEnclaveOp(op, args);
  return r.ok ? "ok" : r.code;
};

async function setup(userId: string) {
  const begun = await call("ceremony.begin", { userId, serverFactorKey: serverFactorPublicKey(userId, SECRET) });
  const words = begun.paperWords.split(" ");
  const answers = begun.checkPositions.map((position) => ({ position, word: words[position - 1] ?? "" }));
  await call("ceremony.checkWords", { handle: begun.handle, answers });
  const sealed = await call("ceremony.sealDevice", { handle: begun.handle, prf: prfOf(5) });
  const committed = await call("ceremony.commit", { handle: begun.handle, userId });
  return { ceremony: sealed.ceremony as RecoveryCeremony, keyId: committed.keyId, loginKey: sealed.loginKey, paper: begun.paperWords };
}

describe("sign-in by recovery in the crypto enclave", () => {
  let n = 0;
  const nextUser = () => `00000000-0000-4000-8000-0000000000d${++n}`;

  it("any two pieces sign the server challenge with the key whose public half was stored", async () => {
    const userId = nextUser();
    const { ceremony, keyId, loginKey, paper } = await setup(userId);
    expect(loginKey).toHaveLength(32);
    const server = () => openServerShard(structuredClone(ceremony), userId, SECRET);
    const base = { userId, keyId, challenge: CHALLENGE };
    for (const pieces of [
      { paperWords: paper, serverShare: server() },
      { prf: prfOf(5), serverShare: server() },
      { prf: prfOf(5), paperWords: paper },
    ]) {
      await forgetDeviceKey(userId);
      const r = await call("ceremony.recoverLogin", { ...base, ceremony: structuredClone(ceremony), ...pieces });
      expect(r.keyId).toBe(keyId);
      expect(verifyRecoveryLogin(loginKey, userId, CHALLENGE, r.signature)).toBe(true);
      // Bound to member and challenge.
      expect(verifyRecoveryLogin(loginKey, userId, "d".repeat(43), r.signature)).toBe(false);
      expect(verifyRecoveryLogin(loginKey, "00000000-0000-4000-8000-0000000000ff", CHALLENGE, r.signature)).toBe(false);
      // The Master Key is back on this device.
      expect((await loadDeviceKey(userId))?.keyId).toBe(keyId);
    }
  });

  it("one piece alone signs nothing and installs nothing", async () => {
    const userId = nextUser();
    const { ceremony, keyId, paper } = await setup(userId);
    const server = () => openServerShard(structuredClone(ceremony), userId, SECRET);
    await forgetDeviceKey(userId);
    const base = { userId, keyId, challenge: CHALLENGE };
    expect(await code("ceremony.recoverLogin", { ...base, ceremony: structuredClone(ceremony), serverShare: server() })).toBe("decrypt_failed");
    expect(await code("ceremony.recoverLogin", { ...base, ceremony: structuredClone(ceremony), paperWords: paper })).toBe("decrypt_failed");
    expect(await code("ceremony.recoverLogin", { ...base, ceremony: structuredClone(ceremony), prf: prfOf(5) })).toBe("decrypt_failed");
    expect(await code("ceremony.recoverLogin", { ...base, ceremony: structuredClone(ceremony), prf: prfOf(9), serverShare: server() })).toBe("decrypt_failed");
    expect(await loadDeviceKey(userId)).toBeNull();
  });

  it("zero-fills the pieces it was handed, on success and on failure", async () => {
    const userId = nextUser();
    const { ceremony, keyId, paper } = await setup(userId);
    await forgetDeviceKey(userId);
    const prf = prfOf(5);
    const share = openServerShard(structuredClone(ceremony), userId, SECRET);
    await call("ceremony.recoverLogin", { userId, keyId, challenge: CHALLENGE, ceremony: structuredClone(ceremony), prf, serverShare: share });
    expect(prf.every((b) => b === 0)).toBe(true);
    expect(share.every((b) => b === 0)).toBe(true);

    await forgetDeviceKey(userId);
    const badPrf = prfOf(9);
    const badShare = openServerShard(structuredClone(ceremony), userId, SECRET);
    expect(await code("ceremony.recoverLogin", { userId, keyId, challenge: CHALLENGE, ceremony: structuredClone(ceremony), prf: badPrf, serverShare: badShare, paperWords: undefined })).toBe("decrypt_failed");
    expect(badPrf.every((b) => b === 0)).toBe(true);
    expect(badShare.every((b) => b === 0)).toBe(true);
    void paper;
  });

  it("refuses a malformed challenge before rebuilding anything, and still wipes the pieces", async () => {
    const userId = nextUser();
    const { ceremony, keyId, paper } = await setup(userId);
    await forgetDeviceKey(userId);
    const prf = prfOf(5);
    expect(await code("ceremony.recoverLogin", { userId, keyId, challenge: "short", ceremony: structuredClone(ceremony), prf, paperWords: paper })).toBe("invalid_input");
    expect(prf.every((b) => b === 0)).toBe(true);
    expect(await loadDeviceKey(userId)).toBeNull();
  });
});
