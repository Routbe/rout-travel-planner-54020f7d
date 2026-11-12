// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  RecoveryError,
  createPaperFactor,
  beginRecoveryCeremony,
  completeRecoveryCeremony,
  createRecoveryCeremony,
  factorKeys,
  openFactorShard,
  paperFactorKeys,
  recoverMasterKey,
  type RecoveryFactor,
} from "./recovery-mpc";

const ALICE = "00000000-0000-4000-8000-00000000000a";
const BOB = "00000000-0000-4000-8000-00000000000b";
const master = new Uint8Array(32).map((_, i) => i + 1);
const device = factorKeys("device_prf", new Uint8Array(32).fill(7), ALICE);
const card = factorKeys("server_guardian", new Uint8Array(32).fill(9), ALICE);
const paper = createPaperFactor(ALICE);
const pub = { device_prf: device.publicKey, server_guardian: card.publicKey, paper_guardian: paper.keys.publicKey };
const sec = { device_prf: device.secretKey, server_guardian: card.secretKey, paper_guardian: paper.keys.secretKey };

const pick = (...factors: RecoveryFactor[]) => Object.fromEntries(factors.map((f) => [f, sec[f]]));

describe("2-of-3 recovery", async () => {
  const ceremony = await createRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: pub });

  it("any two factors, or all three, rebuild the Master Key", async () => {
    for (const set of [["device_prf", "server_guardian"], ["device_prf", "paper_guardian"], ["server_guardian", "paper_guardian"], ["device_prf", "server_guardian", "paper_guardian"]] as RecoveryFactor[][]) {
      expect([...(await recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick(...set) }))]).toEqual([...master]);
    }
  });

  it("one factor alone is refused", async () => {
    for (const f of ["device_prf", "server_guardian", "paper_guardian"] as RecoveryFactor[]) {
      await expect(recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick(f) })).rejects.toThrow(RecoveryError);
    }
  });

  it("the paper factor comes back from its 24 words, and a wrong word fails", async () => {
    const words = paper.mnemonic.split(" ");
    expect(words).toHaveLength(24);
    const again = paperFactorKeys(`  ${paper.mnemonic.toUpperCase()} `, ALICE);
    expect([...(await recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: { device_prf: device.secretKey, paper_guardian: again.secretKey } }))]).toEqual([...master]);
    const swapped = [...words];
    [swapped[0], swapped[1]] = [swapped[1] ?? "", swapped[0] ?? ""];
    expect(() => paperFactorKeys(swapped.join(" "), ALICE)).toThrow(RecoveryError);
    // Same words, other member: a different key, so the shard does not open.
    const bobPaper = paperFactorKeys(paper.mnemonic, BOB);
    expect([...bobPaper.publicKey]).not.toEqual([...paper.keys.publicKey]);
  });

  it("shards are bound to their factor, member and ceremony", async () => {
    // A factor key used for another factor's shard.
    await expect(recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: { device_prf: card.secretKey, server_guardian: card.secretKey } })).rejects.toThrow(RecoveryError);
    // The ceremony presented for another member.
    await expect(recoverMasterKey({ ceremony: { ...ceremony, memberId: BOB }, memberId: BOB, factorSecretKeys: pick("device_prf", "server_guardian") })).rejects.toThrow(RecoveryError);
    // Shards of two ceremonies mixed.
    const other = await createRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: pub });
    expect(other.ceremonyId).not.toBe(ceremony.ceremonyId);
    const mixed = { ...ceremony, shards: { ...ceremony.shards, server_guardian: other.shards.server_guardian } };
    await expect(recoverMasterKey({ ceremony: mixed, memberId: ALICE, factorSecretKeys: pick("device_prf", "server_guardian") })).rejects.toThrow(RecoveryError);
  });

  it("detects a tampered shard or sealed Master Key", async () => {
    const shard = ceremony.shards.device_prf.slice();
    shard[shard.length - 1] = (shard[shard.length - 1] ?? 0) ^ 1;
    await expect(recoverMasterKey({ ceremony: { ...ceremony, shards: { ...ceremony.shards, device_prf: shard } }, memberId: ALICE, factorSecretKeys: pick("device_prf", "server_guardian") })).rejects.toThrow(RecoveryError);
    const sealed = ceremony.sealedMaster.slice();
    sealed[30] = (sealed[30] ?? 0) ^ 1;
    await expect(recoverMasterKey({ ceremony: { ...ceremony, sealedMaster: sealed }, memberId: ALICE, factorSecretKeys: pick("device_prf", "server_guardian") })).rejects.toThrow(RecoveryError);
  });

  it("refuses duplicate factor keys and bad inputs at creation", async () => {
    await expect(createRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: { ...pub, server_guardian: device.publicKey } })).rejects.toThrow(TypeError);
    await expect(createRecoveryCeremony({ masterKey: new Uint8Array(16), memberId: ALICE, factorPublicKeys: pub })).rejects.toThrow(TypeError);
    await expect(createRecoveryCeremony({ masterKey: master, memberId: "alice", factorPublicKeys: pub })).rejects.toThrow(TypeError);
  });

  it("a two-step ceremony seals the device shard last and wipes it", async () => {
    const { draft, deviceShare } = await beginRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: { paper_guardian: paper.keys.publicKey, server_guardian: card.publicKey } });
    expect(Object.keys(draft.shards).sort()).toEqual(["paper_guardian", "server_guardian"]);
    const share = deviceShare;
    const full = completeRecoveryCeremony(draft, deviceShare, device.publicKey);
    expect(share.every((b) => b === 0)).toBe(true);
    expect([...(await recoverMasterKey({ ceremony: full, memberId: ALICE, factorSecretKeys: pick("device_prf", "paper_guardian") }))]).toEqual([...master]);
  });

  it("refuses a device key equal to the paper or server factor key", async () => {
    const { draft, deviceShare } = await beginRecoveryCeremony({ masterKey: master, memberId: ALICE, factorPublicKeys: { paper_guardian: paper.keys.publicKey, server_guardian: card.publicKey } });
    expect(() => completeRecoveryCeremony(draft, deviceShare, paper.keys.publicKey)).toThrow(TypeError);
    expect(deviceShare.every((b) => b === 0)).toBe(true);
  });

  it("the server's opened shard plus one member factor rebuilds the key; the server shard alone does not", async () => {
    const serverShare = openFactorShard(ceremony, ALICE, "server_guardian", card.secretKey);
    expect([...(await recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: pick("paper_guardian"), openedShares: { server_guardian: serverShare } }))]).toEqual([...master]);
    expect(serverShare.every((b) => b === 0)).toBe(true);
    const alone = openFactorShard(ceremony, ALICE, "server_guardian", card.secretKey);
    await expect(recoverMasterKey({ ceremony, memberId: ALICE, factorSecretKeys: {}, openedShares: { server_guardian: alone } })).rejects.toThrow(RecoveryError);
    expect(alone.every((b) => b === 0)).toBe(true);
    expect(() => openFactorShard(ceremony, ALICE, "server_guardian", device.secretKey)).toThrow(RecoveryError);
  });
});
