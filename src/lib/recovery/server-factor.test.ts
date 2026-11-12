// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRecoveryCeremony, factorKeys, createPaperFactor } from "@/lib/crypto-enclave/recovery-mpc";
import { isOwnServerShard, openServerShard, RecoveryFactorSecretMissingError, serverFactorPublicKey } from "./server-factor.server";

const ALICE = "00000000-0000-4000-8000-00000000000a";
const BOB = "00000000-0000-4000-8000-00000000000b";
const SECRET = "Z".repeat(64);

describe("ROUT's recovery factor", () => {
  const saved = process.env["ROUT_RECOVERY_FACTOR_SECRET"];
  beforeEach(() => { delete process.env["ROUT_RECOVERY_FACTOR_SECRET"]; });
  afterEach(() => {
    if (saved === undefined) delete process.env["ROUT_RECOVERY_FACTOR_SECRET"];
    else process.env["ROUT_RECOVERY_FACTOR_SECRET"] = saved;
  });

  it("refuses to work without a strong secret", () => {
    expect(() => serverFactorPublicKey(ALICE)).toThrow(RecoveryFactorSecretMissingError);
    expect(() => serverFactorPublicKey(ALICE, "short")).toThrow(RecoveryFactorSecretMissingError);
    process.env["ROUT_RECOVERY_FACTOR_SECRET"] = SECRET;
    expect(serverFactorPublicKey(ALICE)).toEqual(serverFactorPublicKey(ALICE, SECRET));
  });

  it("is a different key per member and per secret", () => {
    expect(serverFactorPublicKey(ALICE, SECRET)).not.toEqual(serverFactorPublicKey(BOB, SECRET));
    expect(serverFactorPublicKey(ALICE, SECRET)).not.toEqual(serverFactorPublicKey(ALICE, "Y".repeat(64)));
  });

  it("opens only its own shard", async () => {
    const ceremony = await createRecoveryCeremony({
      masterKey: new Uint8Array(32).fill(3),
      memberId: ALICE,
      factorPublicKeys: {
        device_prf: factorKeys("device_prf", new Uint8Array(32).fill(1), ALICE).publicKey,
        paper_guardian: createPaperFactor(ALICE).keys.publicKey,
        server_guardian: serverFactorPublicKey(ALICE, SECRET),
      },
    });
    expect(isOwnServerShard(ALICE, ceremony.shards.server_guardian, SECRET)).toBe(true);
    expect(isOwnServerShard(ALICE, ceremony.shards.paper_guardian, SECRET)).toBe(false);
    expect(isOwnServerShard(BOB, ceremony.shards.server_guardian, SECRET)).toBe(false);
    expect(openServerShard(ceremony, ALICE, SECRET).length).toBeGreaterThan(0);
    expect(() => openServerShard(ceremony, ALICE, "Y".repeat(64))).toThrow();
  });
});
