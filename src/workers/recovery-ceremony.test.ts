// @vitest-environment node
import { describe, expect, it } from "vitest";
import { handleCeremony, heldFingerprint } from "./recovery-ceremony-core";

const M = "00000000-0000-4000-8000-00000000000a";
const prf = () => new Uint8Array(32).fill(7);
const card = () => new Uint8Array(32).fill(9);

describe("recovery ceremony worker", () => {
  it("2 of 3 factors rebuild the same key, 1 is refused, wipe clears memory", async () => {
    const c = await handleCeremony({ id: 1, op: "create", memberId: M, devicePrf: prf(), cardSecret: card() });
    if (!c.ok) throw new Error("create failed");
    expect(JSON.stringify(c)).not.toContain("masterKey");
    const fp = c.fingerprint;
    await handleCeremony({ id: 2, op: "wipe" });
    expect(heldFingerprint()).toBeNull();
    for (const f of [{ devicePrf: prf(), cardSecret: card() }, { devicePrf: prf(), paperWords: c.paperWords }, { cardSecret: card(), paperWords: c.paperWords }]) {
      const r = await handleCeremony({ id: 3, op: "recover", memberId: M, ceremony: c.ceremony!, ...f });
      expect(r).toMatchObject({ ok: true, fingerprint: fp });
    }
    expect(await handleCeremony({ id: 4, op: "recover", memberId: M, ceremony: c.ceremony!, devicePrf: prf() })).toMatchObject({ ok: false, error: "recovery_failed" });
  });

  it("wipes the secret inputs it received", async () => {
    const p = prf();
    await handleCeremony({ id: 5, op: "create", memberId: M, devicePrf: p, cardSecret: card() });
    expect(p.every((b) => b === 0)).toBe(true);
  });
});
