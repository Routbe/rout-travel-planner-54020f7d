import { cbc, cmac } from "@noble/ciphers/aes.js";
import { describe, expect, it } from "vitest";
import { cardDivInput, constantTimeEqual, decryptPiccData, diversifyAes128, SdmError, uidIndex, verifySdmTap, type SdmFailure } from "./sdm-verifier";

const zeroKeys = { metaReadKey: new Uint8Array(16), fileReadKey: new Uint8Array(16) };
// NXP AN12196 "SUN with encrypted PICCData" example (all-zero factory keys).
const nxp = { piccData: "EF963FF7828658A599F3041510671E88", cmac: "94EED9EE65337086" };

function reason(fn: () => unknown): SdmFailure | undefined {
  try {
    fn();
  } catch (e) {
    if (e instanceof SdmError) return e.reason;
    throw e;
  }
  return undefined;
}

/** Builds a tap the way a card would, for keys other than the factory ones. */
function simulateTap(keys: typeof zeroKeys, uid: number[], counter: number) {
  const plain = new Uint8Array(16);
  plain[0] = 0xc7;
  plain.set(uid, 1);
  plain.set([counter & 0xff, (counter >> 8) & 0xff, (counter >> 16) & 0xff], 8);
  const picc = cbc(keys.metaReadKey, new Uint8Array(16), { disablePadding: true }).encrypt(plain);
  const sv2 = Uint8Array.from([0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80, ...uid, ...plain.slice(8, 11)]);
  const full = cmac(new Uint8Array(0), cmac(sv2, keys.fileReadKey));
  const mac = Array.from({ length: 8 }, (_, i) => full[2 * i + 1] ?? 0);
  const hex = (b: ArrayLike<number>) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
  return { piccData: hex(picc), cmac: hex(mac) };
}

describe("NTAG 424 DNA SUN verification", () => {
  it("matches NXP's published example", () => {
    expect(verifySdmTap({ tap: nxp, keys: zeroKeys, lastCounter: null })).toEqual({ uid: "04DE5F1EACC040", readCounter: 61 });
    expect(verifySdmTap({ tap: { piccData: nxp.piccData.toLowerCase(), cmac: nxp.cmac.toLowerCase() }, keys: zeroKeys, lastCounter: 60, expectedUid: "04de5f1eacc040" }).readCounter).toBe(61);
  });

  it("refuses a replayed or older tap", () => {
    expect(reason(() => verifySdmTap({ tap: nxp, keys: zeroKeys, lastCounter: 61 }))).toBe("replayed");
    expect(reason(() => verifySdmTap({ tap: nxp, keys: zeroKeys, lastCounter: 100 }))).toBe("replayed");
  });

  it("refuses a forged MAC, wrong keys, and a different card", () => {
    expect(reason(() => verifySdmTap({ tap: { ...nxp, cmac: "94EED9EE65337087" }, keys: zeroKeys, lastCounter: null }))).toBe("auth_failed");
    const other = { metaReadKey: new Uint8Array(16), fileReadKey: new Uint8Array(16).fill(1) };
    expect(reason(() => verifySdmTap({ tap: nxp, keys: other, lastCounter: null }))).toBe("auth_failed");
    const wrongMeta = { metaReadKey: new Uint8Array(16).fill(2), fileReadKey: new Uint8Array(16) };
    expect(reason(() => verifySdmTap({ tap: nxp, keys: wrongMeta, lastCounter: null }))).toBe("auth_failed");
    expect(reason(() => verifySdmTap({ tap: nxp, keys: zeroKeys, lastCounter: null, expectedUid: "04DE5F1EACC041" }))).toBe("uid_mismatch");
  });

  it("refuses any tampered picc_data byte", () => {
    for (let i = 0; i < 32; i += 2) {
      const flipped = (Number.parseInt(nxp.piccData.slice(i, i + 2), 16) ^ 1).toString(16).padStart(2, "0");
      const tap = { ...nxp, piccData: nxp.piccData.slice(0, i) + flipped + nxp.piccData.slice(i + 2) };
      expect(reason(() => verifySdmTap({ tap, keys: zeroKeys, lastCounter: null })), `byte ${i / 2}`).toBe("auth_failed");
    }
  });

  it("rejects malformed input", () => {
    for (const tap of [
      { piccData: nxp.piccData.slice(2), cmac: nxp.cmac },
      { piccData: nxp.piccData, cmac: nxp.cmac + "00" },
      { piccData: `${nxp.piccData.slice(0, 31)}G`, cmac: nxp.cmac },
      { piccData: ` ${nxp.piccData.slice(1)}`, cmac: nxp.cmac },
    ]) {
      expect(reason(() => verifySdmTap({ tap, keys: zeroKeys, lastCounter: null }))).toBe("malformed");
    }
    expect(() => verifySdmTap({ tap: nxp, keys: { metaReadKey: new Uint8Array(8), fileReadKey: new Uint8Array(16) }, lastCounter: null })).toThrow(TypeError);
  });

  it("works with diversified per-card keys and an exhausted counter is refused", () => {
    const keys = { metaReadKey: new Uint8Array(16).fill(0x11), fileReadKey: new Uint8Array(16).fill(0x22) };
    const uid = [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    expect(verifySdmTap({ tap: simulateTap(keys, uid, 5), keys, lastCounter: 4 })).toEqual({ uid: "04112233445566", readCounter: 5 });
    expect(reason(() => verifySdmTap({ tap: simulateTap(keys, uid, 0xffffff), keys, lastCounter: 4 }))).toBe("counter_exhausted");
  });
});

describe("AN10922 key diversification and card lookup", () => {
  const h = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (x) => Number.parseInt(x, 16));
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();

  it("matches NXP's AN10922 AES-128 example", () => {
    // Master key, UID 04782E21801D80 || AID 3042F5 || system id "NXP Abu".
    const k = diversifyAes128(h("00112233445566778899AABBCCDDEEFF"), h("04782E21801D803042F54E585020416275"));
    expect(hex(k)).toBe("A8DD63A3B89D54B37CA802473FDA9175");
  });

  it("gives every card its own key and refuses inputs outside AN10922's length", () => {
    const master = new Uint8Array(16).fill(7);
    const batch = new Uint8Array(16).fill(9);
    const a = diversifyAes128(master, cardDivInput(h("04112233445566"), batch));
    const b = diversifyAes128(master, cardDivInput(h("04112233445567"), batch));
    expect(hex(a)).not.toBe(hex(b));
    expect(() => diversifyAes128(master, new Uint8Array(15))).toThrow(TypeError);
    expect(() => diversifyAes128(master, new Uint8Array(32))).toThrow(TypeError);
  });

  it("reads UID and counter from NXP's PICCData, and rejects garbage", () => {
    const r = decryptPiccData(new Uint8Array(16), nxp.piccData);
    expect(r && hex(r.uid)).toBe("04DE5F1EACC040");
    expect(r?.readCounter).toBe(61);
    expect(decryptPiccData(new Uint8Array(16).fill(3), nxp.piccData)).toBeNull();
    expect(decryptPiccData(new Uint8Array(16), "zz")).toBeNull();
  });

  it("indexes a card by a keyed hash, never by the UID itself", () => {
    const uid = h("04DE5F1EACC040");
    const i1 = uidIndex(new Uint8Array(32).fill(1), uid);
    expect(i1).toHaveLength(32);
    expect(hex(i1)).not.toContain("04DE5F1EACC040");
    expect(hex(uidIndex(new Uint8Array(32).fill(2), uid))).not.toBe(hex(i1));
  });

  it("compares bytes in constant time", () => {
    expect(constantTimeEqual(h("0102"), h("0102"))).toBe(true);
    expect(constantTimeEqual(h("0102"), h("0103"))).toBe(false);
    expect(constantTimeEqual(h("01"), h("0102"))).toBe(false);
  });
});
