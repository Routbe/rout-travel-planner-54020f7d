import { describe, expect, it } from "vitest";
import { claimSubject, verifySubjectClaim } from "./pairwise";

describe("pairwise partner ids", () => {
  const root = crypto.getRandomValues(new Uint8Array(32));
  it("same partner gives the same id, another partner a different id", async () => {
    const a1 = await claimSubject(root, "app.zwembad.be", "n1");
    const a2 = await claimSubject(root, "app.zwembad.be", "n2");
    const b = await claimSubject(root, "delijn.be", "n1");
    expect(a1.sub).toBe(a2.sub);
    expect(b.sub).not.toBe(a1.sub);
  });
  it("server accepts a correct claim and refuses a wrong signature, sector or nonce", async () => {
    const c = await claimSubject(root, "app.zwembad.be", "nonce-1");
    expect(await verifySubjectClaim(c, "app.zwembad.be", "nonce-1")).toBe(true);
    expect(await verifySubjectClaim(c, "delijn.be", "nonce-1")).toBe(false);
    expect(await verifySubjectClaim(c, "app.zwembad.be", "nonce-2")).toBe(false);
    const other = await claimSubject(crypto.getRandomValues(new Uint8Array(32)), "app.zwembad.be", "nonce-1");
    expect(await verifySubjectClaim({ ...c, signature: other.signature }, "app.zwembad.be", "nonce-1")).toBe(false);
  });
});
