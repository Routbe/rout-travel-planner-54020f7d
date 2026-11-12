import { describe, expect, it } from "vitest";
import { deriveDek, isSealedBlob, open, seal } from "./crypto";
import { masterKeyFromMnemonic, newMasterKey } from "./recovery";
import { didJwk, didWeb, didWebDocument, newSigningKeyPair, publicJwk, signPayload, verifyPayload } from "./did";

describe("e2ee", () => {
  it("ciphertext hides PII and is bound to its AAD", async () => {
    const key = await deriveDek(crypto.getRandomValues(new Uint8Array(32)));
    const blob = await seal(key, { legalName: "Anelies De Bruin" }, "u1:pii");
    expect(blob).not.toContain("Anelies");
    expect(isSealedBlob(blob)).toBe(true);
    expect(await open(key, blob, "u1:pii")).toEqual({ legalName: "Anelies De Bruin" });
    await expect(open(key, blob, "u2:pii")).rejects.toThrow();
  });

  it("24-word phrase restores the master key", () => {
    const { key, mnemonic } = newMasterKey();
    expect(mnemonic.split(" ")).toHaveLength(24);
    expect(masterKeyFromMnemonic(mnemonic)).toEqual(key);
  });

  it("did:web doc embeds did:jwk key; signatures verify only against did:jwk", async () => {
    const kp = await newSigningKeyPair();
    const root = didJwk(await publicJwk(kp.publicKey));
    const doc = didWebDocument(didWeb("rout.be", "anelies"), root);
    expect(doc.id).toBe("did:web:rout.be:u:anelies");
    expect(doc.assertionMethod[0]).toBe(`${root}#0`);
    const jws = await signPayload(kp.privateKey, root, { name: "Anelies" });
    expect(await verifyPayload(jws, root)).toEqual({ name: "Anelies" });
    const other = didJwk(await publicJwk((await newSigningKeyPair()).publicKey));
    await expect(verifyPayload(jws, other)).rejects.toThrow();
  });
});
