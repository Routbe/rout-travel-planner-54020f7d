import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { recoveryLoginMessage, verifyRecoveryLogin } from "./recovery-login";

const member = "00000000-0000-4000-8000-0000000000e1";
const challenge = "x".repeat(43);

describe("sign-in by recovery proof", () => {
  it("accepts only a signature over this member and this challenge", () => {
    const sk = new Uint8Array(32).fill(3);
    const pk = ed25519.getPublicKey(sk);
    const sig = ed25519.sign(recoveryLoginMessage(member, challenge), sk);
    expect(verifyRecoveryLogin(pk, member, challenge, sig)).toBe(true);
    expect(verifyRecoveryLogin(pk, member, "y".repeat(43), sig)).toBe(false);
    expect(verifyRecoveryLogin(pk, "00000000-0000-4000-8000-0000000000e2", challenge, sig)).toBe(false);
    expect(verifyRecoveryLogin(ed25519.getPublicKey(new Uint8Array(32).fill(4)), member, challenge, sig)).toBe(false);
  });

  it("is domain-separated: a plain signature over the challenge is refused", () => {
    const sk = new Uint8Array(32).fill(3);
    const sig = ed25519.sign(new TextEncoder().encode(challenge), sk);
    expect(verifyRecoveryLogin(ed25519.getPublicKey(sk), member, challenge, sig)).toBe(false);
  });

  it("rejects malformed inputs without throwing", () => {
    expect(verifyRecoveryLogin(new Uint8Array(31), member, challenge, new Uint8Array(64))).toBe(false);
    expect(verifyRecoveryLogin(new Uint8Array(32), "not-a-uuid", challenge, new Uint8Array(64))).toBe(false);
    expect(verifyRecoveryLogin(new Uint8Array(32), member, "short", new Uint8Array(64))).toBe(false);
  });
});
