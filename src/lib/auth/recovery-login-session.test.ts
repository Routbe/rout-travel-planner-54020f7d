import { ed25519 } from "@noble/curves/ed25519.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recoveryLoginMessage } from "@/lib/recovery/recovery-login";
import { toB64 } from "@/lib/recovery/ceremony-wire";

const MEMBER = "00000000-0000-4000-8000-0000000000aa";
const AUTH = "00000000-0000-4000-8000-0000000000bb";
const CHALLENGE = "c".repeat(43);
const sk = new Uint8Array(32).fill(3);
const mock = vi.hoisted(() => ({ ceremonyFor: vi.fn(), authId: vi.fn(), audit: vi.fn(), setCookie: vi.fn() }));
vi.mock("better-auth/api", () => ({
  APIError: class extends Error { constructor(public status: string, o: { message: string }) { super(o.message); } },
  createAuthEndpoint: (_p: string, _o: unknown, h: unknown) => h,
}));
vi.mock("better-auth/cookies", () => ({ setSessionCookie: mock.setCookie }));
vi.mock("@/lib/neon", () => ({ withDbContext: (_c: unknown, f: () => unknown) => f() }));
vi.mock("@/lib/audit-log.server", () => ({ recordSecurityEvent: mock.audit }));
vi.mock("@/lib/recovery/recovery-login.server", () => ({
  RECOVERY_CHALLENGE_PREFIX: "rout-recovery:", ceremonyForMember: mock.ceremonyFor, authIdForMember: mock.authId,
}));
import { recoveryLoginSession } from "./recovery-login-session";

type Handler = (ctx: unknown) => Promise<unknown>;
const handler = recoveryLoginSession().endpoints.verifyRecoveryLogin as unknown as Handler;

function ctxWith(body: unknown, stored: { value: string; expiresAt: Date } | null) {
  const internalAdapter = {
    consumeVerificationValue: vi.fn(async () => stored),
    findUserById: vi.fn(async (id: string) => ({ id })),
    createSession: vi.fn(async (id: string) => ({ token: `s-${id}` })),
  };
  return { body, json: (v: unknown) => v, context: { internalAdapter, setNewSession: vi.fn() } };
}
const valid = () => ({ value: MEMBER, expiresAt: new Date(Date.now() + 60_000) });
const sign = (member = MEMBER, challenge = CHALLENGE) => toB64(ed25519.sign(recoveryLoginMessage(member, challenge), sk));

describe("recovery sign-in redemption", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mock.ceremonyFor.mockResolvedValue({ row: {}, loginKey: toB64(ed25519.getPublicKey(sk)) });
    mock.authId.mockResolvedValue(AUTH);
  });

  it("a signature from the member's Master Key login key opens a session for that member's account", async () => {
    const ctx = ctxWith({ challenge: CHALLENGE, signature: sign() }, valid());
    await expect(handler(ctx)).resolves.toEqual({ ok: true });
    expect(ctx.context.internalAdapter.consumeVerificationValue).toHaveBeenCalledWith(`rout-recovery:${CHALLENGE}`);
    expect(ctx.context.internalAdapter.createSession).toHaveBeenCalledWith(AUTH);
    expect(mock.setCookie).toHaveBeenCalledTimes(1);
  });

  it("refuses a signature by another key and records the failure", async () => {
    const other = toB64(ed25519.sign(recoveryLoginMessage(MEMBER, CHALLENGE), new Uint8Array(32).fill(4)));
    const ctx = ctxWith({ challenge: CHALLENGE, signature: other }, valid());
    await expect(handler(ctx)).rejects.toThrow("Invalid recovery");
    expect(ctx.context.internalAdapter.createSession).not.toHaveBeenCalled();
    expect(mock.audit).toHaveBeenCalledWith(expect.objectContaining({ eventType: "recovery_login.failed", userId: MEMBER }));
  });

  it("refuses a used, unknown or expired challenge", async () => {
    await expect(handler(ctxWith({ challenge: CHALLENGE, signature: sign() }, null))).rejects.toThrow("Expired recovery");
    await expect(handler(ctxWith({ challenge: CHALLENGE, signature: sign() }, { value: MEMBER, expiresAt: new Date(Date.now() - 1) }))).rejects.toThrow("Expired recovery");
  });

  it("refuses a vault without a login key", async () => {
    mock.ceremonyFor.mockResolvedValueOnce(null);
    const ctx = ctxWith({ challenge: CHALLENGE, signature: sign() }, valid());
    await expect(handler(ctx)).rejects.toThrow("Invalid recovery");
    expect(ctx.context.internalAdapter.createSession).not.toHaveBeenCalled();
  });

  it("refuses a malformed challenge before reading anything", async () => {
    const ctx = ctxWith({ challenge: "short", signature: sign() }, valid());
    await expect(handler(ctx)).rejects.toThrow("Invalid recovery");
    expect(ctx.context.internalAdapter.consumeVerificationValue).not.toHaveBeenCalled();
  });
});
