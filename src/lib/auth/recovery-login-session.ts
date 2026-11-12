import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";

/**
 * Redeems a sign-in-by-recovery signature for a session. The challenge is a
 * one-time verification value (5 min) bound to one member; the signature must
 * come from that member's Master Key login key (recovery/recovery-login.ts).
 */
export function recoveryLoginSession() {
  return {
    id: "rout-recovery-login-session",
    endpoints: {
      verifyRecoveryLogin: createAuthEndpoint("/recovery/verify", { method: "POST" }, async (ctx) => {
        const body = (ctx.body ?? {}) as { challenge?: unknown; signature?: unknown };
        const { CHALLENGE_RE, verifyRecoveryLogin } = await import("@/lib/recovery/recovery-login");
        const { fromB64 } = await import("@/lib/recovery/ceremony-wire");
        const challenge = typeof body.challenge === "string" ? body.challenge : "";
        const signatureText = typeof body.signature === "string" ? body.signature : "";
        if (!CHALLENGE_RE.test(challenge) || signatureText.length > 100) throw new APIError("UNAUTHORIZED", { message: "Invalid recovery" });
        const { RECOVERY_CHALLENGE_PREFIX, ceremonyForMember, authIdForMember } = await import("@/lib/recovery/recovery-login.server");
        const v = await ctx.context.internalAdapter.consumeVerificationValue(`${RECOVERY_CHALLENGE_PREFIX}${challenge}`);
        if (!v || new Date(v.expiresAt).getTime() <= Date.now()) throw new APIError("UNAUTHORIZED", { message: "Expired recovery" });
        const memberId = v.value;
        const { withDbContext } = await import("@/lib/neon");
        const audit = async (eventType: string) => {
          const { recordSecurityEvent } = await import("@/lib/audit-log.server");
          await withDbContext({ userId: memberId, workspaceId: null }, () => recordSecurityEvent({ eventType, userId: memberId, payload: {} }));
        };
        const found = await ceremonyForMember(memberId);
        let signature: Uint8Array;
        try {
          signature = fromB64(signatureText);
        } catch {
          signature = new Uint8Array(0);
        }
        if (!found || !verifyRecoveryLogin(fromB64(found.loginKey), memberId, challenge, signature)) {
          await audit("recovery_login.failed");
          throw new APIError("UNAUTHORIZED", { message: "Invalid recovery" });
        }
        const authId = await authIdForMember(memberId);
        const user = authId ? await ctx.context.internalAdapter.findUserById(authId) : null;
        if (!user) throw new APIError("UNAUTHORIZED", { message: "Account unavailable" });
        const session = await ctx.context.internalAdapter.createSession(user.id);
        if (!session) throw new APIError("UNAUTHORIZED", { message: "Session unavailable" });
        await setSessionCookie(ctx, { user, session });
        ctx.context.setNewSession({ user, session });
        await audit("recovery_login.restored");
        return ctx.json({ ok: true });
      }),
    },
  };
}
