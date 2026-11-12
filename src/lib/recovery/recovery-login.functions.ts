/**
 * /recovery: sign-in for a member who is locked out, with 2 of 3 factors.
 *
 *   1. startRecoveryLogin   e-mail in; a 6-digit code goes to the account's
 *                           address. Always the same answer (no enumeration).
 *   2. openRecoveryLogin    code in; ROUT releases the stored ceremony, its own
 *                           opened share and a one-time challenge (5 min).
 *   3. the crypto worker rebuilds the Master Key from two factors, signs the
 *      challenge with the Master Key's login key and wipes everything; the
 *      signature is redeemed at /api/auth/recovery/verify for a session.
 *
 * These functions are public by design: every step is rate limited fail-closed,
 * and nothing is released before the e-mail code is proven.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import type { CeremonyWire } from "./ceremony-wire";

const emailSchema = z.string().trim().toLowerCase().max(254).regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);

async function ipLimit(name: string, limit: number) {
  const { getRequest } = await import("@tanstack/react-start/server");
  const request = getRequest();
  const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
  return { request, ok: (await hitRateLimit(name, clientIp(request), { limit, windowSec: 3600 }, { failClosed: true })).ok };
}

export const startRecoveryLogin = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ email: emailSchema }).parse(d))
  .handler(async ({ data }) => {
    const { request, ok } = await ipLimit("recoveryLoginStart", 10);
    if (!ok) return { ok: false as const, error: "rate_limited" as const };
    const { hitRateLimit } = await import("@/lib/rate-limit-db.server");
    if (!(await hitRateLimit("recoveryLoginEmail", data.email, { limit: 5, windowSec: 3600 }, { failClosed: true })).ok) {
      return { ok: false as const, error: "rate_limited" as const };
    }
    try {
      const { resolveMemberByEmail, ceremonyForMember } = await import("./recovery-login.server");
      const memberId = await resolveMemberByEmail(data.email);
      if (memberId && (await ceremonyForMember(memberId))) {
        const { withDbContext } = await import("@/lib/neon");
        const { issueSecurityCode } = await import("@/lib/security-code.server");
        await withDbContext({ userId: memberId, workspaceId: null }, () => issueSecurityCode(memberId, "recovery", request));
      }
    } catch (e) {
      console.error("[recovery-login] start failed", e instanceof Error ? e.message : e);
    }
    // Same answer whether or not the address has an account or a recovery vault.
    return { ok: true as const };
  });

export const openRecoveryLogin = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ email: emailSchema, code: z.string().trim().regex(/^\d{6}$/) }).parse(d))
  .handler(async ({ data }) => {
    const { request, ok } = await ipLimit("recoveryLoginOpen", 20);
    if (!ok) return { ok: false as const, error: "rate_limited" as const };
    const { resolveMemberByEmail, ceremonyForMember, newChallenge, RECOVERY_CHALLENGE_PREFIX, RECOVERY_CHALLENGE_TTL_MS } = await import("./recovery-login.server");
    const memberId = await resolveMemberByEmail(data.email);
    if (!memberId) return { ok: false as const, error: "invalid_code" as const };
    const { withDbContext } = await import("@/lib/neon");
    const { consumeSecurityCode } = await import("@/lib/security-code.server");
    const valid = await withDbContext({ userId: memberId, workspaceId: null }, () => consumeSecurityCode(memberId, "recovery", data.code));
    if (!valid) return { ok: false as const, error: "invalid_code" as const };
    const found = await ceremonyForMember(memberId);
    if (!found) return { ok: false as const, error: "no_ceremony" as const };

    const r = found.row;
    const wire: CeremonyWire = {
      ceremonyId: r.ceremony_id,
      keyId: r.key_id,
      sealedMaster: r.sealed_master,
      shards: { device_prf: r.device_shard, paper_guardian: r.paper_shard, server_guardian: r.server_shard },
    };
    const { ceremonyFromWire, toB64 } = await import("./ceremony-wire");
    const { openServerShard } = await import("./server-factor.server");
    const share = openServerShard(ceremonyFromWire(wire, memberId), memberId);
    let serverShare: string;
    try {
      serverShare = toB64(share);
    } finally {
      share.fill(0);
    }
    const challenge = newChallenge();
    const { createRoutAuth } = await import("@/lib/better-auth.server");
    const auth = await createRoutAuth(request).$context;
    await auth.internalAdapter.createVerificationValue({
      identifier: `${RECOVERY_CHALLENGE_PREFIX}${challenge}`,
      value: memberId,
      expiresAt: new Date(Date.now() + RECOVERY_CHALLENGE_TTL_MS),
    });
    await withDbContext({ userId: memberId, workspaceId: null }, async () => {
      const { notifyUser } = await import("@/lib/notifications.server");
      await notifyUser(memberId, "recovery_attempt", {});
      const { recordSecurityEvent } = await import("@/lib/audit-log.server");
      await recordSecurityEvent({ eventType: "recovery_login.started", userId: memberId, payload: { ceremonyId: r.ceremony_id } });
    });
    return { ok: true as const, memberId, ceremony: wire, serverShare, deviceCredential: r.device_credential, challenge };
  });
