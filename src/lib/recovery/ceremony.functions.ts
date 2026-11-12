/**
 * 2-of-3 recovery ceremony: server boundary. The server stores only RVE1
 * envelopes and can open only its own shard (server_guardian). Saving or
 * deleting needs a fresh passkey step-up; a restore hands out the stored
 * ceremony plus the opened server share, is rate limited fail-closed and
 * always e-mails the owner.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";
import { B64_RE, CEREMONY_ID_RE, CEREMONY_RESTORES_PER_HOUR, MASTER_B64_MAX, SHARD_B64_MAX, type CeremonyWire } from "./ceremony-wire";

const shard = z.string().min(64).max(SHARD_B64_MAX).regex(B64_RE);
const wireSchema = z.object({
  ceremonyId: z.string().regex(CEREMONY_ID_RE),
  keyId: z.string().min(8).max(200).regex(/^[A-Za-z0-9_-]+$/),
  sealedMaster: z.string().min(40).max(MASTER_B64_MAX).regex(B64_RE),
  shards: z.object({ device_prf: shard, paper_guardian: shard, server_guardian: shard }),
});
const credentialSchema = z.string().min(8).max(1400).regex(/^[A-Za-z0-9+/=_-]+$/);

type Row = {
  ceremony_id: string;
  key_id: string;
  sealed_master: string;
  device_shard: string;
  paper_shard: string;
  server_shard: string;
  device_credential: string;
};

async function audit(userId: string, eventType: string, payload: Record<string, unknown> = {}) {
  const { recordSecurityEvent } = await import("@/lib/audit-log.server");
  await recordSecurityEvent({ eventType, userId, payload });
}

/** Status only: whether a ceremony exists and for which Master Key. */
export const getRecoveryCeremonyStatus = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async () => {
    const { sql } = await import("@/lib/neon");
    const rows = (await sql`select * from public.rout_recovery_ceremony_status()`) as { ceremony_id: string; key_id: string; created_at: string }[];
    const r = rows[0];
    const login = r ? ((await sql`select public.rout_recovery_ceremony_login_key() is not null as ok`) as { ok: boolean }[]) : [];
    return {
      ceremony: r ? { ceremonyId: r.ceremony_id, keyId: r.key_id, createdAt: String(r.created_at), canSignIn: login[0]?.ok === true } : null,
    };
  });

/** Public key of ROUT's factor for this member; the browser seals one shard to it. */
export const getRecoveryServerKey = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { serverFactorPublicKey } = await import("./server-factor.server");
    const { toB64 } = await import("./ceremony-wire");
    return { publicKey: toB64(serverFactorPublicKey(context.userId)) };
  });

export const saveRecoveryCeremony = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) =>
    z.object({ ceremony: wireSchema, deviceCredential: credentialSchema, loginKey: z.string().regex(/^[A-Za-z0-9+/]{43}=$/) }).parse(d),
  )
  .handler(async ({ data, context }) => {
    const { requirePasskeyStepUp } = await import("@/lib/auth/step-up-guard.server");
    await requirePasskeyStepUp(context.userId, "recovery_vault");
    const { ceremonyFromWire } = await import("./ceremony-wire");
    const { isOwnServerShard, openServerShard } = await import("./server-factor.server");
    const c = data.ceremony;
    // The server shard must be sealed to ROUT's key for this member and open.
    const ceremony = ceremonyFromWire(c, context.userId);
    if (!isOwnServerShard(context.userId, ceremony.shards.server_guardian)) return { ok: false as const, error: "server_shard_mismatch" };
    try {
      openServerShard(ceremony, context.userId).fill(0);
    } catch {
      return { ok: false as const, error: "server_shard_mismatch" };
    }
    const { sql } = await import("@/lib/neon");
    await sql`select public.rout_recovery_ceremony_put(${c.ceremonyId}, ${c.keyId}, ${c.sealedMaster}, ${c.shards.device_prf}, ${c.shards.paper_guardian}, ${c.shards.server_guardian}, ${data.deviceCredential}, ${data.loginKey})`;
    const { notifyUser } = await import("@/lib/notifications.server");
    await notifyUser(context.userId, "recovery_vault_changed", { action: "saved" });
    await audit(context.userId, "recovery_ceremony.saved", { ceremonyId: c.ceremonyId });
    return { ok: true as const };
  });

export const deleteRecoveryCeremony = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { requirePasskeyStepUp } = await import("@/lib/auth/step-up-guard.server");
    await requirePasskeyStepUp(context.userId, "recovery_vault");
    const { sql } = await import("@/lib/neon");
    await sql`select public.rout_recovery_ceremony_delete()`;
    const { notifyUser } = await import("@/lib/notifications.server");
    await notifyUser(context.userId, "recovery_vault_changed", { action: "deleted" });
    await audit(context.userId, "recovery_ceremony.deleted");
    return { ok: true as const };
  });

/** Hands out the stored ceremony and ROUT's opened share for a restore on this device. */
export const beginCeremonyRestore = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { hitRateLimit } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("recoveryCeremonyRestore", context.userId, { limit: CEREMONY_RESTORES_PER_HOUR, windowSec: 3600 }, { failClosed: true });
    if (!limit.ok) {
      await audit(context.userId, "recovery_ceremony.rate_limited");
      return { ok: false as const, error: "rate_limited" as const };
    }
    const { sql } = await import("@/lib/neon");
    const rows = (await sql`select * from public.rout_recovery_ceremony_get()`) as Row[];
    const r = rows[0];
    if (!r) return { ok: false as const, error: "no_ceremony" as const };
    const wire: CeremonyWire = {
      ceremonyId: r.ceremony_id,
      keyId: r.key_id,
      sealedMaster: r.sealed_master,
      shards: { device_prf: r.device_shard, paper_guardian: r.paper_shard, server_guardian: r.server_shard },
    };
    const { ceremonyFromWire, toB64 } = await import("./ceremony-wire");
    const { openServerShard } = await import("./server-factor.server");
    const share = openServerShard(ceremonyFromWire(wire, context.userId), context.userId);
    let serverShare: string;
    try {
      serverShare = toB64(share);
    } finally {
      share.fill(0);
    }
    const { notifyUser } = await import("@/lib/notifications.server");
    await notifyUser(context.userId, "recovery_attempt", {});
    await audit(context.userId, "recovery_ceremony.restore_started", { ceremonyId: r.ceremony_id });
    return { ok: true as const, ceremony: wire, serverShare, deviceCredential: r.device_credential };
  });

export const finishCeremonyRestore = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ outcome: z.enum(["restored", "failed"]) }).parse(d))
  .handler(async ({ data, context }) => {
    await audit(context.userId, `recovery_ceremony.${data.outcome}`);
    return { ok: true as const };
  });
