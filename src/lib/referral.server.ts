/**
 * Referral-graaf op Neon: wie nodigde wie uit, hoeveel daarvan geverifieerd
 * zijn, en welke beloning dat oplevert. Server-only.
 */
import { sql } from "@/lib/neon";
import { referralReward, type ReferralReward, type ReferralStats } from "./referral-rewards";

type Row = Record<string, unknown>;

/** Telt de referrals opnieuw uit de graaf en schrijft ze op het profiel. */
async function syncCounters(inviterId: string): Promise<ReferralStats> {
  const rows = (await sql`
    select invited, verified_invites from public.rout_referral_counts(${inviterId}::uuid)
  `) as Row[];
  const invited = Number(rows[0]?.["invited"] ?? 0);
  const verifiedInvites = Number(rows[0]?.["verified_invites"] ?? 0);

  await sql`
    update public.profiles
       set invited_count = ${invited}, verified_invites = ${verifiedInvites}, updated_at = now()
     where id = ${inviterId}
  `;

  if (invited >= 10) {
    const { awardBadges } = await import("./badge-grants.server");
    await awardBadges(inviterId, ["influencer" as never], "referral", { invited });
  }

  return { invited, verifiedInvites };
}

/**
 * Koppelt een nieuw lid aan de handle die hem uitnodigde. Eén inviter per lid,
 * geen zelf-referral; herhaalde aanroepen zijn een no-op.
 */
export async function claimReferralForUser(
  inviteeId: string,
  handle: string,
): Promise<{ ok: boolean; reason?: string }> {
  const inviterRows = (await sql`
    select id from public.profiles where lower(username) = ${handle} limit 1
  `) as Row[];
  const inviterId = inviterRows[0]?.["id"] as string | undefined;
  if (!inviterId) return { ok: false, reason: "unknown_handle" };
  if (inviterId === inviteeId) return { ok: false, reason: "self_referral" };

  // Only a brand-new account (< 24h) with a confirmed email can name an inviter.
  const fresh = (await sql`
    select 1 from public.users u
     where u.id = ${inviteeId}
       and u.created_at > now() - interval '24 hours'
       and (u.email_confirmed_at is not null
            or exists (select 1 from neon_auth."user" n where n.id::text = u.id::text and n."emailVerified" = true))
     limit 1
  `.catch(() => [])) as Row[];
  if (fresh.length === 0) return { ok: false, reason: "not_eligible" };

  // The database re-checks self-referral and the 24-hour window, and keeps one inviter per member (db/0236).
  const [claim] = (await sql`
    select public.rout_referral_claim(${inviterId}::uuid, ${inviteeId}::uuid) as claimed
  `) as Row[];
  if (claim?.["claimed"] !== true) return { ok: false, reason: "already_referred" };
  await sql`update public.profiles set referred_by = ${inviterId} where id = ${inviteeId}`;
  await syncCounters(inviterId);
  return { ok: true };
}

/** Markeert het lid als geverifieerde vriend van zijn inviter. Nooit fataal. */
export async function markInviteVerified(inviteeId: string): Promise<void> {
  try {
    const rows = (await sql`
      select inviter_id from public.rout_referral_mark_verified(${inviteeId}::uuid) as inviter_id where inviter_id is not null
    `) as Row[];
    const inviterId = rows[0]?.["inviter_id"] as string | undefined;
    if (inviterId) await syncCounters(inviterId);
  } catch (error) {
    console.error("[referral] verify propagation failed", error);
  }
}

export async function referralStatsFor(
  userId: string,
): Promise<ReferralStats & { reward: ReferralReward }> {
  let stats: ReferralStats = { invited: 0, verifiedInvites: 0 };
  try {
    const rows = (await sql`
      select invited, verified_invites from public.rout_referral_counts(${userId}::uuid)
    `) as Row[];
    stats = {
      invited: Number(rows[0]?.["invited"] ?? 0),
      verifiedInvites: Number(rows[0]?.["verified_invites"] ?? 0),
    };
  } catch (error) {
    console.error("[referral] stats unavailable", error);
  }
  return { ...stats, reward: referralReward(stats) };
}
