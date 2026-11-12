import { sql } from "@/lib/neon";

/**
 * Bootstrap van de beheerdersrol.
 *
 * De "setupmodus"-banner verschijnt zolang er geen enkele rij met rol `admin`
 * in `public.user_roles` staat. Deze helpers regelen de veilige toekenning:
 *
 *  1. de eigenaarsadressen (standaard `hallo@rout.be`, te overschrijven met
 *     `OWNER_EMAILS`) krijgen altijd de rol `admin`;
 *  2. het oudste account krijgt de rol uitsluitend na invoer van de eenmalige
 *     ADMIN_BOOTSTRAP_TOKEN via de beveiligde bootstrapactie.
 *
 * De automatische eigenaarstoekenning is idempotent; de tokenclaim is eenmalig.
 */

function ownerEmails(): string[] {
  const raw = process.env["OWNER_EMAILS"] ?? process.env["ADMIN_EMAIL"] ?? "hallo@rout.be";
  return raw
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter((value) => value.includes("@"));
}

export function isOwnerEmail(email: string | null | undefined): boolean {
  if (!email) return false;
  return ownerEmails().includes(email.trim().toLowerCase());
}

export type AdminEmailEligibility = { ok: true } | { ok: false; reason: "missing_email" | "not_admin" | "db_unreachable" };

/** Eligibility with a reason; never grants privileges. */
export async function adminEmailEligibility(email: unknown): Promise<AdminEmailEligibility> {
  if (typeof email !== "string" || !email.trim()) return { ok: false, reason: "missing_email" };
  const normalized = email.trim().toLowerCase();
  if (isOwnerEmail(normalized)) return { ok: true };
  try {
    const rows = (await sql`
      select public.rout_admin_email_eligible(${normalized}) as ok
    `) as { ok: boolean }[];
    return rows[0]?.ok === true ? { ok: true } : { ok: false, reason: "not_admin" };
  } catch (err) {
    console.error("[admin-auth] canUseAdminEmail lookup error:", err);
    return { ok: false, reason: "db_unreachable" };
  }
}

/** Eligibility only; never grants privileges. */
export async function canUseAdminEmail(email: unknown): Promise<boolean> {
  return (await adminEmailEligibility(email)).ok;
}

/** Configured owner addresses (for the diagnostic test mail only). */
export function configuredOwnerEmails(): string[] {
  return ownerEmails();
}

/** Owner auto-grant; the database also requires the e-mail on admin_owner_emails (db/0227). */
async function grantOwnerAdmin(userId: string): Promise<void> {
  const { withDbContext } = await import("@/lib/neon");
  await withDbContext({ userId, workspaceId: null }, () => sql`select public.rout_admin_grant_owner()`);
}

async function hasAnyAdmin(): Promise<boolean> {
  const rows = (await sql`select public.rout_any_admin() as ok`) as { ok: boolean }[];
  return rows[0]?.ok === true;
}

/**
 * Geeft dit account de beheerdersrol wanneer het een eigenaarsadres is.
 * Faalt nooit hard: authenticatie mag hier niet op stuklopen.
 */
export async function ensureOwnerAdmin(
  userId: string,
  email: string | null | undefined,
): Promise<void> {
  try {
    if (isOwnerEmail(email)) {
      await grantOwnerAdmin(userId);
      return;
    }
    // No automatic fallback: an arbitrary oldest account must never silently
    // become administrator.
  } catch (error) {
    console.warn("[owner-admin] could not ensure admin role", error);
  }
}

/**
 * Geeft terug of er al minstens één beheerder bestaat.
 */
export async function hasBootstrapAdmin(): Promise<boolean> {
  try {
    return await hasAnyAdmin();
  } catch (error) {
    console.warn("[owner-admin] bootstrap state failed", error);
    return false;
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

/** One-use promotion for the oldest account, invoked only from an authenticated action. */
export async function claimBootstrapAdmin(userId: string, token: string): Promise<boolean> {
  const configured = process.env["ADMIN_BOOTSTRAP_TOKEN"]?.trim();
  if (!configured || !constantTimeEqual(configured, token.trim())) return false;
  if (await hasAnyAdmin()) return false;

  const digest = Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(configured))),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  // The database re-checks: no admin yet, caller is the oldest account, digest unused.
  const { withDbContext } = await import("@/lib/neon");
  const rows = (await withDbContext({ userId, workspaceId: null }, () =>
    sql`select public.rout_admin_bootstrap_claim(${digest}) as ok`)) as { ok: boolean }[];
  return rows[0]?.ok === true;
}
