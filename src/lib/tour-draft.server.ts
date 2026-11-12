import { sql } from "@/lib/neon";
import { parseTourDraft, type TourDraft } from "@/lib/tour-draft";

const normalizeEmail = (email: string) => email.trim().toLowerCase();

export async function upsertTourDraft(email: string, draft: TourDraft) {
  const address = normalizeEmail(email);
  if (!address.includes("@")) return { ok: false as const, reason: "invalid_email" };
  await sql`select public.rout_onboarding_draft_put(${address}, ${JSON.stringify(draft)}::jsonb)`;
  return { ok: true as const };
}

export async function readTourDraft(email: string): Promise<TourDraft | null> {
  const address = normalizeEmail(email);
  if (!address) return null;
  const rows = (await sql`
    select public.rout_onboarding_draft_get(${address}) as draft
  `) as { draft: unknown }[];
  const row = rows[0];
  return row && row.draft != null ? parseTourDraft(row.draft) : null;
}

export async function deleteTourDraft(email: string) {
  await sql`select public.rout_onboarding_draft_drop(${normalizeEmail(email)})`;
}

/**
 * Anonieme concepten (nog geen e-mailadres): de rondleiding bewaart ze op een
 * willekeurig token. De sleutelkolom blijft `email`, met het voorvoegsel
 * `token:` zodat er geen extra migratie nodig is.
 */
const tokenKey = (token: string) => `token:${token.trim().slice(0, 80)}`;

export async function upsertTourDraftByToken(token: string, draft: TourDraft) {
  const key = tokenKey(token);
  if (key.length < 12) return { ok: false as const, reason: "invalid_token" };
  await sql`select public.rout_onboarding_draft_put(${key}, ${JSON.stringify(draft)}::jsonb)`;
  return { ok: true as const };
}

export async function readTourDraftByToken(token: string): Promise<TourDraft | null> {
  const rows = (await sql`
    select public.rout_onboarding_draft_get(${tokenKey(token)}) as draft
  `) as { draft: unknown }[];
  const row = rows[0];
  return row && row.draft != null ? parseTourDraft(row.draft) : null;
}

export async function deleteTourDraftByToken(token: string) {
  await sql`select public.rout_onboarding_draft_drop(${tokenKey(token)})`;
}
