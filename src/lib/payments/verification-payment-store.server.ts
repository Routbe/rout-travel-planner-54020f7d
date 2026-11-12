/**
 * Verification payments through the 0229 database functions.
 *
 * Member actions (open, attach, reprice, fail, expire) run in the member's own
 * request context; the database takes the caller from it. Service actions
 * (lookups, the atomic "paid" claim, status marks) are what signed webhooks and
 * cron jobs use: they need no member session and each does exactly one thing.
 * Plain reads of the member's own rows keep going through the table, which the
 * owner policy limits to the signed-in member.
 */
import { sql } from "@/lib/neon";

export type PaymentRecord = {
  id: string;
  user_id: string;
  tier: string;
  amount_cents: number;
  currency: string;
  donation_cents: number;
  donation_plan: string;
  provider: string;
  provider_ref: string | null;
  reference_code: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
};

type Row = Record<string, unknown>;
const record = (rows: Row[], key = "p"): PaymentRecord | null => (rows[0]?.[key] as PaymentRecord | null) ?? null;

export type OpenPaymentInput = {
  provider: "stripe" | "sepa" | "bunq";
  amountCents: number;
  donationCents: number;
  donationPlan: string;
  reference: string;
};

/** Member: a new pending payment for the signed-in member. */
export async function openPayment(input: OpenPaymentInput): Promise<PaymentRecord | null> {
  const rows = (await sql`
    select public.rout_vp_open(${input.provider}, ${input.amountCents}, ${input.donationCents},
                               ${input.donationPlan}, ${input.reference}) as p
  `) as Row[];
  return record(rows);
}

/** Member: store the provider reference (pi_… or bunqme:…) on their own open payment. */
export async function attachProviderRef(paymentId: string, providerRef: string): Promise<boolean> {
  const rows = (await sql`select public.rout_vp_attach_ref(${paymentId}, ${providerRef}) as ok`) as Row[];
  return rows[0]?.["ok"] === true;
}

/** Member: new amounts on their own reused, still-open Stripe payment. */
export async function repricePayment(paymentId: string, amountCents: number, donationCents: number, donationPlan: string): Promise<boolean> {
  const rows = (await sql`
    select public.rout_vp_reprice(${paymentId}, ${amountCents}, ${donationCents}, ${donationPlan}) as ok
  `) as Row[];
  return rows[0]?.["ok"] === true;
}

/** Member: close their own abandoned Stripe attempts. */
export async function expireOwnOpenStripePayments(): Promise<number> {
  const rows = (await sql`select public.rout_vp_expire_own_open_stripe() as n`) as Row[];
  return Number(rows[0]?.["n"] ?? 0);
}

/** Member: their own checkout could not start. */
export async function failOwnPayment(paymentId: string): Promise<boolean> {
  const rows = (await sql`select public.rout_vp_fail_own(${paymentId}) as ok`) as Row[];
  return rows[0]?.["ok"] === true;
}

/** Service: one payment by id. */
export async function getPayment(paymentId: string): Promise<PaymentRecord | null> {
  return record((await sql`select public.rout_vp_get(${paymentId}) as p`) as Row[]);
}

/** Service: newest payment for a bank reference code. */
export async function findPaymentByReference(reference: string): Promise<PaymentRecord | null> {
  return record((await sql`select public.rout_vp_find(${reference}, null) as p`) as Row[]);
}

/** Service: newest payment for a provider reference (Stripe intent id). */
export async function findPaymentByProviderRef(providerRef: string): Promise<PaymentRecord | null> {
  return record((await sql`select public.rout_vp_find(null, ${providerRef}) as p`) as Row[]);
}

/** Service: the atomic "paid" transition. True only for the call that flipped the row. */
export async function claimPaid(paymentId: string, providerRef: string | null): Promise<boolean> {
  const rows = (await sql`select public.rout_vp_claim_paid(${paymentId}, ${providerRef}) as ok`) as Row[];
  return rows[0]?.["ok"] === true;
}

export type MarkStatus = "processing" | "failed" | "expired" | "refunded" | "incomplete" | "pending" | "cancelled";

/** Service: a non-final outcome. A paid payment only ever moves to "refunded". */
export async function markStatus(
  paymentId: string,
  status: MarkStatus,
  providerRef: string | null = null,
): Promise<"updated" | "paid" | "not_found"> {
  const rows = (await sql`select public.rout_vp_mark(${paymentId}, ${status}, ${providerRef}) as r`) as Row[];
  return (rows[0]?.["r"] as "updated" | "paid" | "not_found" | undefined) ?? "not_found";
}

/** Service: a recurring donation stopped. */
export async function endDonation(paymentId: string): Promise<boolean> {
  const rows = (await sql`select public.rout_vp_end_donation(${paymentId}) as ok`) as Row[];
  return rows[0]?.["ok"] === true;
}

/** Service: open SEPA transfers whose expected total equals the received amount. */
export async function sepaCandidates(amountCents: number): Promise<PaymentRecord[]> {
  const rows = (await sql`select public.rout_vp_sepa_candidates(${amountCents}) as p`) as Row[];
  return rows.map((r) => r["p"] as PaymentRecord);
}

/** Service: position of a payment among all paid payments (invoice numbering). */
export async function paidSequence(at: string): Promise<number> {
  const rows = (await sql`select public.rout_vp_paid_sequence(${at}::timestamptz) as n`) as Row[];
  return Number(rows[0]?.["n"] ?? 0);
}

/** Cron: one transfer-window round. */
export async function transferWindowScan(): Promise<{ scanned: number; expired: number }> {
  const rows = (await sql`select public.rout_vp_transfer_scan() as s`) as Row[];
  const s = (rows[0]?.["s"] ?? {}) as { scanned?: number; expired?: number };
  return { scanned: Number(s.scanned ?? 0), expired: Number(s.expired ?? 0) };
}
