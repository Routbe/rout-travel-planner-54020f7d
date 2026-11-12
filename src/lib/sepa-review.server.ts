/**
 * Server-side store for the SEPA name-mismatch review queue (matcher level 2b).
 *
 * A transfer lands here when the amount matches exactly one pending payment
 * but the payer name differs from the account holder. Nothing is activated
 * until an admin approves the row.
 */
import { sql } from "@/lib/neon";

export type SepaReviewStatus = "open" | "approved" | "rejected";

export interface SepaReviewRow {
  id: string;
  payment_id: string | null;
  user_id: string | null;
  reason: string;
  status: SepaReviewStatus;
  reference: string | null;
  amount_cents: number | null;
  expected_cents: number | null;
  payer_name: string | null;
  holder_name: string | null;
  match_score: number | null;
  notes: string | null;
  decided_by: string | null;
  decided_at: string | null;
  created_at: string;
  member_email: string | null;
  member_name: string | null;
}

export interface QueueInput {
  paymentId: string | null;
  userId: string | null;
  reference: string | null;
  amountCents: number | null;
  expectedCents: number | null;
  payerName: string | null;
  holderName: string | null;
  matchScore: number | null;
  reason?: string;
  notes?: string | null;
}

/**
 * Adds one review row. Idempotent per payment: a bank that re-delivers the
 * same notification updates the existing open row instead of duplicating it.
 * Never throws — a failing queue write must not break the webhook.
 */
export async function queueSepaReview(input: QueueInput): Promise<string | null> {
  try {
    // Bank webhooks carry no member session: the queue is written by a narrow function (db/0234).
    const rows = (await sql`
      select public.rout_sepa_review_queue(${input.paymentId}::uuid, ${input.userId}::uuid,
        ${input.reason ?? "name_mismatch"}, ${input.reference}, ${input.amountCents}::int, ${input.expectedCents}::int,
        ${input.payerName}, ${input.holderName}, ${input.matchScore}::numeric, ${input.notes ?? null}) as id
    `) as Array<{ id: string | null }>;
    return rows[0]?.id ?? null;
  } catch (error) {
    console.error("[sepa-review] queue insert failed", error);
    return null;
  }
}

/** Admin list, newest first, optionally filtered by status and free text. */
export async function listSepaReviews(options: {
  status?: SepaReviewStatus | "all";
  search?: string | null;
  limit?: number;
}): Promise<SepaReviewRow[]> {
  const status = options.status ?? "open";
  const search = options.search?.trim() ? `%${options.search.trim()}%` : null;
  const limit = Math.min(Math.max(options.limit ?? 100, 1), 500);

  const rows = (await sql.query(
    `select q.*, p.email as member_email, p.display_name as member_name
       from public.sepa_review_queue q
       left join public.profiles p on p.id = q.user_id
      where ($1::text = 'all' or q.status = $1::text)
        and ($2::text is null
             or q.reference ilike $2 or q.payer_name ilike $2
             or q.holder_name ilike $2 or p.email ilike $2)
      order by q.created_at desc
      limit $3`,
    [status, search, limit],
  )) as unknown as SepaReviewRow[];

  return rows.map((row) => ({
    ...row,
    match_score: row.match_score === null ? null : Number(row.match_score),
  }));
}

/** Counters for the header chips. */
export async function countSepaReviews(): Promise<Record<SepaReviewStatus, number>> {
  const rows = (await sql`
    select status, count(*)::int as total from public.sepa_review_queue group by status
  `) as Array<{ status: SepaReviewStatus; total: number }>;
  const out: Record<SepaReviewStatus, number> = { open: 0, approved: 0, rejected: 0 };
  for (const row of rows) if (row.status in out) out[row.status] = row.total;
  return out;
}

async function loadReview(id: string): Promise<SepaReviewRow | null> {
  const rows = (await sql`
    select * from public.sepa_review_queue where id = ${id} limit 1
  `) as unknown as SepaReviewRow[];
  return rows[0] ?? null;
}

/**
 * Approve = the money really belongs to this member: settle the payment and
 * activate the account. Reject = leave the account untouched.
 */
export async function decideSepaReview(
  id: string,
  decision: "approved" | "rejected",
  adminId: string,
  notes: string | null,
): Promise<{ ok: boolean; activated: boolean; error?: string }> {
  const review = await loadReview(id);
  if (!review) return { ok: false, activated: false, error: "Review not found" };
  if (review.status !== "open") {
    return { ok: false, activated: false, error: "This review was already handled" };
  }

  let activated = false;
  if (decision === "approved" && review.payment_id) {
    const { settleSepaPayment } = await import("./sepa-matching.server");
    activated = await settleSepaPayment(review.payment_id, review.reference, review.amount_cents);
  }

  await sql`
    update public.sepa_review_queue
       set status = ${decision},
           decided_by = ${adminId},
           decided_at = now(),
           notes = coalesce(${notes}, notes)
     where id = ${id}
  `;

  try {
    const { writeAudit } = await import("./admin.server");
    await writeAudit({ adminId,
      action: decision === "approved" ? "SEPA_REVIEW_APPROVED" : "SEPA_REVIEW_REJECTED",
      targetUserId: review.user_id ?? null, targetLabel: review.reference ?? "unknown",
      notes: `Name-mismatch review ${decision}${notes ? ` — ${notes}` : ""}.` });
  } catch (error) {
    console.error("[sepa-review] audit log failed", error);
  }

  if (review.user_id && decision === "rejected") {
    try {
      const { notifyUser } = await import("./notifications.server");
      await notifyUser(review.user_id, "transfer_name_mismatch", {
        review_id: id,
        decision,
      });
    } catch (error) {
      console.error("[sepa-review] notify failed", error);
    }
  }

  return { ok: true, activated };
}
