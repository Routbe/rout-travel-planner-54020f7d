/** Outbound webhooks: enqueue + signed delivery with exponential backoff (db/0129). */
import { sql } from "@/lib/neon";
import { MAX_ATTEMPTS, SIGNATURE_HEADER, nextRetryDelaySec, signWebhook } from "./signature";

export async function enqueueWebhookEvent(ownerUserId: string, eventType: string, payload: Record<string, unknown>) {
  await sql`select public.rout_webhook_delivery_enqueue(${ownerUserId}::uuid, ${eventType}, ${JSON.stringify(payload)}::jsonb)`;
}

/** Delivers due rows; called by the cron route. Returns counts only. */
export async function deliverDueWebhooks(limit = 50) {
  const { open } = await import("@/lib/crypto/secretbox.server");
  const rows = (await sql`select id, event_type, payload_json, attempts, url, secret_ciphertext, secret_iv, endpoint_id
      from public.rout_webhook_delivery_due(${limit}::int)`) as Record<string, unknown>[];
  let delivered = 0;
  let retried = 0;
  let failed = 0;
  for (const r of rows) {
    const attempts = Number(r["attempts"]) + 1;
    let status = 0;
    try {
      const secret = await open(String(r["secret_ciphertext"]), String(r["secret_iv"]), `webhook:${String(r["endpoint_id"])}`);
      const body = JSON.stringify({ id: r["id"], type: r["event_type"], data: r["payload_json"] });
      const res = await fetch(String(r["url"]), {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json", [SIGNATURE_HEADER]: await signWebhook(secret, body, Math.floor(Date.now() / 1000)) },
        body,
        signal: AbortSignal.timeout(10_000),
      });
      status = res.status;
    } catch {
      status = 0;
    }
    if (status >= 200 && status < 300) {
      delivered++;
      await sql`select public.rout_webhook_delivery_result(${r["id"]}::uuid, ${status}::int, 'delivered', null)`;
      continue;
    }
    const delay = nextRetryDelaySec(attempts);
    if (delay === null || attempts >= MAX_ATTEMPTS) {
      failed++;
      await sql`select public.rout_webhook_delivery_result(${r["id"]}::uuid, ${status}::int, 'failed', null)`;
    } else {
      retried++;
      await sql`select public.rout_webhook_delivery_result(${r["id"]}::uuid, ${status}::int, 'retry', ${delay}::int)`;
    }
  }
  return { delivered, retried, failed };
}
