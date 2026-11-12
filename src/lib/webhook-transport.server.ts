import { sql } from "./neon";

/** Only transport metadata: never endpoint URLs, request bodies or credentials. */
export async function recordOutboundWebhook(source: string, kind: string, status: number | null) {
  try {
    const id = `outbound:${crypto.randomUUID()}`;
    await sql`select public.rout_webhook_event_record(${id}, ${source}, ${kind}, 'outbound', ${status},
      ${status != null && status >= 200 && status < 300 ? "done" : "failed"})`;
  } catch (error) {
    console.error("[webhook-transport] recording failed", error);
  }
}