import { createFileRoute } from "@tanstack/react-router";
import { verifyStripeSignature } from "@/lib/webhook-replay";

export const Route = createFileRoute("/api_/public/stripe-webhook")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env["STRIPE_WEBHOOK_SECRET"];
        if (!secret) return new Response("Webhook not configured", { status: 503 });

        const signature = request.headers.get("stripe-signature") ?? "";
        const body = await request.text();
        if (!verifyStripeSignature(body, signature, secret)) {
          return new Response("Invalid signature", { status: 401 });
        }

        let event: { id?: string; type?: string };
        try {
          event = JSON.parse(body) as { id?: string; type?: string };
        } catch {
          console.error("[stripe-webhook] onleesbare payload", { bytes: body.length });
          return new Response("Malformed payload", { status: 400 });
        }

        const eventId = event.id ?? null;
        const kind = event.type ?? null;
        const { sql } = await import("@/lib/neon");

        // Idempotency: claim het event met één atomaire insert. Een tweede
        // levering van hetzelfde id doet niets meer zolang de eerste liep of
        // slaagde; alleen een eerder gefaalde poging wordt heropend.
        if (eventId) {
          try {
            const [claim] = (await sql`
              select public.rout_webhook_event_claim(${eventId}, 'stripe', ${kind}) as claimed
            `) as { claimed: boolean }[];
            if (claim?.claimed !== true) {
              console.info("[stripe-webhook] duplicaat overgeslagen", { eventId, kind });
              return new Response("duplicate", { status: 200 });
            }
          } catch (err) {
            // Kan de claim niet weggeschreven worden, dan liever een 500 zodat
            // Stripe opnieuw levert dan het event stil laten vallen.
            console.error("[stripe-webhook] claim mislukt", {
              eventId,
              kind,
              error: err instanceof Error ? err.message : String(err),
            });
            return new Response("Idempotency store unavailable", { status: 500 });
          }
        }

        const { applyStripeEvent } = await import("@/lib/stripe-events.server");
        try {
          const result = await applyStripeEvent(event);
          if (eventId) {
            await sql`select public.rout_webhook_event_finish(${eventId}, 'done', ${result ?? null}, null, 200)`;
          }
          console.info("[stripe-webhook] verwerkt", { eventId, kind, result });
          return new Response(result, { status: 200 });
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          console.error("[stripe-webhook] verwerking mislukt", {
            eventId,
            kind,
            error: message,
            stack: err instanceof Error ? err.stack : undefined,
          });
          if (eventId) {
            await sql`select public.rout_webhook_event_finish(${eventId}, 'failed', null, ${message.slice(0, 500)}, 500)`
              .catch(() => undefined);
          }
          // 500 laat Stripe opnieuw leveren; de claim staat op 'failed' en mag heropend worden.
          return new Response("Processing failed", { status: 500 });
        }
      },
    },
  },
});
