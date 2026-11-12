import { createFileRoute } from "@tanstack/react-router";

/**
 * Public health probe used by the status widget in the footer.
 *
 * Deliberately privacy-clean: nothing about the caller is read, stored or
 * logged — the handler only reports whether the app can reach its Neon
 * Postgres database, how long that round-trip took, and which migration level
 * this deployment's code expects (used before applying held-back lockdowns).
 */
export const Route = createFileRoute("/api_/public/health")({
  server: {
    handlers: {
      GET: async () => {
        const started = Date.now();
        let status: "operational" | "degraded" = "operational";

        try {
          const { sql } = await import("@/lib/neon");
          await sql`SELECT 1`;
        } catch {
          status = "degraded";
        }

        const { CODE_SCHEMA_LEVEL } = await import("@/lib/schema-version");
        return Response.json(
          { status, latency_ms: Date.now() - started, schema: CODE_SCHEMA_LEVEL },
          { headers: { "cache-control": "no-store" } },
        );
      },
    },
  },
});
