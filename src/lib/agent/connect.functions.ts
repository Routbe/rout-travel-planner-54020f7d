import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

/**
 * Public lookup for the /connect intro: only the display name and logo of an
 * active "Login met ROUT" app — the same facts the consent screen shows.
 */
export const getConnectClient = createServerFn({ method: "GET" })
  .inputValidator((input: unknown) => z.strictObject({ clientId: z.string().trim().min(1).max(200) }).parse(input))
  .handler(async ({ data }) => {
    try {
      const { sql } = await import("@/lib/neon");
      // Public app facts through the database: no member owns this request (db/0228).
      const rows = (await sql`select public.rout_oauth_client_get(${data.clientId}) as c`) as Record<string, unknown>[];
      const row = rows[0]?.["c"] as Record<string, unknown> | null | undefined;
      if (!row || row["status"] !== "active") return null;
      return {
        name: typeof row["name"] === "string" ? row["name"] : null,
        logoUrl: typeof row["logo_url"] === "string" && /^https:\/\//.test(row["logo_url"]) ? row["logo_url"] : null,
      };
    } catch (error) {
      console.warn("[connect:client]", (error as Error)?.message);
      return null;
    }
  });
