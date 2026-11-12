/**
 * Member-facing security events (security_events). Written only through the
 * validating database function (db/0234); the table itself is closed to the app.
 */
import { sql } from "./neon";

export interface SecurityEventInput {
  userId: string | null;
  kind: string;
  severity: "info" | "warning" | "error" | "critical";
  message: string;
  details?: Record<string, unknown>;
}

export async function writeSecurityEvent(e: SecurityEventInput): Promise<void> {
  await sql`select public.rout_security_event_write(${e.userId}::uuid, ${e.kind}, ${e.severity}, ${e.message},
    ${JSON.stringify(e.details ?? {})}::jsonb)`;
}
