import { sql } from "@/lib/neon";
import { decideSlidingLimit, type RateRule } from "@/lib/rate-limit-rules";

/**
 * Database-backed limits (db/64) so every server instance shares one counter.
 * A database failure lets the request through with a warning: a broken
 * counter must never lock everybody out of sign-in.
 */

export async function sha256Hex(value: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Keyed, purpose-separated and rotated daily: an IP cannot be recovered from a
 * bucket, and buckets of different limits cannot be linked to each other.
 */
async function bucketFor(name: string, subject: string, nowMs: number): Promise<string> {
  const { rateLimitKey } = await import("@/lib/qa/privacy-keys.server");
  return `${name}:${await rateLimitKey(name, subject, nowMs)}`;
}

export async function hitRateLimit(name: string, subject: string, rule: RateRule, options: { failClosed?: boolean } = {}) {
  try {
    const bucket = await bucketFor(name, subject, Date.now());
    // 0232: one atomic database step on the database clock; it also clears the
    // bucket's older windows and now and then sweeps stale ones.
    const rows = (await sql`select * from public.rout_rate_limit_check_and_increment(${bucket}, ${rule.windowSec})`) as {
      hits: number;
      prev: number;
      now_ms: number | string;
    }[];
    const row = rows[0];
    const dbNow = Number(row?.now_ms);
    return decideSlidingLimit(Number(row?.prev ?? 0), Number(row?.hits ?? 1), rule, Number.isFinite(dbNow) ? dbNow : Date.now());
  } catch (error) {
    console.warn(`[rate-limit] ${name} skipped:`, (error as Error)?.message);
    return options.failClosed ? { ok: false, retryAfter: rule.windowSec } : { ok: true, retryAfter: 0 };
  }
}

/** Hits of one limit in the last `sinceSec` seconds, without counting a new one. */
export async function peekRateLimit(name: string, subject: string, sinceSec: number): Promise<number> {
  const bucket = await bucketFor(name, subject, Date.now());
  const rows = (await sql`select public.rout_rate_limit_peek(${bucket}, ${sinceSec}) as hits`) as { hits: number }[];
  return Number(rows[0]?.hits ?? 0);
}

export function clientIp(request: Request): string {
  return (
    request.headers.get("cf-connecting-ip")?.trim() ||
    request.headers.get("x-real-ip")?.trim() ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

/** Shared (all instances) sliding-window guard for public HTTP endpoints; null = allowed. */
export async function guardShared(request: Request, name: string, rule: RateRule): Promise<Response | null> {
  const r = await hitRateLimit(name, clientIp(request), rule);
  if (r.ok) return null;
  const { tooManyRequests } = await import("@/lib/rate-limit-rules");
  return tooManyRequests(r.retryAfter);
}
