import { sql } from "@/lib/neon";
import { hitRateLimit, sha256Hex } from "@/lib/rate-limit-db.server";

/** 6-digit code that redeems the same magic link (db/72). */

export const LOGIN_CODE_TTL_SEC = 15 * 60;

export function newLoginCode(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000;
  return String(n).padStart(6, "0");
}

const norm = (email: string) => email.trim().toLowerCase();

/** Stores the code; returns it, or null when storing failed (mail then carries only the link). */
export async function issueLoginCode(email: string, link: string): Promise<string | null> {
  try {
    const code = newLoginCode();
    const e = await sha256Hex(norm(email));
    // 0232: replaces any earlier code for this address in one database step.
    await sql`select public.rout_stateless_otp_issue('login_code', ${e}, ${await sha256Hex(`${e}:${code}`)}, ${link}, ${LOGIN_CODE_TTL_SEC})`;
    // Sign-in codes never reach the logs, not even in preview.
    return code;
  } catch (err) {
    console.error("[login-code] issue failed", (err as Error)?.message);
    return null;
  }
}

/** Single use: returns the magic link when the code matches, else a reason. */
export async function redeemLoginCode(
  email: string,
  code: string,
): Promise<{ ok: true; link: string } | { ok: false; reason: "invalid" | "rate_limited" }> {
  const clean = code.replace(/\D/g, "");
  if (clean.length !== 6 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(norm(email))) return { ok: false, reason: "invalid" };
  const limit = await hitRateLimit("login-code", norm(email), { limit: 5, windowSec: 600 });
  if (!limit.ok) return { ok: false, reason: "rate_limited" };
  const e = await sha256Hex(norm(email));
  // 0232: single use, and five wrong codes burn the code in the database itself.
  const rows = (await sql`select * from public.rout_stateless_otp_verify('login_code', ${e}, ${clean})`) as {
    outcome: string;
    payload: string | null;
  }[];
  const link = rows[0]?.outcome === "ok" ? rows[0].payload : null;
  return link ? { ok: true, link } : { ok: false, reason: "invalid" };
}
