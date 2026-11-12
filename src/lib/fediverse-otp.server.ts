import { sql } from "@/lib/neon";

/**
 * E-mailcode (6 cijfers) voor Bluesky- en Mastodon-aanmeldingen.
 *
 * Een extern account wordt nooit aan een e-mailadres gehangen op basis van
 * enkel wat de gebruiker intypt: eerst moet de code uit de mailbox kloppen.
 * Codes zijn gehasht, 10 minuten geldig, max. 3 pogingen, daarna 15 min slot.
 */

export const FEDI_PENDING_COOKIE = "rout_fedi_pending";
export const OTP_TTL_MS = 10 * 60 * 1000;
export const OTP_MAX_ATTEMPTS = 3;
export const OTP_LOCK_MS = 15 * 60 * 1000;

export type FediProvider = "bluesky" | "mastodon";

export interface PendingFediLogin {
  provider: FediProvider;
  accountId: string;
  handle: string;
  next: string;
}

export function encodePending(p: PendingFediLogin): string {
  return [p.provider, p.accountId, p.handle, p.next].join("|");
}

export function decodePending(raw: string | null): PendingFediLogin | null {
  if (!raw) return null;
  const [provider, accountId, handle, next] = raw.split("|");
  if ((provider !== "bluesky" && provider !== "mastodon") || !accountId || !handle) return null;
  return { provider, accountId, handle, next: next?.startsWith("/") && !next.startsWith("//") ? next : "/dashboard" };
}

export async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Gelijke-tijd-vergelijking van twee hex-strings. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function generateCode(): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return String(buf[0]! % 1_000_000).padStart(6, "0");
}

export class OtpError extends Error {}

/** Maakt (of vervangt) de code en verstuurt ze. Een slot blijft gerespecteerd. */
export async function issueCode(pendingRaw: string, email: string): Promise<void> {
  const key = await sha256(pendingRaw);
  const code = generateCode();
  const codeHash = await sha256(`${key}|${email}|${code}`);
  // 0232: the database keeps an active lock and resets the try counter.
  const rows = (await sql`select public.rout_stateless_otp_issue('fediverse', ${key}, ${codeHash}, ${email}, ${OTP_TTL_MS / 1000}) as r`) as {
    r: string;
  }[];
  if (rows[0]?.r === "locked") throw new OtpError("Te veel pogingen. Probeer het over 15 minuten opnieuw.");

  const { sendTransactionalEmail } = await import("@/lib/notifications.server");
  await sendTransactionalEmail({
    to: email,
    subject: `Je ROUT-code: ${code}`,
    category: "system" as never,
    html: `<p>Gebruik deze code om je ROUT-account te bevestigen:</p>
<p style="font-size:28px;letter-spacing:6px;font-weight:700;font-family:monospace">${code}</p>
<p>De code is 10 minuten geldig. Heb je dit niet aangevraagd? Negeer dan deze e-mail — er wordt niets gekoppeld.</p>`,
    tags: ["fediverse-otp"],
  });
}

/** Controleert de code. Geeft het bevestigde e-mailadres terug. */
export async function verifyCode(pendingRaw: string, code: string): Promise<string> {
  const key = await sha256(pendingRaw);
  // 0232: the code is checked, counted and locked inside the database; the
  // stored hash never comes back to the app.
  const rows = (await sql`select * from public.rout_stateless_otp_verify('fediverse', ${key}, ${code.trim()})`) as {
    outcome: string;
    payload: string | null;
    attempts_left: number | null;
  }[];
  const result = rows[0];
  switch (result?.outcome) {
    case "ok":
      if (result.payload) return result.payload;
      break;
    case "missing":
      throw new OtpError("Vraag eerst een code aan.");
    case "expired":
      throw new OtpError("Deze code is verlopen. Vraag een nieuwe aan.");
    case "locked":
      throw new OtpError("Te veel foute pogingen. Probeer het over 15 minuten opnieuw.");
    case "wrong":
      throw new OtpError(`Onjuiste code. Nog ${Math.max(0, Number(result.attempts_left ?? 0))} poging(en).`);
  }
  throw new OtpError("Vraag eerst een code aan.");
}
