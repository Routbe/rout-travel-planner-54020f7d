/**
 * Adminwachtrij voor fysieke cadeaubonnen (gratis levering in België).
 * Digitale bonnen komen hier nooit in: die vertrekken meteen per e-mail.
 */
import { sql } from "@/lib/neon";

type Row = Record<string, unknown>;

export const FULFILMENT_STEPS = ["pending_print", "packaged", "shipped"] as const;
export type FulfilmentStatus = (typeof FULFILMENT_STEPS)[number];

export interface GiftShipmentRow {
  id: string;
  code: string;
  amount_cents: number;
  design: string;
  status: string;
  fulfilment_status: string;
  tracking_code: string | null;
  purchaser_email: string;
  recipient_name: string | null;
  ship_name: string | null;
  ship_line1: string | null;
  ship_postal_code: string | null;
  ship_city: string | null;
  ship_country: string | null;
  created_at: string;
  shipped_at: string | null;
}

/** Alle fysieke bonnen; `openOnly` verbergt wat al verzonden is. */
export async function fetchGiftShipments(openOnly: boolean): Promise<GiftShipmentRow[]> {
  try {
    // 0229: admin-only database function.
    const rows = (await sql`select public.rout_gift_shipments(${openOnly}) as g`) as Row[];
    return rows.map((r) => r["g"]) as unknown as GiftShipmentRow[];
  } catch (error) {
    console.error("[admin] cadeaubon-wachtrij kon niet worden gelezen", error);
    throw new Error("gift_shipments_unavailable");
  }
}

/** Zet één zending een stap verder; trackingcode is optioneel. */
export async function updateGiftShipment(opts: {
  giftId: string;
  status: FulfilmentStatus;
  trackingCode?: string | null;
}): Promise<{ ok: boolean; message: string }> {
  const tracking = (opts.trackingCode ?? "").trim().slice(0, 64) || null;
  const rows = (await sql`select public.rout_gift_shipment_update(${opts.giftId}, ${opts.status}, ${tracking}) as code`) as Row[];
  const code = rows[0]?.["code"];
  if (typeof code !== "string") return { ok: false, message: "Zending niet gevonden." };
  return { ok: true, message: `${code} staat nu op ${opts.status}.` };
}
