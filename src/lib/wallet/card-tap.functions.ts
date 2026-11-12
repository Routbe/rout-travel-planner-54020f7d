/**
 * Public ROUT Card tap check (/t). No session: the card proves itself with a
 * live NTAG 424 DNA SUN tap (sdm-tap.server.ts). Rate limited fail-closed per
 * IP; every denial looks the same and nothing about the card's owner is returned.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

export type CardTapResult = { status: "verified"; activated: boolean } | { status: "denied" } | { status: "limited" };

export const verifyCardTapFn = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ p: z.string().max(64), m: z.string().max(64) }).strict().parse(d))
  .handler(async ({ data }): Promise<CardTapResult> => {
    const { getRequest, setResponseHeader } = await import("@tanstack/react-start/server");
    setResponseHeader("cache-control", "no-store");
    const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
    const limit = await hitRateLimit("card-tap", clientIp(getRequest()), { limit: 20, windowSec: 60 }, { failClosed: true }).catch(() => ({ ok: false }));
    if (!limit.ok) return { status: "limited" };
    try {
      const { publicCardProof } = await import("@/lib/vault/sdm-tap.server");
      const state = await publicCardProof(data);
      return { status: "verified", activated: state === "active" };
    } catch {
      return { status: "denied" };
    }
  });
