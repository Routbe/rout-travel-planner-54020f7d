import type { RefObject } from "react";
import { EnclaveError } from "@/lib/crypto-enclave/client";

/** Reads an uncontrolled field once and empties it, so the words stay out of React and the DOM. */
export function takeInput(el: HTMLInputElement | HTMLTextAreaElement | null | undefined): string {
  if (!el) return "";
  const v = el.value.trim();
  el.value = "";
  return v;
}
export const takeValue = (ref: RefObject<HTMLTextAreaElement | null>) => takeInput(ref.current);

export function ceremonyMessage(e: unknown): string {
  if (e instanceof EnclaveError) {
    if (e.code === "invalid_mnemonic") return "Deze woorden kloppen niet. Controleer elk woord en de volgorde.";
    if (e.code === "key_mismatch") return "Deze woorden horen bij een andere hoofdsleutel dan die op dit toestel.";
    if (e.code === "master_key_required") return "Dit toestel heeft al een hoofdsleutel. Typ eerst je huidige 24 herstelwoorden.";
    if (e.code === "decrypt_failed") return "Dit stuk opent je herstelkluis niet. Controleer of het bij deze kluis hoort.";
    if (e.code === "unknown_handle") return "Deze stap is verlopen. Begin opnieuw.";
    if (e.code === "enclave_unavailable") return "Je browser blokkeert de beveiligde rekenmodule.";
    return `Er ging iets mis in de beveiligde rekenmodule (${e.code}). Probeer opnieuw.`;
  }
  if (e instanceof Error && e.message === "prf_unsupported") return "Deze toegangssleutel kan je herstelkluis niet beveiligen. Voeg een nieuwere toegangssleutel toe, bijvoorbeeld die van je telefoon of computer.";
  if (e instanceof Error && /NotAllowed|abort/i.test(e.name + e.message)) return "Geannuleerd of geen toegangssleutel gevonden.";
  return e instanceof Error ? e.message : "Er ging iets mis.";
}
