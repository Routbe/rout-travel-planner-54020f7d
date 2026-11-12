/** UI side of the recovery ceremony worker: posts messages only, no crypto. */
import type { CeremonyRequest, CeremonyResponse } from "./recovery-ceremony-core";

type Body = CeremonyRequest extends infer R ? (R extends { id: number } ? Omit<R, "id"> : never) : never;
let worker: Worker | null = null;
let seq = 0;
const waiting = new Map<number, (r: CeremonyResponse) => void>();

function get(): Worker {
  if (worker) return worker;
  worker = new Worker(new URL("./recovery-ceremony.worker.ts", import.meta.url), { type: "module", name: "rout-recovery-ceremony" });
  worker.onmessage = (e: MessageEvent<CeremonyResponse>) => { waiting.get(e.data.id)?.(e.data); waiting.delete(e.data.id); };
  return worker;
}

/** Secret byte inputs are transferred (detached on this side), never copied. */
export function ceremony(body: Body): Promise<CeremonyResponse> {
  const id = ++seq;
  const transfer = (["devicePrf", "cardSecret"] as const)
    .map((k) => (body as Record<string, unknown>)[k]).filter((v): v is Uint8Array => v instanceof Uint8Array).map((v) => v.buffer);
  return new Promise((resolve) => { waiting.set(id, resolve); get().postMessage({ ...body, id }, transfer); });
}

export function terminateCeremony() { worker?.terminate(); worker = null; waiting.clear(); }
