/// <reference lib="webworker" />
/**
 * 2-of-3 recovery ceremony worker: Shamir split/combine of the ceremony key and
 * the Master Key exist only in this worker's memory. No network, no fallback.
 */
import { handleCeremony, type CeremonyRequest } from "./recovery-ceremony-core";

declare const self: DedicatedWorkerGlobalScope;
let queue = Promise.resolve();
self.onmessage = (event: MessageEvent<CeremonyRequest>) => {
  queue = queue.then(async () => self.postMessage(await handleCeremony(event.data)));
};
