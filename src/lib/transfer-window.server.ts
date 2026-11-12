/**
 * Betaaltermijn van overschrijvingen.
 *
 * Een overschrijving krijgt exact één week (7 dagen) om binnen te komen. Zolang
 * die termijn loopt blijft de scanner de openstaande betaling regelmatig
 * nakijken; pas na het verstrijken van `expires_at` wordt de betaling verlopen
 * verklaard. Zo wordt niemand geannuleerd omdat zijn bank er dagen over doet.
 */
/** Duur van het betaalvenster voor overschrijvingen. */
export const TRANSFER_WINDOW_DAYS = 7;

export interface TransferScanResult {
  scanned: number;
  expired: number;
  stillOpen: number;
}

/**
 * Eén scanronde: markeert elke openstaande overschrijving als nagekeken en zet
 * alleen betalingen waarvan het venster van 7 dagen voorbij is op `expired`.
 */
export async function runTransferWindowScan(): Promise<TransferScanResult> {
  // One database function (0229) does the whole round for the open statuses
  // (pending, awaiting_transfer): fill a missing end date, mark scanned, expire.
  const { transferWindowScan } = await import("./payments/verification-payment-store.server");
  const round = await transferWindowScan();

  const result = {
    scanned: round.scanned,
    expired: round.expired,
    stillOpen: round.scanned - round.expired,
  };
  console.info("[transfer-scan] ronde afgerond", result);
  return result;
}
