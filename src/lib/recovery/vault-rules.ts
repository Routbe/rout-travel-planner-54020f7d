/** Pure rules for the sign-in recovery-code Emergency Kit. */

/** File name for downloads, never containing the account name or any code. */
export function kitFileName(kind: "codes", date: Date, ext: "pdf" | "txt"): string {
  return `rout-herstel${kind}-${date.toISOString().slice(0, 10)}.${ext}`;
}
