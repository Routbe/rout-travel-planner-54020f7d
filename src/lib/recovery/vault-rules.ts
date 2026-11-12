/** Pure rules for the recovery-phrase screens (Master Key words and recovery codes). */
/** The generated phrase can be confirmed only after it left the screen (copy, file or PDF) and the member ticked the box. */
export function phraseConfirmed(s: { secured: boolean; ticked: boolean }): boolean {
  return s.secured && s.ticked;
}

/** Splits a phrase into numbered words for the screen and the Emergency Kit; only 24-word phrases qualify. */
export function numberedWords(phrase: string): { n: number; word: string }[] | null {
  const words = phrase.trim().split(/\s+/).filter(Boolean);
  if (words.length !== 24) return null;
  return words.map((word, i) => ({ n: i + 1, word }));
}

/** File name for downloads, never containing the account name or any word. */
export function kitFileName(kind: "phrase" | "codes", date: Date, ext: "pdf" | "txt"): string {
  return `rout-${kind === "phrase" ? "herstelwoorden" : "herstelcodes"}-${date.toISOString().slice(0, 10)}.${ext}`;
}
