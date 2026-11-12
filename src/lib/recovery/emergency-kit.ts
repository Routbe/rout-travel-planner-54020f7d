/**
 * Emergency Kit PDF for one-time sign-in recovery codes, drawn 100% in the
 * browser with jsPDF. Nothing is uploaded; the caller hands the Blob to a download.
 * Browser-only: import dynamically from an event handler.
 */
export type KitInput = {
  kind: "codes";
  /** The one-time sign-in recovery codes. */
  items: string[];
  account?: string | null;
  createdAt?: Date;
};

export async function buildEmergencyKitPdf(input: KitInput): Promise<Blob> {
  const { jsPDF } = await import("jspdf");
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const date = input.createdAt ?? new Date();
  const W = 210;
  const M = 18;
  // PDF artwork, not app UI: fixed print colours.
  const ink = [17, 17, 17] as const;
  const soft = [110, 110, 110] as const;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(...ink);
  doc.text("ROUT Noodkit", M, 26);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(...soft);
  doc.text("Je eenmalige herstelcodes voor tweestapsverificatie", M, 34);
  doc.text(`Gemaakt op ${date.toLocaleDateString("nl-BE")}${input.account ? `  -  ${input.account}` : ""}`, M, 40);

  // Warning box
  doc.setDrawColor(...ink);
  doc.setLineWidth(0.4);
  doc.roundedRect(M, 46, W - 2 * M, 22, 2, 2);
  doc.setTextColor(...ink);
  doc.setFontSize(10);
  doc.text(doc.splitTextToSize(
    "Elke code werkt één keer om in te loggen als je je toestel kwijt bent. ROUT vraagt er nooit naar. Bewaar dit blad offline op een veilige plek.",
    W - 2 * M - 8,
  ), M + 4, 53);

  let y = 80;
  {
    doc.setFont("courier", "normal");
    doc.setFontSize(13);
    input.items.forEach((code, i) => {
      const col = i % 2;
      const row = Math.floor(i / 2);
      doc.setTextColor(...soft);
      doc.text(`${String(i + 1).padStart(2, "0")}`, M + col * 80, y + row * 10);
      doc.setTextColor(...ink);
      doc.text(code, M + 10 + col * 80, y + row * 10);
      doc.text("[ ] gebruikt", M + 52 + col * 80, y + row * 10);
    });
    y += Math.ceil(input.items.length / 2) * 10 + 8;
  }

  // Fill-in fields
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(...ink);
  doc.text("Zelf invullen", M, y);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  const fields = ["Bewaard op (plaats):", "Wie weet waar dit ligt:", "Datum laatste controle:"];
  fields.forEach((f, i) => {
    const yy = y + 9 + i * 10;
    doc.text(f, M, yy);
    doc.setDrawColor(160, 160, 160);
    doc.line(M + 48, yy + 1, W - M, yy + 1);
  });
  y += 9 + fields.length * 10 + 6;

  doc.setFont("helvetica", "bold");
  doc.text("Zo gebruik je dit", M, y);
  doc.setFont("helvetica", "normal");
  const steps = ["1. Log in op rout.be met je e-mail en wachtwoord of passkey.", "2. Kies bij de tweede stap Herstelcode gebruiken.", "3. Vink de gebruikte code hierboven af.", "4. Maak nieuwe codes als je er nog maar een paar over hebt."];
  steps.forEach((s, i) => doc.text(s, M, y + 7 + i * 6));

  doc.setFontSize(8);
  doc.setTextColor(...soft);
  doc.text("Gemaakt in je browser. Dit bestand is nooit naar ROUT gestuurd.", M, 287);
  return doc.output("blob");
}

/** Triggers a local download of a Blob. */
export function downloadBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
