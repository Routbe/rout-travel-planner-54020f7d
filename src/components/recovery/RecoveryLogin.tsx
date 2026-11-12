import { useEffect, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Check, FileText, Fingerprint, KeyRound, Mail, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { enclave } from "@/lib/crypto-enclave/client";
import type { RecoveryCeremony } from "@/lib/crypto-enclave/recovery-mpc";
import { ceremonyFromWire, fromB64, toB64, wordCount } from "@/lib/recovery/ceremony-wire";
import { openRecoveryLogin, startRecoveryLogin } from "@/lib/recovery/recovery-login.functions";
import { ceremonyMessage, takeValue } from "./ceremony-ui";

type Step = "email" | "code" | "factors";
type Combo = "rout_paper" | "rout_passkey" | "passkey_paper";
/** What ROUT released after the e-mail code. Kept in a ref, never in state; the share is zero-filled on leave. */
type Opened = { memberId: string; ceremony: RecoveryCeremony; keyId: string; serverShare: Uint8Array; deviceCredential: string; challenge: string };

const STEPS: { id: Step; label: string }[] = [
  { id: "email", label: "E-mail" },
  { id: "code", label: "Code" },
  { id: "factors", label: "Twee stukken" },
];
const COMBOS: { id: Combo; title: string; detail: string; icons: [typeof Server, typeof Server] }[] = [
  { id: "rout_paper", title: "ROUT + mijn papieren woorden", detail: "Voor als je je toegangssleutel kwijt bent.", icons: [Server, FileText] },
  { id: "rout_passkey", title: "ROUT + mijn toegangssleutel", detail: "Voor als je je papier niet bij de hand hebt.", icons: [Server, Fingerprint] },
  { id: "passkey_paper", title: "Mijn toegangssleutel + papieren woorden", detail: "Zonder het stuk van ROUT.", icons: [Fingerprint, FileText] },
];

/**
 * /recovery: sign in when locked out. ROUT's own piece is released only after
 * the e-mail code; the crypto worker rebuilds the Master Key from two pieces,
 * signs ROUT's one-time challenge and wipes the pieces and the key. Typed words
 * stay in an uncontrolled field and are cleared the moment they are read.
 */
export function RecoveryLogin() {
  const start = useServerFn(startRecoveryLogin);
  const open = useServerFn(openRecoveryLogin);
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [combo, setCombo] = useState<Combo>("rout_paper");
  const [paperCount, setPaperCount] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [signedIn, setSignedIn] = useState(false);
  const opened = useRef<Opened | null>(null);
  const paperField = useRef<HTMLTextAreaElement>(null);

  const forget = () => {
    opened.current?.serverShare.fill(0);
    opened.current = null;
    takeValue(paperField);
    setPaperCount(0);
  };
  useEffect(() => forget, []);

  const restart = (why: string | null) => { forget(); setCode(""); setStep("email"); setError(why); };

  async function sendCode(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const r = await start({ data: { email } });
      if (!r.ok) setError("Te veel pogingen. Probeer het over een uur opnieuw.");
      else setStep("code");
    } catch { setError("Dit e-mailadres klopt niet."); } finally { setBusy(false); }
  }

  async function checkCode(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const r = await open({ data: { email, code } });
      setCode("");
      if (!r.ok) {
        setError(r.error === "rate_limited" ? "Te veel pogingen. Probeer het over een uur opnieuw."
          : r.error === "no_ceremony" ? "Voor dit account is nog geen herstelkluis ingesteld waarmee je kunt inloggen."
          : "Deze code klopt niet of is verlopen.");
        return;
      }
      opened.current = {
        memberId: r.memberId, ceremony: ceremonyFromWire(r.ceremony, r.memberId), keyId: r.ceremony.keyId,
        serverShare: fromB64(r.serverShare), deviceCredential: r.deviceCredential, challenge: r.challenge,
      };
      setStep("factors");
    } catch { setError("Deze code klopt niet of is verlopen."); } finally { setBusy(false); }
  }

  async function recover(e: React.FormEvent) {
    e.preventDefault();
    const o = opened.current;
    if (!o) return restart("Deze stap is verlopen. Begin opnieuw.");
    setBusy(true); setError(null);
    const usesPaper = combo !== "rout_passkey";
    const usesPasskey = combo !== "rout_paper";
    try {
      const paperWords = usesPaper ? takeValue(paperField) : undefined;
      setPaperCount(0);
      // A copy travels (transferred, so it leaves this thread); the original is wiped in forget().
      const serverShare = combo === "passkey_paper" ? undefined : o.serverShare.slice();
      const call = (prf?: Uint8Array) =>
        enclave.ceremony.recoverLogin({ userId: o.memberId, ceremony: o.ceremony, keyId: o.keyId, challenge: o.challenge, prf, paperWords, serverShare });
      let result: { signature: Uint8Array };
      if (usesPasskey) {
        const { withPasskeyPrf } = await import("@/lib/recovery/passkey-prf");
        result = await withPasskeyPrf("ceremony", (prf) => call(prf), o.deviceCredential);
      } else {
        result = await call();
      }
      const res = await fetch("/api/auth/recovery/verify", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ challenge: o.challenge, signature: toB64(result.signature) }),
      });
      if (!res.ok) return restart("Deze herstelpoging is verlopen. Begin opnieuw.");
      forget();
      setSignedIn(true);
      window.location.assign("/auth/continue");
    } catch (err) {
      setError(ceremonyMessage(err));
    } finally { setBusy(false); }
  }

  const current = STEPS.findIndex((s) => s.id === step);
  const needsPaper = combo !== "rout_passkey";

  return (
    <main className="mx-auto max-w-md space-y-6 px-5 py-14">
      <header className="space-y-2">
        <p className="flex items-center gap-2 text-sm text-muted-foreground"><KeyRound className="size-4" /> Herstelkluis · 2 van 3</p>
        <h1 className="text-2xl font-semibold">Inloggen met herstel</h1>
        <p className="text-sm text-muted-foreground">Buitengesloten? Met 2 van je 3 stukken krijg je je account en je hoofdsleutel terug. Eén stuk alleen opent niets.</p>
      </header>

      <ol className="grid grid-cols-3 gap-2" aria-label="Stappen">
        {STEPS.map((s, i) => (
          <li key={s.id} aria-current={i === current ? "step" : undefined} className="min-w-0 space-y-1">
            <div className={`h-1 rounded-full ${i <= current ? "bg-primary" : "bg-muted"}`} />
            <p className={`flex min-w-0 items-center gap-1 text-xs ${i === current ? "font-medium text-foreground" : "text-muted-foreground"}`}>
              {i < current && <Check className="size-3 shrink-0" />}<span className="truncate">{s.label}</span>
            </p>
          </li>
        ))}
      </ol>

      <section className="space-y-4 rounded-2xl border border-border bg-card p-4 sm:p-5">
        {step === "email" && (
          <form className="space-y-3" onSubmit={(e) => void sendCode(e)}>
            <label htmlFor="recovery-email" className="text-sm font-medium">E-mailadres van je account</label>
            <Input id="recovery-email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
            <p className="text-xs text-muted-foreground">ROUT stuurt een code naar dit adres. Dat bewijst het stuk dat ROUT voor je bewaart.</p>
            <Button type="submit" className="w-full" disabled={busy || !email.includes("@")}><Mail /> Code sturen</Button>
          </form>
        )}

        {step === "code" && (
          <form className="space-y-3" onSubmit={(e) => void checkCode(e)}>
            <label htmlFor="recovery-code" className="text-sm font-medium">Code uit je e-mail</label>
            <Input id="recovery-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} className="font-mono tracking-widest" />
            <p className="text-xs text-muted-foreground">Heeft dit adres een account met een herstelkluis, dan is de code onderweg. Hij is 10 minuten geldig.</p>
            <div className="flex flex-col gap-2 sm:flex-row">
              <Button type="submit" disabled={busy || code.length !== 6}><Check /> Verder</Button>
              <Button type="button" variant="ghost" onClick={() => restart(null)}>Ander adres</Button>
            </div>
          </form>
        )}

        {step === "factors" && (
          <form className="space-y-4" onSubmit={(e) => void recover(e)}>
            <fieldset className="space-y-2">
              <legend className="mb-2 text-sm font-medium">Welke twee stukken gebruik je?</legend>
              {COMBOS.map((c) => {
                const [A, B] = c.icons;
                return (
                  <label key={c.id} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 text-sm ${combo === c.id ? "border-primary bg-background" : "border-border"}`}>
                    <input type="radio" name="recovery-combo" value={c.id} checked={combo === c.id} onChange={() => setCombo(c.id)} className="mt-1" />
                    <span className="space-y-0.5">
                      <span className="flex items-center gap-1.5 font-medium"><A className="size-4" /><B className="size-4" /> {c.title}</span>
                      <span className="block text-xs text-muted-foreground">{c.detail}</span>
                    </span>
                  </label>
                );
              })}
            </fieldset>
            {needsPaper && (
              <div className="space-y-2">
                <label htmlFor="recovery-paper-words" className="text-sm font-medium">Je 24 papieren woorden</label>
                <Textarea id="recovery-paper-words" ref={paperField} defaultValue="" onChange={(e) => setPaperCount(wordCount(e.target.value))} rows={3} autoComplete="off" autoCorrect="off" autoCapitalize="none" spellCheck={false} className="font-mono" placeholder="woord1 woord2 woord3 …" />
              </div>
            )}
            <Button type="submit" className="w-full" disabled={busy || signedIn || (needsPaper && paperCount !== 24)}>
              {combo === "rout_paper" ? <KeyRound /> : <Fingerprint />} {combo === "rout_paper" ? "Herstellen en inloggen" : "Bevestigen met toegangssleutel"}
            </Button>
            <p className="text-xs text-muted-foreground">Alles gebeurt in de beveiligde rekenmodule van je browser. Na het inloggen worden de stukken en de sleutel meteen gewist. Je krijgt van elke poging een e-mail.</p>
          </form>
        )}

        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        {signedIn && <p role="status" className="text-sm">Hersteld. Je wordt ingelogd…</p>}
      </section>
    </main>
  );
}
