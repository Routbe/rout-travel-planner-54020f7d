// Master Recovery Key: 24-word BIP39 mnemonic. Splitting it is the 2-of-3 ceremony in crypto-enclave/recovery-mpc.ts.
import { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { wipe } from "@/lib/crypto/wipe";

export function newMasterKey(): { key: Uint8Array; mnemonic: string } {
  const key = crypto.getRandomValues(new Uint8Array(32)); // 256 bits → 24 words
  try {
    return { key, mnemonic: entropyToMnemonic(key, wordlist) };
  } catch (error) {
    wipe(key);
    throw error;
  }
}

export function masterKeyFromMnemonic(mnemonic: string): Uint8Array {
  const m = mnemonic.trim().toLowerCase().split(/\s+/).join(" ");
  try {
    return mnemonicToEntropy(m, wordlist); // validates once, without a discarded extra entropy buffer
  } catch {
    throw new Error("Invalid recovery phrase");
  }
}
