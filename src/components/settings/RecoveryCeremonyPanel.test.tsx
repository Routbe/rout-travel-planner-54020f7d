import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const WORDS = Array.from({ length: 24 }, (_, i) => `paperword${i + 1}`);
const mock = vi.hoisted(() => ({
  status: vi.fn(), serverKey: vi.fn(), save: vi.fn(), deviceStatus: vi.fn(),
  begin: vi.fn(), checkWords: vi.fn(), sealDevice: vi.fn(), commit: vi.fn(), discard: vi.fn(async () => null),
  prf: vi.fn(),
}));
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@/hooks/useAuth", () => ({ useAuth: () => ({ user: { id: "00000000-0000-4000-8000-0000000000aa" } }) }));
vi.mock("@/components/auth/StepUpDialog", () => ({ withStepUp: (fn: () => unknown) => fn(), requestStepUp: vi.fn(async () => true) }));
vi.mock("@/lib/auth/step-up.functions", () => ({ refreshSessionFreshness: vi.fn() }));
vi.mock("@/lib/webauthn.functions", () => ({ addPasskey: vi.fn(async () => ({ ok: true })) }));
vi.mock("@/lib/recovery/passkey-prf", () => ({ withPasskeyPrf: mock.prf }));
vi.mock("@/lib/recovery/ceremony.functions", () => ({
  getRecoveryCeremonyStatus: mock.status, getRecoveryServerKey: mock.serverKey, saveRecoveryCeremony: mock.save,
  deleteRecoveryCeremony: vi.fn(), beginCeremonyRestore: vi.fn(), finishCeremonyRestore: vi.fn(),
}));
vi.mock("@/lib/crypto-enclave/client", async (original) => ({
  ...await original<typeof import("@/lib/crypto-enclave/client")>(),
  enclave: {
    deviceKey: { status: mock.deviceStatus },
    ceremony: { begin: mock.begin, checkWords: mock.checkWords, sealDevice: mock.sealDevice, commit: mock.commit, discard: mock.discard },
  },
}));
import { RecoveryCeremonyPanel } from "./RecoveryCeremonyPanel";

describe("2-of-3 recovery wizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mock.status.mockResolvedValue({ ceremony: null });
    mock.deviceStatus.mockResolvedValue(null);
    mock.serverKey.mockResolvedValue({ publicKey: "AAAA" });
    mock.begin.mockResolvedValue({ handle: "h1", paperWords: WORDS.join(" "), checkPositions: [3, 11, 20], keyId: "key-1", fresh: true });
    mock.checkWords.mockImplementation(async (_h: string, answers: { position: number; word: string }[]) => ({ ok: answers.every((a) => a.word === WORDS[a.position - 1]) }));
    mock.sealDevice.mockResolvedValue({
      ceremony: { version: 1, ceremonyId: "0".repeat(32), memberId: "m", threshold: 2, sealedMaster: new Uint8Array(60), shards: { device_prf: new Uint8Array(80), paper_guardian: new Uint8Array(80), server_guardian: new Uint8Array(80) } },
      keyId: "key-1",
      loginKey: new Uint8Array(32).fill(9),
    });
    mock.prf.mockImplementation(async (_purpose: string, consume: (o: Uint8Array, c: string) => Promise<unknown>) => consume(new Uint8Array(32), "credential-1"));
    mock.save.mockResolvedValue({ ok: true });
    mock.commit.mockResolvedValue({ keyId: "key-1" });
  });
  afterEach(cleanup);

  const fillCheck = (words: Record<number, string>) => {
    for (const [p, w] of Object.entries(words)) fireEvent.change(screen.getByLabelText(`Woord ${p}`), { target: { value: w } });
  };

  it("shows the 24 words, drops them on confirmation, and demands 3 correct words before the passkey", async () => {
    render(<RecoveryCeremonyPanel />);
    fireEvent.click(await screen.findByRole("button", { name: /Herstelkluis instellen/ }));
    fireEvent.click(screen.getByRole("button", { name: /Beginnen/ }));
    expect(await screen.findByText("paperword24")).toBeInTheDocument();
    const next = screen.getByRole("button", { name: "Verder" });
    expect(next).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(next);

    // Words are gone from the screen as soon as the member confirms.
    expect(screen.queryByText("paperword24")).toBeNull();
    expect(document.body.textContent).not.toMatch(/paperword/);
    expect(screen.queryByRole("button", { name: /Bevestigen met toegangssleutel/ })).toBeNull();

    // Exactly the three asked positions; the button waits until all are filled.
    expect(screen.getByLabelText("Woord 3")).toBeInTheDocument();
    expect(screen.getByLabelText("Woord 11")).toBeInTheDocument();
    expect(screen.getByLabelText("Woord 20")).toBeInTheDocument();
    const check = screen.getByRole("button", { name: /Controleren/ });
    fillCheck({ 3: "paperword3", 11: "paperword11" });
    expect(check).toBeDisabled();

    // A wrong word blocks the passkey step and the typed words are cleared from the fields.
    fillCheck({ 20: "wrong" });
    fireEvent.click(check);
    expect(await screen.findByRole("alert")).toHaveTextContent("Niet alle woorden kloppen");
    expect((screen.getByLabelText("Woord 3") as HTMLInputElement).value).toBe("");
    expect(mock.sealDevice).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /Bevestigen met toegangssleutel/ })).toBeNull();

    fillCheck({ 3: "paperword3", 11: "paperword11", 20: "paperword20" });
    fireEvent.click(screen.getByRole("button", { name: /Controleren/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Bevestigen met toegangssleutel/ }));
    await screen.findByText(/Je herstelkluis is actief/);
    expect(mock.checkWords).toHaveBeenLastCalledWith("h1", [
      { position: 3, word: "paperword3" }, { position: 11, word: "paperword11" }, { position: 20, word: "paperword20" },
    ]);
    expect(mock.save).toHaveBeenCalledTimes(1);
    expect(mock.save.mock.calls[0][0].data.deviceCredential).toBe("credential-1");
    expect(mock.commit).toHaveBeenCalledWith("h1", "00000000-0000-4000-8000-0000000000aa");
  });

  it("a failed save can be retried without sealing the passkey share a second time", async () => {
    mock.save.mockRejectedValueOnce(new Error("Bevestiging geannuleerd."));
    render(<RecoveryCeremonyPanel />);
    fireEvent.click(await screen.findByRole("button", { name: /Herstelkluis instellen/ }));
    fireEvent.click(screen.getByRole("button", { name: /Beginnen/ }));
    await screen.findByText("paperword1");
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Verder" }));
    fillCheck({ 3: "paperword3", 11: "paperword11", 20: "paperword20" });
    fireEvent.click(screen.getByRole("button", { name: /Controleren/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Bevestigen met toegangssleutel/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Bevestiging geannuleerd.");
    fireEvent.click(screen.getByRole("button", { name: /Bevestigen met toegangssleutel/ }));
    await screen.findByText(/Je herstelkluis is actief/);
    expect(mock.sealDevice).toHaveBeenCalledTimes(1);
    expect(mock.prf).toHaveBeenCalledTimes(1);
    expect(mock.save).toHaveBeenCalledTimes(2);
    expect(mock.commit).toHaveBeenCalledTimes(1);
  });

  it("asks for the existing Master Key words on a device that has one, and clears the field", async () => {
    mock.deviceStatus.mockResolvedValue({ keyId: "key-1" });
    render(<RecoveryCeremonyPanel />);
    fireEvent.click(await screen.findByRole("button", { name: /Herstelkluis instellen/ }));
    await waitFor(() => expect(screen.getByLabelText("Je huidige 24 herstelwoorden")).toBeInTheDocument());
    const field = screen.getByLabelText("Je huidige 24 herstelwoorden") as HTMLTextAreaElement;
    const begin = screen.getByRole("button", { name: /Beginnen/ });
    fireEvent.change(field, { target: { value: "one two three" } });
    expect(begin).toBeDisabled();
    const master = Array.from({ length: 24 }, (_, i) => `master${i}`).join(" ");
    fireEvent.change(field, { target: { value: master } });
    fireEvent.click(begin);
    await screen.findByText("paperword1");
    expect(mock.begin).toHaveBeenCalledWith("00000000-0000-4000-8000-0000000000aa", expect.any(Uint8Array), master);
  });

  it("discards the worker ceremony when the member cancels", async () => {
    render(<RecoveryCeremonyPanel />);
    fireEvent.click(await screen.findByRole("button", { name: /Herstelkluis instellen/ }));
    fireEvent.click(screen.getByRole("button", { name: /Beginnen/ }));
    await screen.findByText("paperword1");
    fireEvent.click(screen.getByRole("button", { name: "Annuleren" }));
    expect(mock.discard).toHaveBeenCalledWith("h1");
    expect(document.body.textContent).not.toMatch(/paperword/);
  });
});
