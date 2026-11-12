import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const MEMBER = "00000000-0000-4000-8000-0000000000aa";
const mock = vi.hoisted(() => ({ start: vi.fn(), open: vi.fn(), recoverLogin: vi.fn(), prf: vi.fn(), fromWire: vi.fn() }));
vi.mock("@tanstack/react-start", () => ({ useServerFn: (fn: unknown) => fn }));
vi.mock("@/lib/recovery/recovery-login.functions", () => ({ startRecoveryLogin: mock.start, openRecoveryLogin: mock.open }));
vi.mock("@/lib/recovery/passkey-prf", () => ({ withPasskeyPrf: mock.prf }));
vi.mock("@/lib/recovery/ceremony-wire", async (original) => ({
  ...await original<typeof import("@/lib/recovery/ceremony-wire")>(),
  ceremonyFromWire: mock.fromWire,
}));
vi.mock("@/lib/crypto-enclave/client", async (original) => ({
  ...await original<typeof import("@/lib/crypto-enclave/client")>(),
  enclave: { ceremony: { recoverLogin: mock.recoverLogin } },
}));
import { RecoveryLogin } from "./RecoveryLogin";

const share = btoa(String.fromCharCode(...new Uint8Array(48).fill(7)));
const words = Array.from({ length: 24 }, (_, i) => `w${i}`).join(" ");

describe("/recovery sign-in", () => {
  let fetcher: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    vi.clearAllMocks();
    mock.start.mockResolvedValue({ ok: true });
    mock.open.mockResolvedValue({
      ok: true, memberId: MEMBER, challenge: "c".repeat(43), serverShare: share, deviceCredential: "cred",
      ceremony: { ceremonyId: "x", keyId: "key-1", sealedMaster: "", shards: {} },
    });
    mock.fromWire.mockReturnValue({ memberId: MEMBER });
    mock.recoverLogin.mockResolvedValue({ keyId: "key-1", signature: new Uint8Array(64).fill(1) });
    mock.prf.mockImplementation(async (_p: string, consume: (o: Uint8Array) => Promise<unknown>) => consume(new Uint8Array(32)));
    fetcher = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("location", { ...window.location, assign: vi.fn() });
  });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

  async function toFactors() {
    render(<RecoveryLogin />);
    fireEvent.change(screen.getByLabelText("E-mailadres van je account"), { target: { value: "a@b.be" } });
    fireEvent.click(screen.getByRole("button", { name: /Code sturen/ }));
    fireEvent.change(await screen.findByLabelText("Code uit je e-mail"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: /Verder/ }));
    await screen.findByText("Welke twee stukken gebruik je?");
  }

  it("ROUT + paper: words go to the worker once, the field is emptied, the signature is redeemed", async () => {
    await toFactors();
    expect(mock.open).toHaveBeenCalledWith({ data: { email: "a@b.be", code: "123456" } });
    const field = screen.getByLabelText("Je 24 papieren woorden") as HTMLTextAreaElement;
    const go = screen.getByRole("button", { name: /Herstellen en inloggen/ });
    fireEvent.change(field, { target: { value: "w1 w2" } });
    expect(go).toBeDisabled();
    fireEvent.change(field, { target: { value: words } });
    fireEvent.click(go);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    const args = mock.recoverLogin.mock.calls[0][0];
    expect(args).toMatchObject({ userId: MEMBER, keyId: "key-1", challenge: "c".repeat(43), paperWords: words });
    expect(args.prf).toBeUndefined();
    expect(args.serverShare).toHaveLength(48);
    expect(field.value).toBe("");
    const [url, init] = fetcher.mock.calls[0] as [string, { body: string }];
    expect(url).toBe("/api/auth/recovery/verify");
    expect(JSON.parse(init.body).challenge).toBe("c".repeat(43));
    await waitFor(() => expect(window.location.assign).toHaveBeenCalledWith("/auth/continue"));
  });

  it("passkey + paper never sends ROUT's piece", async () => {
    await toFactors();
    fireEvent.click(screen.getByLabelText(/Mijn toegangssleutel \+ papieren woorden/));
    fireEvent.change(screen.getByLabelText("Je 24 papieren woorden"), { target: { value: words } });
    fireEvent.click(screen.getByRole("button", { name: /Bevestigen met toegangssleutel/ }));
    await waitFor(() => expect(mock.recoverLogin).toHaveBeenCalledTimes(1));
    const args = mock.recoverLogin.mock.calls[0][0];
    expect(args.serverShare).toBeUndefined();
    expect(args.prf).toBeInstanceOf(Uint8Array);
    expect(mock.prf).toHaveBeenCalledWith("ceremony", expect.any(Function), "cred");
  });

  it("a refused signature does not sign in and starts over", async () => {
    fetcher.mockResolvedValueOnce({ ok: false });
    await toFactors();
    fireEvent.change(screen.getByLabelText("Je 24 papieren woorden"), { target: { value: words } });
    fireEvent.click(screen.getByRole("button", { name: /Herstellen en inloggen/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("verlopen");
    expect(window.location.assign).not.toHaveBeenCalled();
    expect(screen.getByLabelText("E-mailadres van je account")).toBeInTheDocument();
  });

  it("a wrong code keeps ROUT's piece closed", async () => {
    mock.open.mockResolvedValueOnce({ ok: false, error: "invalid_code" });
    render(<RecoveryLogin />);
    fireEvent.change(screen.getByLabelText("E-mailadres van je account"), { target: { value: "a@b.be" } });
    fireEvent.click(screen.getByRole("button", { name: /Code sturen/ }));
    fireEvent.change(await screen.findByLabelText("Code uit je e-mail"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: /Verder/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("klopt niet");
    expect(screen.queryByText("Welke twee stukken gebruik je?")).toBeNull();
  });
});
