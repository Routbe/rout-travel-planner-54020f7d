import { describe, expect, it, vi } from "vitest";
import { fetchNativeUserInfo, nativeOidcEndpoints } from "./native-endpoints";

const ok = (body: unknown) => vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })) as unknown as typeof fetch;

describe("native ROUT ID endpoints", () => {
  it("builds every endpoint on the issuer without a discovery fetch", () => {
    expect(nativeOidcEndpoints("https://rout.be")).toEqual({
      issuer: "https://rout.be",
      authorizationUrl: "https://rout.be/oauth/authorize",
      tokenUrl: "https://rout.be/api/public/oauth/token",
      userInfoUrl: "https://rout.be/api/public/oauth/userinfo",
      jwksUrl: "https://rout.be/.well-known/jwks.json",
      endSessionUrl: "https://rout.be/oauth/end-session",
    });
  });
});

describe("fetchNativeUserInfo", () => {
  it("uses sub as the account id and lowercases the email", async () => {
    const info = await fetchNativeUserInfo("https://rout.be/u", "tok", ok({ sub: "s1", email: "A@Rout.be", email_verified: true }));
    expect(info).toEqual({ id: "s1", email: "a@rout.be", name: undefined, image: undefined, emailVerified: true });
  });

  it("treats an address as verified only when email_verified is exactly true", async () => {
    const info = await fetchNativeUserInfo("https://rout.be/u", "tok", ok({ sub: "s1", email: "a@rout.be", email_verified: "true" }));
    expect(info?.emailVerified).toBe(false);
  });

  it("refuses without an access token, a sub or an email", async () => {
    const f = ok({ sub: "s1", email: "a@rout.be" });
    expect(await fetchNativeUserInfo("https://rout.be/u", undefined, f)).toBeNull();
    expect(f).not.toHaveBeenCalled();
    expect(await fetchNativeUserInfo("https://rout.be/u", "tok", ok({ email: "a@rout.be" }))).toBeNull();
    expect(await fetchNativeUserInfo("https://rout.be/u", "tok", ok({ sub: "s1" }))).toBeNull();
  });

  it("returns null when userinfo answers an error", async () => {
    const f = vi.fn(async () => new Response("no", { status: 401 })) as unknown as typeof fetch;
    expect(await fetchNativeUserInfo("https://rout.be/u", "tok", f)).toBeNull();
  });
});
