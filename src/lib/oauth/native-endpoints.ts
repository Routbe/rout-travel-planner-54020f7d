import { canonicalAppUrl } from "@/lib/app-url";

/** ROUT's own OIDC issuer: always absolute (scheme + host, no trailing slash). */
export function oidcIssuer(): string {
  const raw = (process.env["NEXT_PUBLIC_APP_URL"] || canonicalAppUrl()).trim().replace(/\/+$/, "");
  return /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
}

/**
 * Endpoints of ROUT's own OIDC provider. One source for the discovery document
 * and the native "ROUT ID" sign-in, so sign-in never has to fetch its own
 * discovery document over HTTP.
 */
export function nativeOidcEndpoints(iss: string = oidcIssuer()) {
  return {
    issuer: iss,
    authorizationUrl: `${iss}/oauth/authorize`,
    tokenUrl: `${iss}/api/public/oauth/token`,
    userInfoUrl: `${iss}/api/public/oauth/userinfo`,
    jwksUrl: `${iss}/.well-known/jwks.json`,
    endSessionUrl: `${iss}/oauth/end-session`,
  };
}

export type NativeUserInfo = { id: string; email: string; name?: string; image?: string; emailVerified: boolean };

/** Identity for the native sign-in, read only from the userinfo endpoint with the access token. */
export async function fetchNativeUserInfo(
  userInfoUrl: string,
  accessToken: string | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<NativeUserInfo | null> {
  if (!accessToken) return null;
  let p: Record<string, unknown>;
  try {
    const r = await fetchImpl(userInfoUrl, { headers: { authorization: `Bearer ${accessToken}` } });
    if (!r.ok) return null;
    p = (await r.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
  const sub = p["sub"];
  if (typeof sub !== "string" || !sub || typeof p["email"] !== "string") return null;
  return {
    id: sub,
    email: (p["email"] as string).toLowerCase(),
    name: typeof p["name"] === "string" ? (p["name"] as string) : undefined,
    image: typeof p["picture"] === "string" ? (p["picture"] as string) : undefined,
    emailVerified: p["email_verified"] === true,
  };
}
