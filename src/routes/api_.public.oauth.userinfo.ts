import { createFileRoute } from "@tanstack/react-router";

/**
 * Userinfo-endpoint: geeft de claims terug die bij de scopes van het
 * access-token horen. `sub` is het (pairwise) subject uit het token; het interne id verlaat de server nooit.
 */
export const Route = createFileRoute("/api_/public/oauth/userinfo")({
  server: {
    handlers: {
      OPTIONS: async () =>
        new Response(null, {
          status: 204,
          headers: {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET, POST, OPTIONS",
            "access-control-allow-headers": "authorization, content-type",
          },
        }),
      GET: async ({ request }) => handle(request),
      POST: async ({ request }) => handle(request),
    },
  },
});

async function handle(request: Request): Promise<Response> {
  const [{ verifyAccessToken, OAuthError }, { generateUserInfoResponse, ScopeForbiddenError }, { handleUserInfo }, { withDbContext }] =
    await Promise.all([
      import("@/lib/oauth/provider.server"),
      import("@/lib/auth/oidc-identifiers.server"),
      import("@/lib/oauth/userinfo-handler"),
      import("@/lib/neon"),
    ]);
  return handleUserInfo(request, {
    verifyAccessToken,
    // The verified token names the member; their claims are owner-scoped rows.
    generateUserInfoResponse: (userId, clientId, scopes, ctx) =>
      withDbContext({ userId, workspaceId: null }, () => generateUserInfoResponse(userId, clientId, scopes, ctx)),
    isOAuthError: (e): e is InstanceType<typeof OAuthError> => e instanceof OAuthError,
    isScopeForbidden: (e): e is InstanceType<typeof ScopeForbiddenError> => e instanceof ScopeForbiddenError,
  });
}
