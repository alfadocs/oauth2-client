import { appendOauthTokenScopes, formatUnknownError, inferUserId, inferUsername } from "./auth-utils.js";
import { parseCookies, serializeCookie } from "./cookie.js";
import { exchangeCodeForToken, fetchUserInfo } from "./oauth.js";
import type { TokenResponse } from "./oauth.js";
import { generatePkce, generateState } from "./pkce.js";
import { decodePreAuth, encodePreAuth } from "./session.js";
import type { AuthStorage, StoredUser } from "./storage.js";

export interface AlfadocsAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  storage: AuthStorage;
  baseUrl?: string;
  appOrigin: string;
  appPostLoginPath?: string;
  cookieName?: string;
  preAuthCookieName?: string;
  /**
   * OAuth2 scopes (`scope` on authorize). Default: `["patient:list"]`.
   * The same list is sent on the token `POST` as standard `scope` (space-separated) and as Alfadocs `oauth_token_scopes`.
   */
  scopes?: string[];
  /**
   * Provide the user profile after token exchange. Default: `GET /api/v1/me`.
   * Use when `/me` rejects the access token but you can build a profile (e.g. from the JWT or another API).
   */
  resolveProfile?: (input: {
    accessToken: string;
    tokenResponse: TokenResponse;
    meUrl: string;
    fetchImpl: typeof globalThis.fetch;
  }) => Promise<Record<string, unknown>>;
  /**
   * Controls the Secure attribute on auth cookies.
   * Keep `true` in production. Set `false` only for local HTTP testing.
   * Default: true
   */
  cookieSecure?: boolean;
  /**
   * HTTP client for Alfadocs (token + `/api/v1/me`). Defaults to `globalThis.fetch`.
   * For self-signed dev servers, inject a fetch with TLS verification disabled (dev only).
   */
  fetch?: typeof globalThis.fetch;
  oauthDebug?: boolean;
}

export interface AlfadocsAuth {
  handleOptions(req: Request): Response;
  handleLogin(req: Request): Promise<Response>;
  handleCallback(req: Request): Promise<Response>;
  handleSession(req: Request): Promise<Response>;
  handleLogout(req: Request): Response;
  handleRequest(req: Request): Promise<Response>;
}

/**
 * Wires OAuth (PKCE + callback + session cookie) to pluggable storage.
 * Call sites get one object (`handleRequest` / focused handlers) so Edge, Node, or tests
 * share the same flow without baking in Supabase or another backend.
 */
export function createAlfadocsAuth(config: AlfadocsAuthConfig): AlfadocsAuth {
  const baseUrl = (config.baseUrl ?? "https://app.alfadocs.loc").replace(/\/$/, "");
  const authorizeUrl = `${baseUrl}/oauth2/authorize`;
  const tokenUrl = `${baseUrl}/oauth2/token`;
  const meUrl = `${baseUrl}/api/v1/me`;
  const appOrigin = config.appOrigin.replace(/\/$/, "");
  const appPostLoginPath = config.appPostLoginPath ?? "/";
  const cookieName = config.cookieName ?? "alfadocs_session";
  const preAuthCookieName = config.preAuthCookieName ?? "alfadocs_preauth";
  const scopes = config.scopes ?? ["patient:list"];

  const cookieSecure = config.cookieSecure ?? true;
  const sessionSameSite: "None" | "Lax" = cookieSecure ? "None" : "Lax";
  const baseFetch: typeof globalThis.fetch =
    config.fetch ??
    ((input, init) => globalThis.fetch(input, init));
  const httpFetch: typeof globalThis.fetch =
    config.oauthDebug === true
      ? async (input, init) => {
          const url = String(input);
          if (
            url.includes("/oauth2/token") &&
            init?.method === "POST" &&
            typeof init.body === "string"
          ) {
            const formParams = new URLSearchParams(init.body);
            const fields = Object.fromEntries(formParams.entries());
            console.warn("[@alfadocs/auth] POST /oauth2/token form:", fields);
            console.warn("[@alfadocs/auth] POST /oauth2/token raw body:", init.body);
            console.warn("[@alfadocs/auth] scope in token request:", formParams.get("scope"));
            console.warn(
              "[@alfadocs/auth] oauth_token_scopes in token request:",
              formParams.get("oauth_token_scopes"),
            );
          }
          return baseFetch(input, init);
        }
      : baseFetch;

  const corsHeaders: Record<string, string> = {
    "Access-Control-Allow-Origin": appOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
  };

  // Keep response formatting in one place so CORS/content-type are always consistent.
  function jsonResponse(
    data: unknown,
    status = 200,
    extra: Record<string, string> = {},
  ): Response {
    return new Response(JSON.stringify(data), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json", ...extra },
    });
  }

  function errorResponse(status: number, message: string): Response {
    return jsonResponse({ error: message }, status);
  }

  function unauthenticatedResponse(): Response {
    return jsonResponse({ authenticated: false });
  }

  // Synchronize provider profile into storage on each login callback.
  // This keeps authData fresh while preserving stable user identity when possible.
  async function upsertUserFromProfile(profile: Record<string, unknown>): Promise<StoredUser> {
    const userId = inferUserId(profile);
    const username = inferUsername(profile);
    const authData = profile;

    if (!userId) {
      return config.storage.createUser(crypto.randomUUID(), username, authData);
    }

    const existing = await config.storage.getUser(userId);
    if (!existing) {
      return config.storage.createUser(userId, username, authData);
    }

    return config.storage.updateUser(existing.id, { username, authData });
  }

  // Short-circuit browser preflight requests for credentialed cross-origin calls.
  function handleOptions(_req: Request): Response {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Start OAuth with PKCE + state and store verifier/state in an httpOnly pre-auth cookie.
  async function handleLogin(_req: Request): Promise<Response> {
    const { verifier, challenge } = await generatePkce();
    const state = generateState();

    const preAuthCookie = serializeCookie(
      preAuthCookieName,
      encodePreAuth({ codeVerifier: verifier, state }),
      { httpOnly: true, secure: cookieSecure, sameSite: "Lax", maxAge: 600 },
    );

    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    if (scopes.length > 0) params.set("scope", scopes.join(" "));
    appendOauthTokenScopes(params, "oauth_token_scopes", scopes);
    if (config.oauthDebug === true) {
      console.warn("[@alfadocs/auth] redirect to authorize:", `${authorizeUrl}?${params}`);
      console.warn("[@alfadocs/auth] scope in authorize URL:", params.get("scope"));
      console.warn(
        "[@alfadocs/auth] oauth_token_scopes in authorize URL:",
        params.get("oauth_token_scopes"),
      );
    }

    return new Response(null, {
      status: 302,
      headers: { Location: `${authorizeUrl}?${params}`, "Set-Cookie": preAuthCookie },
    });
  }

  // Complete OAuth callback: validate anti-CSRF state, exchange code, persist user/session.
  async function handleCallback(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const oauthError = url.searchParams.get("error");
    if (oauthError) {
      const description = url.searchParams.get("error_description") ?? oauthError;
      return errorResponse(400, description);
    }

    const authorizationCode = url.searchParams.get("code");
    const callbackState = url.searchParams.get("state");
    if (!authorizationCode || !callbackState) {
      return errorResponse(400, "Missing code or state in callback URL");
    }

    const cookies = parseCookies(req.headers.get("cookie") ?? "");
    const rawPreAuthCookie = cookies[preAuthCookieName];
    if (!rawPreAuthCookie) {
      return errorResponse(400, "Pre-auth cookie missing");
    }
    const preAuth = decodePreAuth(rawPreAuthCookie);
    if (!preAuth || preAuth.state !== callbackState) {
      return errorResponse(400, "Invalid pre-auth state");
    }

    let tokens;
    try {
      tokens = await exchangeCodeForToken(
        {
          tokenUrl,
          clientId: config.clientId,
          clientSecret: config.clientSecret,
          redirectUri: config.redirectUri,
          code: authorizationCode,
          codeVerifier: preAuth.codeVerifier,
          scopes: scopes.length > 0 ? scopes : undefined,
        },
        httpFetch,
      );
    } catch (err) {
      const msg = formatUnknownError(err);
      return errorResponse(502, msg);
    }

    let profile: Record<string, unknown>;
    try {
      if (config.resolveProfile) {
        profile = await config.resolveProfile({
          accessToken: tokens.access_token,
          tokenResponse: tokens,
          meUrl,
          fetchImpl: httpFetch,
        });
      } else {
        profile = await fetchUserInfo(meUrl, tokens.access_token, httpFetch);
      }
    } catch (err) {
      const msg = formatUnknownError(err);
      return errorResponse(502, msg);
    }

    let user: StoredUser;
    try {
      user = await upsertUserFromProfile(profile);
    } catch (err) {
      const msg = formatUnknownError(err);
      return errorResponse(500, `Failed persisting user: ${msg}`);
    }

    let sessionCookieValue = "";
    try {
      const session = await config.storage.createSession(user.id);
      sessionCookieValue = session.cookieValue;
    } catch (err) {
      const msg = formatUnknownError(err);
      return errorResponse(500, `Failed creating session: ${msg}`);
    }

    const sessionCookie = serializeCookie(cookieName, sessionCookieValue, {
      httpOnly: true,
      secure: cookieSecure,
      sameSite: sessionSameSite,
      maxAge: 60 * 60 * 24 * 7,
    });
    const clearPreAuth = serializeCookie(preAuthCookieName, "", {
      httpOnly: true,
      secure: cookieSecure,
      sameSite: "Lax",
      maxAge: 0,
    });

    const headers = new Headers({ Location: `${appOrigin}${appPostLoginPath}` });
    headers.append("Set-Cookie", sessionCookie);
    headers.append("Set-Cookie", clearPreAuth);
    return new Response(null, { status: 302, headers });
  }

  // Resolve current auth state from session cookie and stored session/user records.
  async function handleSession(req: Request): Promise<Response> {
    const cookies = parseCookies(req.headers.get("cookie") ?? "");
    const cookieValue = cookies[cookieName];
    if (!cookieValue) return unauthenticatedResponse();

    try {
      const session = await config.storage.getSession(cookieValue);
      if (!session) return unauthenticatedResponse();
      const user = await config.storage.getUser(session.userId);
      if (!user) return unauthenticatedResponse();
      return jsonResponse({ authenticated: true, user: user.authData });
    } catch (err) {
      const msg = formatUnknownError(err);
      return jsonResponse({ authenticated: false, error: msg }, 500);
    }
  }

  // Logout is cookie invalidation only; session lookup becomes unauthenticated next request.
  function handleLogout(_req: Request): Response {
    const clear = serializeCookie(cookieName, "", {
      httpOnly: true,
      secure: cookieSecure,
      sameSite: sessionSameSite,
      maxAge: 0,
    });
    return jsonResponse({ ok: true }, 200, { "Set-Cookie": clear });
  }

  // Single entrypoint router so deployment targets only need to call one method.
  async function handleRequest(req: Request): Promise<Response> {
    if (req.method === "OPTIONS") return handleOptions(req);
    const url = new URL(req.url);
    if (req.method === "POST") return handleLogout(req);
    if (url.searchParams.get("action") === "login") return handleLogin(req);
    if (url.searchParams.has("code") || url.searchParams.has("error")) return handleCallback(req);
    return handleSession(req);
  }

  return { handleOptions, handleLogin, handleCallback, handleSession, handleLogout, handleRequest };
}
