/**
 * @alfadocs/oauth2-client — Supabase adapter
 *
 * Backend-first Alfadocs auth library for Supabase Edge Functions.
 *
 * The entire OAuth2 + PKCE flow runs server-side. The browser never handles
 * a code verifier, an access token, or a refresh token. It only:
 *   1. Navigates to your Edge Function's /login endpoint to start login.
 *   2. Lands back on your app after Alfadocs redirects to /callback.
 *   3. Calls /session on mount to know if the user is authenticated.
 *
 * Usage in a Supabase Edge Function:
 *
 * ```ts
 * import { createAlfadocsSupabaseAuth } from "@alfadocs/oauth2-client/supabase"
 *
 * const auth = createAlfadocsSupabaseAuth({
 *   clientId:    Deno.env.get("ALFADOCS_CLIENT_ID")!,
 *   clientSecret: Deno.env.get("ALFADOCS_CLIENT_SECRET")!,
 *   redirectUri: Deno.env.get("ALFADOCS_REDIRECT_URI")!,
 *   appOrigin:   Deno.env.get("APP_ORIGIN")!,
 * })
 *
 * Deno.serve(async (req) => {
 *   if (req.method === "OPTIONS") return auth.handleOptions(req)
 *   const path = new URL(req.url).pathname
 *   if (path.endsWith("/login"))    return auth.handleLogin(req)
 *   if (path.endsWith("/callback")) return auth.handleCallback(req)
 *   if (path.endsWith("/session"))  return auth.handleSession(req)
 *   if (path.endsWith("/logout"))   return auth.handleLogout(req)
 *   return new Response("Not found", { status: 404 })
 * })
 * ```
 */

import { generatePkce, generateState } from "../core/pkce";
import { parseCookies, serializeCookie } from "../core/cookie";
import {
  encodeSession,
  decodeSession,
  encodePreAuth,
  decodePreAuth,
} from "../core/session";
import {
  exchangeCodeForToken,
  refreshAccessToken,
  fetchUserInfo,
  buildSessionData,
} from "../core/oauth";

export type { AlfadocsUser, SessionData } from "../core/session";

// ─── Public types ─────────────────────────────────────────────────────────────

export interface AlfadocsSupabaseAuthConfig {
  /** OAuth2 client ID (public, appears in the authorize URL) */
  clientId: string;
  /** OAuth2 client secret — kept server-side only, never exposed to the browser */
  clientSecret: string;
  /**
   * Alfadocs base URL.
   * Default: `"https://app.alfadocs.loc"` (local dev).
   * Set to `"https://app.alfadocs.com"` for production.
   */
  baseUrl?: string;
  /**
   * The URL Alfadocs redirects to after the user authenticates.
   * Must match a redirect URI registered on your Alfadocs OAuth client.
   *
   * When using `handleRequest` (single-endpoint mode), this is just the bare
   * function URL — no sub-path needed:
   * `"https://xyz.supabase.co/functions/v1/alfadocs-auth"`
   */
  redirectUri: string;
  /**
   * Your frontend app origin.
   * Used as the `Access-Control-Allow-Origin` header and for the post-login redirect.
   * e.g. `"https://myapp.lovable.app"`
   */
  appOrigin: string;
  /**
   * Path within your app to redirect the user to after a successful login.
   * Default: `"/"`
   */
  appPostLoginPath?: string;
  /**
   * Name of the long-lived session cookie.
   * Default: `"alfadocs_session"`
   */
  cookieName?: string;
  /**
   * Name of the short-lived pre-auth cookie (stores PKCE verifier + state).
   * Default: `"alfadocs_preauth"`
   */
  preAuthCookieName?: string;
  /**
   * Session cookie `Max-Age` in seconds.
   * Default: `604800` (7 days)
   */
  cookieMaxAgeSeconds?: number;
  /**
   * OAuth2 scopes to request.
   * Default: `["allowed"]` (requests all scopes registered on the client)
   */
  scopes?: string[];
}

/** Discriminated union returned by `handleSession` as parsed JSON */
export type SessionResult =
  | { authenticated: false }
  | { authenticated: true; user: Record<string, unknown> };

/** The auth handler object returned by `createAlfadocsSupabaseAuth` */
export interface AlfadocsSupabaseAuth {
  /**
   * Responds to CORS preflight requests (OPTIONS).
   * Call this first in your Edge Function before any other routing.
   */
  handleOptions(req: Request): Response;

  /**
   * Starts the OAuth2 login flow.
   * Generates PKCE verifier + state server-side, stores them in a short-lived
   * httpOnly pre-auth cookie, and returns a 302 redirect to the Alfadocs
   * authorization endpoint.
   *
   * The browser just navigates to this endpoint — no frontend library needed.
   */
  handleLogin(req: Request): Promise<Response>;

  /**
   * Handles the OAuth2 callback from Alfadocs.
   * Reads the pre-auth cookie, validates the state parameter, exchanges the
   * authorization code for tokens, fetches the user profile from /api/v1/me,
   * sets a long-lived httpOnly session cookie, and redirects the user back to
   * the app (`appOrigin + appPostLoginPath`).
   */
  handleCallback(req: Request): Promise<Response>;

  /**
   * Checks whether the session cookie is present and valid.
   * Auto-refreshes the access token if it is expiring soon (within 5 minutes).
   * Returns JSON `{ authenticated: boolean, user?: object }`.
   *
   * Call this from the browser on app mount with `credentials: "include"`:
   * ```ts
   * const res = await fetch(sessionUrl, { credentials: "include" })
   * const { authenticated, user } = await res.json()
   * ```
   */
  handleSession(req: Request): Promise<Response>;

  /**
   * Clears the session cookie.
   * Returns JSON `{ ok: true }`.
   */
  handleLogout(req: Request): Response;

  /**
   * Single-endpoint handler — routes all auth traffic automatically.
   * Point your entire OAuth2 flow (login, callback, session, logout) at one URL.
   *
   * Routing rules:
   *   OPTIONS  *                  → CORS preflight
   *   GET      ?action=login      → start login flow
   *   GET      ?code=...          → OAuth2 callback (Alfadocs redirect)
   *   GET      (no params)        → session check
   *   POST     (any)              → logout
   *
   * Edge Function example — the entire handler is one line:
   * ```ts
   * Deno.serve((req) => auth.handleRequest(req))
   * ```
   *
   * The `redirectUri` you register on Alfadocs is just the bare function URL:
   * `https://xyz.supabase.co/functions/v1/alfadocs-auth`
   */
  handleRequest(req: Request): Promise<Response>;
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export function createAlfadocsSupabaseAuth(
  config: AlfadocsSupabaseAuthConfig,
): AlfadocsSupabaseAuth {
  const baseUrl = (config.baseUrl ?? "https://app.alfadocs.loc").replace(/\/$/, "");
  const authorizeUrl = `${baseUrl}/oauth2/authorize`;
  const tokenUrl = `${baseUrl}/oauth2/token`;
  const meUrl = `${baseUrl}/api/v1/me`;
  const appOrigin = config.appOrigin.replace(/\/$/, "");
  const appPostLoginPath = config.appPostLoginPath ?? "/";
  const cookieName = config.cookieName ?? "alfadocs_session";
  const preAuthCookieName = config.preAuthCookieName ?? "alfadocs_preauth";
  const cookieMaxAge = config.cookieMaxAgeSeconds ?? 60 * 60 * 24 * 7;
  const scopes = config.scopes ?? ["allowed"];

  // CORS headers — applied to all responses so fetch() calls from the browser work
  const corsHeaders: Record<string, string> = {
    "Access-Control-Allow-Origin": appOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
  };

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

  // ── OPTIONS ───────────────────────────────────────────────────────────────

  function handleOptions(_req: Request): Response {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // ── LOGIN ─────────────────────────────────────────────────────────────────

  async function handleLogin(_req: Request): Promise<Response> {
    const { verifier, challenge } = await generatePkce();
    const state = generateState();

    // Store PKCE verifier + state in a short-lived httpOnly cookie.
    // SameSite=Lax: the pre-auth cookie must be sent when Alfadocs redirects
    // back to /callback — that is a top-level GET navigation, which Lax allows.
    const preAuthCookie = serializeCookie(
      preAuthCookieName,
      encodePreAuth({ codeVerifier: verifier, state }),
      { httpOnly: true, secure: true, sameSite: "Lax", maxAge: 600 },
    );

    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    if (scopes.length > 0) {
      params.set("scope", scopes.join(" "));
    }

    return new Response(null, {
      status: 302,
      headers: { Location: `${authorizeUrl}?${params}`, "Set-Cookie": preAuthCookie },
    });
  }

  // ── CALLBACK ──────────────────────────────────────────────────────────────

  async function handleCallback(req: Request): Promise<Response> {
    const url = new URL(req.url);

    const error = url.searchParams.get("error");
    if (error) {
      const desc = url.searchParams.get("error_description") ?? error;
      return jsonResponse({ error: desc }, 400);
    }

    const code = url.searchParams.get("code");
    const returnedState = url.searchParams.get("state");
    if (!code || !returnedState) {
      return jsonResponse({ error: "Missing code or state in callback URL" }, 400);
    }

    // Read pre-auth cookie
    const cookies = parseCookies(req.headers.get("cookie") ?? "");
    const rawPreAuth = cookies[preAuthCookieName];
    if (!rawPreAuth) {
      return jsonResponse(
        { error: "Pre-auth cookie missing — login session expired or cookies are blocked" },
        400,
      );
    }
    const preAuth = decodePreAuth(rawPreAuth);
    if (!preAuth) {
      return jsonResponse({ error: "Pre-auth cookie is corrupted" }, 400);
    }
    if (preAuth.state !== returnedState) {
      return jsonResponse({ error: "State mismatch — possible CSRF attack" }, 400);
    }

    // Exchange code for tokens
    let tokens;
    try {
      tokens = await exchangeCodeForToken({
        tokenUrl,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        redirectUri: config.redirectUri,
        code,
        codeVerifier: preAuth.codeVerifier,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return jsonResponse({ error: msg }, 502);
    }

    // Fetch user info from Alfadocs
    let user;
    try {
      user = await fetchUserInfo(meUrl, tokens.access_token);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return jsonResponse({ error: msg }, 502);
    }

    const sessionData = buildSessionData(tokens, user);

    // Session cookie: SameSite=None because the browser (lovable.app) makes
    // cross-origin fetch() calls to Supabase (supabase.co). None requires Secure.
    const sessionCookie = serializeCookie(
      cookieName,
      encodeSession(sessionData),
      { httpOnly: true, secure: true, sameSite: "None", maxAge: cookieMaxAge },
    );

    // Clear the pre-auth cookie immediately — it is single-use
    const clearPreAuth = serializeCookie(preAuthCookieName, "", {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      maxAge: 0,
    });

    // Use Headers with append() to set two Set-Cookie headers correctly.
    // A comma-joined single Set-Cookie header is incorrect per RFC 6265.
    const headers = new Headers({
      Location: `${appOrigin}${appPostLoginPath}`,
    });
    headers.append("Set-Cookie", sessionCookie);
    headers.append("Set-Cookie", clearPreAuth);

    return new Response(null, { status: 302, headers });
  }

  // ── SESSION ───────────────────────────────────────────────────────────────

  async function handleSession(req: Request): Promise<Response> {
    const cookies = parseCookies(req.headers.get("cookie") ?? "");
    const raw = cookies[cookieName];

    if (!raw) return jsonResponse({ authenticated: false });

    const session = decodeSession(raw);
    if (!session) return jsonResponse({ authenticated: false });

    // Access token has enough time left — return immediately without refreshing
    const REFRESH_THRESHOLD_MS = 5 * 60 * 1000;
    if (Date.now() < session.expiresAt - REFRESH_THRESHOLD_MS) {
      return jsonResponse({ authenticated: true, user: session.user });
    }

    // Token is expired or expiring soon — attempt refresh
    if (!session.refreshToken) {
      // No refresh token available: clear stale cookie
      const clear = serializeCookie(cookieName, "", {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 0,
      });
      return jsonResponse({ authenticated: false }, 200, { "Set-Cookie": clear });
    }

    let refreshed;
    try {
      refreshed = await refreshAccessToken({
        tokenUrl,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        refreshToken: session.refreshToken,
      });
    } catch {
      // Transient server error: keep the session if the token hasn't hard-expired yet
      if (Date.now() < session.expiresAt) {
        return jsonResponse({ authenticated: true, user: session.user });
      }
      return jsonResponse({ authenticated: false });
    }

    if (!refreshed) {
      // Refresh token was rejected (revoked/expired): clear session
      const clear = serializeCookie(cookieName, "", {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 0,
      });
      return jsonResponse({ authenticated: false }, 200, { "Set-Cookie": clear });
    }

    // Refresh succeeded: build new session, preserve the existing user info
    const newSession = buildSessionData(refreshed, session.user);
    const newCookie = serializeCookie(
      cookieName,
      encodeSession(newSession),
      { httpOnly: true, secure: true, sameSite: "None", maxAge: cookieMaxAge },
    );
    return jsonResponse(
      { authenticated: true, user: newSession.user },
      200,
      { "Set-Cookie": newCookie },
    );
  }

  // ── LOGOUT ────────────────────────────────────────────────────────────────

  function handleLogout(_req: Request): Response {
    const clear = serializeCookie(cookieName, "", {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 0,
    });
    return jsonResponse({ ok: true }, 200, { "Set-Cookie": clear });
  }

  async function handleRequest(req: Request): Promise<Response> {
    if (req.method === "OPTIONS") return handleOptions(req);

    const url = new URL(req.url);

    if (req.method === "POST") return handleLogout(req);

    // GET — distinguish login / callback / session by query params
    if (url.searchParams.get("action") === "login") return handleLogin(req);
    if (url.searchParams.has("code") || url.searchParams.has("error")) return handleCallback(req);
    return handleSession(req);
  }

  return { handleOptions, handleLogin, handleCallback, handleSession, handleLogout, handleRequest };
}
