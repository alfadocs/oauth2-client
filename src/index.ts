/**
 * @alfadocs/oauth2-client
 *
 * Drop-in OAuth2 PKCE client for Alfadocs authentication.
 * Designed for Lovable apps using Supabase as the backend.
 *
 * How it works:
 *   1. `login()`            — generates PKCE, redirects user to Alfadocs
 *   2. `handleCallback()`   — sends the auth code to your Supabase Edge Function,
 *                             which exchanges it server-side and sets an httpOnly cookie
 *   3. `refreshSession()`   — call on app mount to restore session from the cookie
 *   4. `isAuthenticated()`  — sync check of in-memory state
 *   5. `logout()`           — clears the cookie via Supabase
 *
 * The browser never sees the access token. All token handling happens server-side
 * in the Supabase Edge Function. The session is persisted as an httpOnly cookie,
 * which survives page refreshes and is inaccessible to JavaScript.
 *
 * See README for the required Supabase Edge Function template.
 */

// ─── Public types ─────────────────────────────────────────────────────────────

/**
 * Configuration for `initAlfadocsAuth`.
 *
 * ```ts
 * const auth = initAlfadocsAuth({
 *   clientId:    import.meta.env.VITE_ALFADOCS_CLIENT_ID,
 *   redirectUri: `${window.location.origin}/callback`,
 *   exchangeUrl: import.meta.env.VITE_SUPABASE_EXCHANGE_URL,
 *   baseUrl:     'https://app.alfadocs.com',
 * })
 * ```
 */
export interface AlfadocsAuthConfig {
  /** Your Alfadocs OAuth2 client ID. */
  clientId: string;

  /**
   * The URL Alfadocs will redirect back to after authentication.
   * Must exactly match a redirect URI registered on your Alfadocs client.
   */
  redirectUri: string;

  /**
   * URL of your Supabase Edge Function that handles token exchange and session management.
   * e.g. `https://xyz.supabase.co/functions/v1/alfadocs-auth`
   *
   * The function must implement:
   * - `POST /`        — exchange code, set httpOnly cookie
   * - `GET /session`  — validate cookie, return `{ authenticated: boolean }`
   * - `POST /logout`  — clear cookie
   *
   * See README for the full Edge Function template.
   */
  exchangeUrl: string;

  /**
   * Alfadocs base URL. Defaults to the local development server (`https://app.alfadocs.loc`).
   * Set explicitly for production: `https://app.alfadocs.com`.
   */
  baseUrl?: string;

  /** OAuth2 scopes to request (e.g. `["patient:view"]`). Defaults to `[]`. */
  scopes?: string[];
}

/** The auth client returned by `initAlfadocsAuth`. */
export interface AlfadocsAuth {
  /**
   * Redirects the user to the Alfadocs login page.
   * Automatically generates and stores PKCE + state.
   *
   * Call this when the user clicks your "Login" button.
   */
  login(): Promise<void>;

  /**
   * Handles the OAuth2 callback after Alfadocs redirects the user back.
   * Call this on the page whose URL matches your `redirectUri`.
   *
   * Sends the authorization code to your Supabase Edge Function, which
   * exchanges it for tokens server-side and sets an httpOnly session cookie.
   *
   * @param url Full callback URL. Defaults to `window.location.href`.
   */
  handleCallback(url?: string): Promise<void>;

  /**
   * Checks whether the session cookie is still valid by calling your Supabase
   * Edge Function. Call this once on app mount to restore auth state after a
   * page refresh.
   *
   * Returns `true` if the user is authenticated, `false` otherwise.
   *
   * ```ts
   * useEffect(() => {
   *   auth.refreshSession().then(setIsLoggedIn)
   * }, [])
   * ```
   */
  refreshSession(): Promise<boolean>;

  /**
   * Synchronous check of the in-memory auth state.
   * Always returns `false` after a page refresh until `refreshSession()` completes.
   * Use `refreshSession()` for the authoritative check.
   */
  isAuthenticated(): boolean;

  /**
   * Clears the session by calling your Supabase Edge Function, which removes
   * the httpOnly cookie.
   */
  logout(): Promise<void>;
}

// ─── PKCE / state keys (sessionStorage — ephemeral, redirect-safe) ────────────
// These two values must survive the browser navigation to Alfadocs and back.
// sessionStorage persists across same-tab navigations but is cleared on tab close.
// They are single-use and hold no long-term secret value.

const KEY_PKCE_VERIFIER = "alfadocs_auth_pkce";
const KEY_STATE = "alfadocs_auth_state";
// Tracks the last successfully exchanged code to handle React StrictMode
// double-invocation of handleCallback (auth codes are single-use).
const KEY_LAST_CODE = "alfadocs_auth_last_code";

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function generatePkce(): Promise<{ verifier: string; challenge: string }> {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  const verifier = base64UrlEncode(bytes.buffer);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: base64UrlEncode(digest) };
}

function generateState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes.buffer);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Initialize Alfadocs authentication.
 *
 * @example
 * ```ts
 * // src/auth.ts — create once, import everywhere
 * import { initAlfadocsAuth } from '@alfadocs/oauth2-client'
 *
 * export const auth = initAlfadocsAuth({
 *   clientId:    import.meta.env.VITE_ALFADOCS_CLIENT_ID,
 *   redirectUri: `${window.location.origin}/callback`,
 *   exchangeUrl: import.meta.env.VITE_SUPABASE_EXCHANGE_URL,
 *   baseUrl:     'https://app.alfadocs.com',
 * })
 * ```
 */
export function initAlfadocsAuth(config: AlfadocsAuthConfig): AlfadocsAuth {
  const baseUrl = (config.baseUrl ?? "https://app.alfadocs.loc").replace(/\/$/, "");
  const authorizeUrl = `${baseUrl}/oauth2/authorize`;
  const exchangeUrl = config.exchangeUrl.replace(/\/$/, "");
  const scopes = config.scopes ?? [];

  // In-memory auth state. Set by handleCallback / refreshSession, cleared by logout.
  // Lost on page refresh — call refreshSession() on mount to restore it.
  let authenticated = false;

  return {
    async login(): Promise<void> {
      const state = generateState();
      const { verifier, challenge } = await generatePkce();

      sessionStorage.setItem(KEY_STATE, state);
      sessionStorage.setItem(KEY_PKCE_VERIFIER, verifier);

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

      window.location.href = `${authorizeUrl}?${params}`;
    },

    async handleCallback(url?: string): Promise<void> {
      const searchParams = new URL(url ?? window.location.href).searchParams;

      const error = searchParams.get("error");
      if (error) {
        throw new Error(
          `[AlfadocsAuth] Login failed: ${searchParams.get("error_description") ?? error}`,
        );
      }

      const code = searchParams.get("code");
      if (!code) {
        // No code in URL. If we're already authenticated (e.g. user navigated
        // directly to the callback page after a prior login), silently succeed.
        if (authenticated) return;
        throw new Error("[AlfadocsAuth] No authorization code found in callback URL.");
      }

      // React StrictMode calls useEffect twice in dev. Auth codes are single-use,
      // so skip the exchange if we already successfully processed this exact code.
      if (sessionStorage.getItem(KEY_LAST_CODE) === code) return;

      const storedState = sessionStorage.getItem(KEY_STATE);
      const codeVerifier = sessionStorage.getItem(KEY_PKCE_VERIFIER) ?? undefined;
      sessionStorage.removeItem(KEY_STATE);
      sessionStorage.removeItem(KEY_PKCE_VERIFIER);

      if (storedState && searchParams.get("state") !== storedState) {
        throw new Error("[AlfadocsAuth] State mismatch — this callback may have been tampered with.");
      }

      const response = await fetch(exchangeUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // required: allows the Supabase function to set the cookie
        body: JSON.stringify({ code, code_verifier: codeVerifier }),
      });

      if (!response.ok) {
        const body = await response.text().catch(() => "");
        throw new Error(`[AlfadocsAuth] Session exchange failed (HTTP ${response.status}): ${body}`);
      }

      sessionStorage.setItem(KEY_LAST_CODE, code);
      authenticated = true;
    },

    async refreshSession(): Promise<boolean> {
      const response = await fetch(`${exchangeUrl}/session`, {
        method: "GET",
        credentials: "include", // sends the httpOnly cookie to the Supabase function
      });

      if (!response.ok) {
        authenticated = false;
        return false;
      }

      const data = await response.json() as { authenticated: boolean };
      authenticated = data.authenticated ?? false;
      return authenticated;
    },

    isAuthenticated(): boolean {
      return authenticated;
    },

    async logout(): Promise<void> {
      await fetch(`${exchangeUrl}/logout`, {
        method: "POST",
        credentials: "include",
      }).catch(() => {
        // Ignore network errors on logout — clear local state regardless.
      });
      authenticated = false;
    },
  };
}
