/**
 * Client configuration for the AlfaDocs OAuth2 server.
 */
export interface OAuth2ClientConfig {
  /** Override for the authorization URL. Defaults to production AlfaDocs. */
  authorizeEndpoint?: string;
  /** Override for the token URL. Defaults to production AlfaDocs. */
  tokenEndpoint?: string;
  clientId: string;
  redirectUri: string;
  /** Scopes to request, e.g. `["patient:view"]`. */
  scopes?: string[];
}

/** PKCE code verifier and S256 code challenge pair. */
export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

/** Optional parameters when building the authorization URL. */
export interface AuthorizeUrlParams {
  state?: string;
  pkce?: PkcePair;
  extraParams?: Record<string, string>;
}

/** Response from the token endpoint (access token, optional refresh token, etc.). */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  [key: string]: unknown;
}

/** Default AlfaDocs OAuth2 URLs (production). */
export const DEFAULT_AUTHORIZE_ENDPOINT = "https://app.alfadocs.com/oauth2/authorize";
export const DEFAULT_TOKEN_ENDPOINT = "https://app.alfadocs.com/oauth2/token";

// ---------------------------------------------------------------------------
// PKCE helpers (use in browser or Node 18+)
// ---------------------------------------------------------------------------

/**
 * Returns the global Web Crypto implementation.
 * Works in browsers and Node 18+.
 */
function getCrypto(): Crypto {
  if (typeof globalThis !== "undefined" && (globalThis as { crypto?: Crypto }).crypto) {
    return (globalThis as { crypto: Crypto }).crypto;
  }
  throw new Error(
    "Web Crypto is not available. Use a browser or Node 18+, or provide a polyfill.",
  );
}

/**
 * Encodes bytes to base64. Uses `btoa` when available, otherwise a small inline encoder.
 */
function toBase64(bytes: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(bytes));
  if (typeof btoa === "function") {
    return btoa(binary);
  }
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < binary.length; i += 3) {
    const c1 = binary.charCodeAt(i);
    const c2 = i + 1 < binary.length ? binary.charCodeAt(i + 1) : 0;
    const c3 = i + 2 < binary.length ? binary.charCodeAt(i + 2) : 0;
    out += chars[c1 >> 2]
         + chars[((c1 & 3) << 4) | (c2 >> 4)]
         + (i + 1 < binary.length ? chars[((c2 & 15) << 2) | (c3 >> 6)] : "=")
         + (i + 2 < binary.length ? chars[c3 & 63] : "=");
  }
  return out;
}

/**
 * Encodes bytes as base64url (URL-safe, no padding).
 * Used for the PKCE code_challenge.
 */
function base64UrlEncode(bytes: ArrayBuffer): string {
  const base64 = toBase64(bytes);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Creates a PKCE code verifier and S256 code challenge.
 * Call this before redirecting the user to the authorize URL; pass the verifier when exchanging the code.
 *
 * @param length - Length of the random verifier (default 64).
 * @returns `{ codeVerifier, codeChallenge }` to use with `buildAuthorizeUrl` and `exchangeCodeForToken`.
 */
export async function createPkcePair(length = 64): Promise<PkcePair> {
  const crypto = getCrypto();
  const random = new Uint8Array(length);
  crypto.getRandomValues(random);
  const codeVerifier = Array.from(random)
    .map((b) => (b % 36).toString(36))
    .join("");

  const data = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const codeChallenge = base64UrlEncode(digest);

  return { codeVerifier, codeChallenge };
}

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

/**
 * Builds the authorization URL to send the user to for login.
 * Add optional state and PKCE from `createPkcePair` for security.
 *
 * @param config - Client config (clientId, redirectUri, optional endpoints and scopes).
 * @param params - Optional state, PKCE pair, and extra query params.
 * @returns Full URL to redirect the user to.
 */
export function buildAuthorizeUrl(
  config: OAuth2ClientConfig,
  params: AuthorizeUrlParams = {},
): string {
  const baseUrl = config.authorizeEndpoint ?? DEFAULT_AUTHORIZE_ENDPOINT;
  const url = new URL(baseUrl);

  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);

  if (config.scopes?.length) {
    url.searchParams.set("scope", config.scopes.join(" "));
  }
  if (params.state) {
    url.searchParams.set("state", params.state);
  }
  if (params.pkce) {
    url.searchParams.set("code_challenge", params.pkce.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
  }
  if (params.extraParams) {
    for (const [key, value] of Object.entries(params.extraParams)) {
      url.searchParams.set(key, value);
    }
  }

  return url.toString();
}

// ---------------------------------------------------------------------------
// Callback parsing
// ---------------------------------------------------------------------------

/** Query parameters parsed from the OAuth2 redirect callback URL. */
export interface ParsedCallback {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}

/**
 * Parses the redirect URL after the user returns from the authorization server.
 * Use this to read `code`, `state`, or `error` / `error_description`.
 *
 * @param urlLike - Full callback URL (e.g. `window.location.href` or the request URL on the server).
 * @returns Object with `code`, `state`, and optionally `error` / `error_description`.
 */
export function parseCallback(urlLike: string): ParsedCallback {
  const url = new URL(urlLike, "http://dummy");
  const p = url.searchParams;
  return {
    code: p.get("code") ?? undefined,
    state: p.get("state") ?? undefined,
    error: p.get("error") ?? undefined,
    error_description: p.get("error_description") ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// Token endpoint (server-side: code exchange and refresh)
// ---------------------------------------------------------------------------

/**
 * POSTs form body to the token endpoint and returns the JSON response.
 * Shared by authorization-code and refresh-token flows.
 */
async function postToTokenEndpoint(
  config: OAuth2ClientConfig,
  bodyParams: Record<string, string>,
): Promise<TokenResponse> {
  const endpoint = config.tokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT;
  const body = new URLSearchParams(bodyParams);

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token endpoint returned ${response.status}: ${text}`);
  }

  return (await response.json()) as TokenResponse;
}

/** Parameters for exchanging an authorization code for tokens. */
export interface ExchangeCodeParams {
  config: OAuth2ClientConfig;
  code: string;
  codeVerifier?: string;
  clientSecret?: string;
  extraParams?: Record<string, string>;
}

/**
 * Exchanges an authorization code for access token (and optional refresh token).
 * Call this on your server after the user returns with a `code` in the callback URL.
 *
 * @param params - Config, code, optional PKCE verifier, client secret, and extra form params.
 * @returns Token response including `access_token` and optionally `refresh_token`.
 */
export async function exchangeCodeForToken(params: ExchangeCodeParams): Promise<TokenResponse> {
  const { config, code, codeVerifier, clientSecret, extraParams = {} } = params;
  const body: Record<string, string> = {
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    ...extraParams,
  };
  if (codeVerifier) body.code_verifier = codeVerifier;
  if (clientSecret) body.client_secret = clientSecret;

  return postToTokenEndpoint(config, body);
}

/** Parameters for refreshing an access token. */
export interface RefreshTokenParams {
  config: OAuth2ClientConfig;
  refreshToken: string;
  clientSecret?: string;
  extraParams?: Record<string, string>;
}

/**
 * Exchanges a refresh token for a new access token (and optionally a new refresh token).
 * Call this on your server when the access token expires.
 *
 * @param params - Config, refresh token, optional client secret, and extra form params.
 * @returns New token response.
 */
export async function refreshAccessToken(params: RefreshTokenParams): Promise<TokenResponse> {
  const { config, refreshToken, clientSecret, extraParams = {} } = params;
  const body: Record<string, string> = {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: config.clientId,
    ...extraParams,
  };
  if (clientSecret) body.client_secret = clientSecret;

  return postToTokenEndpoint(config, body);
}
