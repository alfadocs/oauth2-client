export interface OAuth2ClientConfig {
  /**
   * Optional override for the authorization endpoint.
   * Defaults to production: https://app.alfadocs.com/oauth2/authorize
   */
  authorizeEndpoint?: string;
  /**
   * Optional override for the token endpoint.
   * Defaults to production: https://app.alfadocs.com/oauth2/token
   */
  tokenEndpoint?: string;
  clientId: string;
  redirectUri: string;
  scopes?: string[];         // e.g. ["patient:view"]
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
}

export interface AuthorizeUrlParams {
  state?: string;
  pkce?: PkcePair;
  extraParams?: Record<string, string>;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  [key: string]: unknown;
}

// --- Defaults for production AlfaDocs environment ---

export const DEFAULT_AUTHORIZE_ENDPOINT = "https://app.alfadocs.com/oauth2/authorize";
export const DEFAULT_TOKEN_ENDPOINT = "https://app.alfadocs.com/oauth2/token";

// --- PKCE helpers (browser) ---
function getCrypto(): Crypto {
  // Works in both browser and Node 18+ (Web Crypto on globalThis)
  if (typeof globalThis !== "undefined" && (globalThis as any).crypto) {
    return (globalThis as any).crypto as Crypto;
  }
  throw new Error(
    "globalThis.crypto is not available; PKCE helpers require a browser or a crypto polyfill",
  );
}

function base64UrlEncode(bytes: ArrayBuffer): string {
  let base64: string;

  if (typeof btoa === "function") {
    const binary = String.fromCharCode(...new Uint8Array(bytes));
    base64 = btoa(binary);
  } else if (typeof Buffer !== "undefined") {
    // Node.js / environments with Buffer available
    // eslint-disable-next-line no-undef
    base64 = Buffer.from(bytes).toString("base64");
  } else {
    throw new Error("No base64 encoder available for PKCE code challenge.");
  }

  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function createPkcePair(length = 64): Promise<PkcePair> {
  const crypto = getCrypto();
  const random = new Uint8Array(length);
  crypto.getRandomValues(random);
  const codeVerifier = Array.from(random)
    .map(b => (b % 36).toString(36))
    .join("");

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const codeChallenge = base64UrlEncode(digest);

  return { codeVerifier, codeChallenge };
}

// --- Authorization URL builder ---

export function buildAuthorizeUrl(
  config: OAuth2ClientConfig,
  params: AuthorizeUrlParams = {}
): string {
  const url = new URL(config.authorizeEndpoint ?? DEFAULT_AUTHORIZE_ENDPOINT);

  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);

  if (config.scopes && config.scopes.length > 0) {
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

// --- Callback parser ---

export interface ParsedCallback {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}

export function parseCallback(urlLike: string): ParsedCallback {
  const url = new URL(urlLike, "http://dummy");
  const params = url.searchParams;

  const result: ParsedCallback = {};

  if (params.has("code")) {
    result.code = params.get("code") || undefined;
  }
  if (params.has("state")) {
    result.state = params.get("state") || undefined;
  }
  if (params.has("error")) {
    result.error = params.get("error") || undefined;
    result.error_description = params.get("error_description") || undefined;
  }

  return result;
}

// --- Token exchange ---

export interface ExchangeCodeParams {
  config: OAuth2ClientConfig;
  code: string;
  codeVerifier?: string; // required when using PKCE
  clientSecret?: string; // only for confidential clients
  extraParams?: Record<string, string>;
}

export async function exchangeCodeForToken({
  config,
  code,
  codeVerifier,
  clientSecret,
  extraParams = {},
}: ExchangeCodeParams): Promise<TokenResponse> {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", config.redirectUri);
  body.set("client_id", config.clientId);

  if (codeVerifier) {
    body.set("code_verifier", codeVerifier);
  }

  if (clientSecret) {
    body.set("client_secret", clientSecret);
  }

  for (const [key, value] of Object.entries(extraParams)) {
    body.set(key, value);
  }

  const tokenEndpoint = config.tokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT;

  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body.toString(),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Token endpoint returned ${response.status}: ${text}`);
  }

  return (await response.json()) as TokenResponse;
}

