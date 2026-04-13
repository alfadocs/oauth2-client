/**
 * OAuth2 HTTP helpers — token exchange, refresh, and user info fetch.
 * All functions talk to the Alfadocs server via standard fetch().
 */

import { decodeJwt } from "jose";
import type { AlfadocsUser, SessionData } from "./session.js";

/** Pull a readable message from OAuth token error payloads (JSON or form). */
function formatTokenErrorBody(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "(empty response body — check client_id, client_secret, redirect_uri, and token endpoint URL)";
  try {
    const parsedJson = JSON.parse(trimmed) as {
      error?: string;
      error_description?: string;
      message?: string;
    };
    if (parsedJson.error_description) return `${parsedJson.error ?? "error"}: ${parsedJson.error_description}`;
    if (parsedJson.error) return parsedJson.error;
    if (parsedJson.message) return parsedJson.message;
  } catch {
    /* not JSON */
  }
  try {
    const formParams = new URLSearchParams(trimmed);
    const errorCode = formParams.get("error");
    const errorDescription = formParams.get("error_description");
    if (errorCode && errorDescription) return `${errorCode}: ${errorDescription}`;
    if (errorCode) return errorCode;
  } catch {
    /* ignore */
  }
  return trimmed;
}

/** Shorten HTML error pages and hint when /me rejects the token for scope reasons. */
function formatMeEndpointError(status: number, raw: string): string {
  const trimmed = raw.trim();
  const scopeHint =
    /scopes are empty|Invalid access token/i.test(trimmed)
      ? "If the client only registers `patient:list`, the token should include it — check Alfadocs links `/api/v1/me` to that scope and that the token response carries scopes. "
      : "";
  const snippet =
    trimmed.length > 480 ? `${trimmed.slice(0, 480)}…` : trimmed;
  return `${scopeHint}(HTTP ${status}) ${snippet}`;
}

/**
 * Read space-separated scopes from a JWT access token payload, if present.
 * Uses `jose` decode only — no signature verification (appropriate for filling `scope`
 * when the token response JSON omits it; verification belongs in future dedicated APIs).
 */
function tryScopesFromJwtAccessToken(accessToken: string): string | undefined {
  try {
    const payload = decodeJwt(accessToken) as {
      scope?: unknown;
      scp?: unknown;
    };
    if (typeof payload.scope === "string") return payload.scope;
    if (Array.isArray(payload.scope)) return payload.scope.join(" ");
    if (typeof payload.scp === "string") return payload.scp;
    if (Array.isArray(payload.scp)) return payload.scp.join(" ");
  } catch {
    /* opaque token or malformed JWT */
  }
  return undefined;
}

// Normalize low-level fetch failures so callers always get URL + root cause context.
function wrapFetchFailure(label: string, url: string, err: unknown): Error {
  const msg = err instanceof Error ? err.message : String(err);
  const errWithCause = err instanceof Error && "cause" in err ? err.cause : undefined;
  const causePart =
    errWithCause instanceof Error
      ? errWithCause.message
      : errWithCause != null
        ? String(errWithCause)
        : "";
  const detail = causePart ? `${msg}; cause: ${causePart}` : msg;
  return new Error(`[AlfadocsAuth] ${label} — ${url} — ${detail}`);
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  /** Space-separated scopes returned by the token endpoint, when present. */
  scope?: string;
}

export interface ExchangeCodeParams {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
  /**
   * Scopes from the authorize step. When non-empty, sends standard OAuth `scope` (space-separated)
   * and Alfadocs `oauth_scope_list` as a bracket string, e.g. `['a','b']`.
   */
  scopes?: string[];
}

export interface RefreshTokenParams {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}

// ─── Functions ────────────────────────────────────────────────────────────────

/**
 * Exchanges an authorization code for an access token + optional refresh token.
 * Throws with a descriptive message on HTTP errors.
 */
export async function exchangeCodeForToken(
  params: ExchangeCodeParams,
  fetchImpl: typeof globalThis.fetch = (input, init) => globalThis.fetch(input, init),
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    redirect_uri: params.redirectUri,
    code: params.code,
    code_verifier: params.codeVerifier,
    // We intentionally keep credentials in the body to match Alfadocs' working integration.
    client_id: params.clientId,
    client_secret: params.clientSecret,
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };

  const scopeList = params.scopes?.map((s) => s.trim()).filter(Boolean) ?? [];
  if (scopeList.length > 0) {
    body.set("scope", scopeList.join(" "));
    body.set("oauth_scope_list", `['${scopeList.join("','")}']`);
  }

  let res: Response;
  try {
    res = await fetchImpl(params.tokenUrl, {
      method: "POST",
      headers,
      body: body.toString(),
    });
  } catch (err) {
    throw wrapFetchFailure("Token exchange (network)", params.tokenUrl, err);
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(
      `[AlfadocsAuth] Token exchange failed (HTTP ${res.status}): ${formatTokenErrorBody(detail)}`,
    );
  }

  const json = (await res.json()) as TokenResponse;
  if (json.scope === undefined || json.scope === "") {
    const fromJwt = tryScopesFromJwtAccessToken(json.access_token);
    if (fromJwt) json.scope = fromJwt;
  }
  return json;
}

/**
 * Refreshes an expired access token using the stored refresh token.
 *
 * Returns `null` if the refresh token is invalid or revoked (HTTP 4xx) —
 * the caller should clear the session.
 * Throws on server errors (5xx) or network failures — the caller should
 * keep the current session intact and retry later.
 */
export async function refreshAccessToken(
  params: RefreshTokenParams,
  fetchImpl: typeof globalThis.fetch = (input, init) => globalThis.fetch(input, init),
): Promise<TokenResponse | null> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: params.refreshToken,
    // Keep the same credential style used by code exchange for consistency.
    client_id: params.clientId,
    client_secret: params.clientSecret,
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };

  let res: Response;
  try {
    res = await fetchImpl(params.tokenUrl, {
      method: "POST",
      headers,
      body: body.toString(),
    });
  } catch (err) {
    throw wrapFetchFailure("Token refresh (network)", params.tokenUrl, err);
  }

  if (res.status >= 400 && res.status < 500) {
    // Refresh token is invalid or revoked — signal caller to clear session
    return null;
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(
      `[AlfadocsAuth] Token refresh failed (HTTP ${res.status}): ${formatTokenErrorBody(detail)}`,
    );
  }

  return res.json() as Promise<TokenResponse>;
}

/**
 * Fetches the current user's profile from the Alfadocs /api/v1/me endpoint.
 * Throws on failure.
 */
export async function fetchUserInfo(
  meUrl: string,
  accessToken: string,
  fetchImpl: typeof globalThis.fetch = (input, init) => globalThis.fetch(input, init),
): Promise<AlfadocsUser> {
  let res: Response;
  try {
    res = await fetchImpl(meUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });
  } catch (err) {
    throw wrapFetchFailure("User info (network)", meUrl, err);
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(
      `[AlfadocsAuth] Failed to fetch user info: ${formatMeEndpointError(res.status, detail)}`,
    );
  }

  return res.json() as Promise<AlfadocsUser>;
}

/**
 * Builds a `SessionData` object from a token response and user info.
 * `expiresAt` is computed as `Date.now() + expires_in * 1000` (epoch ms).
 */
export function buildSessionData(
  tokens: TokenResponse,
  user: AlfadocsUser,
): SessionData {
  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token ?? null,
    expiresAt: Date.now() + (tokens.expires_in ?? 3600) * 1000,
    user,
  };
}
