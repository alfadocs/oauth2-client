/**
 * OAuth2 HTTP helpers — token exchange, refresh, and user info fetch.
 * All functions talk to the Alfadocs server via standard fetch().
 */

import type { AlfadocsUser, SessionData } from "./session";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
}

export interface ExchangeCodeParams {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
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
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: params.clientId,
    client_secret: params.clientSecret,
    redirect_uri: params.redirectUri,
    code: params.code,
    code_verifier: params.codeVerifier,
  });

  const res = await fetch(params.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(
      `[AlfadocsAuth] Token exchange failed (HTTP ${res.status}): ${detail}`,
    );
  }

  return res.json() as Promise<TokenResponse>;
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
): Promise<TokenResponse | null> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: params.clientId,
    client_secret: params.clientSecret,
    refresh_token: params.refreshToken,
  });

  const res = await fetch(params.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (res.status >= 400 && res.status < 500) {
    // Refresh token is invalid or revoked — signal caller to clear session
    return null;
  }

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(
      `[AlfadocsAuth] Token refresh failed (HTTP ${res.status}): ${detail}`,
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
): Promise<AlfadocsUser> {
  const res = await fetch(meUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(
      `[AlfadocsAuth] Failed to fetch user info (HTTP ${res.status}): ${detail}`,
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
