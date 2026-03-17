/**
 * Session and pre-auth data types + cookie encode/decode helpers.
 *
 * Session cookie  (`alfadocs_session`) — long-lived, stores tokens + user.
 * Pre-auth cookie (`alfadocs_preauth`) — short-lived (10 min), stores PKCE
 *   verifier + state between /login and /callback.
 *
 * Both are stored as URI-encoded JSON. No encryption — the cookies are
 * httpOnly so JavaScript cannot read them, and HTTPS prevents interception.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

/** Alfadocs user info returned by /api/v1/me */
export interface AlfadocsUser {
  id?: string | number;
  email?: string;
  name?: string;
  /** Any additional fields returned by the API */
  [key: string]: unknown;
}

/** Payload stored in the long-lived session cookie */
export interface SessionData {
  accessToken: string;
  refreshToken: string | null;
  /** Unix epoch milliseconds when the access token expires */
  expiresAt: number;
  user: AlfadocsUser;
}

/** Payload stored in the short-lived pre-auth cookie (set in /login, read in /callback) */
export interface PreAuthData {
  codeVerifier: string;
  state: string;
}

// ─── Session encode / decode ──────────────────────────────────────────────────

export function encodeSession(data: SessionData): string {
  return encodeURIComponent(JSON.stringify(data));
}

/**
 * Decodes a session cookie value. Returns `null` on any parse or
 * structural validation failure — callers treat this as unauthenticated.
 */
export function decodeSession(raw: string): SessionData | null {
  try {
    const parsed = JSON.parse(decodeURIComponent(raw));
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      typeof parsed.accessToken !== "string" ||
      typeof parsed.expiresAt !== "number" ||
      typeof parsed.user !== "object" ||
      parsed.user === null
    ) {
      return null;
    }
    return parsed as SessionData;
  } catch {
    return null;
  }
}

// ─── Pre-auth encode / decode ─────────────────────────────────────────────────

export function encodePreAuth(data: PreAuthData): string {
  return encodeURIComponent(JSON.stringify(data));
}

/**
 * Decodes a pre-auth cookie value. Returns `null` on any failure —
 * callers treat this as a missing/expired pre-auth state.
 */
export function decodePreAuth(raw: string): PreAuthData | null {
  try {
    const parsed = JSON.parse(decodeURIComponent(raw));
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      typeof parsed.codeVerifier !== "string" ||
      typeof parsed.state !== "string"
    ) {
      return null;
    }
    return parsed as PreAuthData;
  } catch {
    return null;
  }
}
