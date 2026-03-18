/**
 * Cookie parsing and serialization — pure string manipulation, no DOM dependency.
 */

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  /** SameSite=None requires Secure=true — caller is responsible for this invariant. */
  sameSite?: "Strict" | "Lax" | "None";
  path?: string;
  /** Max-Age in seconds. Set to 0 to delete the cookie. */
  maxAge?: number;
  domain?: string;
}

/**
 * Parses the `Cookie` request header into a name → value map.
 * Handles values that contain `=` (e.g. base64) by splitting only on the first `=`.
 */
export function parseCookies(cookieHeader: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of cookieHeader.split(";")) {
    const eqIndex = part.indexOf("=");
    if (eqIndex === -1) continue;
    const key = part.slice(0, eqIndex).trim();
    const value = part.slice(eqIndex + 1).trim();
    if (key) result[key] = value;
  }
  return result;
}

/**
 * Serializes a `Set-Cookie` header value.
 * Defaults `Path=/` so the cookie is sent on all paths under the domain.
 */
export function serializeCookie(
  name: string,
  value: string,
  options: CookieOptions = {},
): string {
  const parts: string[] = [`${name}=${value}`];
  parts.push(`Path=${options.path ?? "/"}`);
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.domain !== undefined) parts.push(`Domain=${options.domain}`);
  if (options.sameSite !== undefined) parts.push(`SameSite=${options.sameSite}`);
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  return parts.join("; ");
}
