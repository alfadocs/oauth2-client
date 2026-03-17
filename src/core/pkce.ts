/**
 * PKCE helpers — pure crypto, no I/O.
 * Uses the Web Crypto API (crypto.subtle), available in Deno, Service Workers,
 * and Supabase Edge Functions.
 */

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export interface PkceResult {
  verifier: string;
  challenge: string;
}

/**
 * Generates a PKCE verifier (64 random bytes, base64url-encoded) and its
 * SHA-256 challenge. Both are required for the OAuth2 PKCE flow.
 *
 * The verifier stays server-side (in the pre-auth cookie).
 * The challenge is sent to the Alfadocs authorization endpoint.
 */
export async function generatePkce(): Promise<PkceResult> {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  const verifier = base64UrlEncode(bytes.buffer as ArrayBuffer);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return { verifier, challenge: base64UrlEncode(digest) };
}

/**
 * Generates a cryptographically random state string (16 bytes, base64url).
 * Used to bind the authorization request to the callback and prevent CSRF.
 */
export function generateState(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes.buffer as ArrayBuffer);
}
