// Small helpers shared by the auth factory. Split out so `auth.ts` stays mostly flow wiring.

// We persist a username for quick display/search; this fallback chain avoids rejecting
// valid logins when the provider profile shape differs across environments.
export function inferUsername(user: Record<string, unknown>): string {
  const fromEmail = user.email;
  if (typeof fromEmail === "string" && fromEmail.length > 0) return fromEmail;
  const fromName = user.name;
  if (typeof fromName === "string" && fromName.length > 0) return fromName;
  const fromId = user.id;
  if (typeof fromId === "string" && fromId.length > 0) return fromId;
  if (typeof fromId === "number") return String(fromId);
  return "unknown";
}

// Build a stable user id from provider profile data when available.
// Keeping this in one place avoids subtle id-shape drift between call sites.
export function inferUserId(profile: Record<string, unknown>): string {
  const profileId = profile.id;
  if (typeof profileId === "string" && profileId.length > 0) return profileId;
  if (typeof profileId === "number") return String(profileId);
  return "";
}

// Convert unknown thrown values into readable API errors for operators and clients.
// This prevents opaque outputs like "[object Object]" in auth responses.
export function formatUnknownError(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  if (err && typeof err === "object") {
    const maybe = err as {
      message?: unknown;
      code?: unknown;
      details?: unknown;
      hint?: unknown;
    };
    const message = typeof maybe.message === "string" ? maybe.message : "";
    const code = typeof maybe.code === "string" ? maybe.code : "";
    const details = typeof maybe.details === "string" ? maybe.details : "";
    const hint = typeof maybe.hint === "string" ? maybe.hint : "";
    const joined = [code, message, details, hint].filter(Boolean).join(" | ");
    if (joined) return joined;
    try {
      return JSON.stringify(err);
    } catch {
      return String(err);
    }
  }
  return String(err);
}

function normalizeScopeList(value: string[] | string): string[] {
  return (Array.isArray(value) ? value : [value]).map((v) => v.trim()).filter(Boolean);
}

// Alfadocs expects `oauth_token_scopes` as a single string in array-like format.
export function appendOauthTokenScopes(params: URLSearchParams, key: string, value: string[] | string): void {
  const clean = normalizeScopeList(value);
  if (clean.length === 0) return;
  const encoded = `['${clean.join("','")}']`;
  params.set(key, encoded);
}
