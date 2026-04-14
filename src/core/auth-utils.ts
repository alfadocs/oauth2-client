// Small helpers shared by the auth factory. Split out so `auth.ts` stays mostly flow wiring.

function asRecord(v: unknown): Record<string, unknown> | null {
  if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
  return null;
}

function pickUserId(o: Record<string, unknown>): string {
  const v = o.userId;
  if (typeof v === "string" && v.trim().length > 0) return v.trim();
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return "";
}

// We persist a username for quick display/search; this fallback chain avoids rejecting
// valid logins when the provider profile shape differs across environments.
export function inferUsername(user: Record<string, unknown>): string {
  const fromEmail = user.email;
  if (typeof fromEmail === "string" && fromEmail.length > 0) return fromEmail;
  const data = asRecord(user.data);
  if (data) {
    const userEmail = data.userEmail;
    if (typeof userEmail === "string" && userEmail.length > 0) return userEmail;
    const ownerEmail = data.ownerEmail;
    if (typeof ownerEmail === "string" && ownerEmail.length > 0) return ownerEmail;
  }
  const fromName = user.name;
  if (typeof fromName === "string" && fromName.length > 0) return fromName;
  const nestedId = data ? pickUserId(data) : "";
  if (nestedId) return nestedId;
  return pickUserId(user) || "unknown";
}

/** Alfadocs `/api/v1/me` wraps the payload in `{ status, data: { userId, ... } }`. */
export function userIdFromProfile(profile: Record<string, unknown>): string {
  const data = asRecord(profile.data);
  if (data) {
    const id = pickUserId(data);
    if (id) return id;
  }
  return pickUserId(profile);
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
