import type { AuthStorage, StoredSession, StoredUser } from "../core/storage.js";

/** PostgREST resource names; must match `supabase/migrations` DDL for `alfa_*` tables. */
const USERS_TABLE = "alfa_users";
const SESSIONS_TABLE = "alfa_sessions";

/** Isolates rows per app when many tenants share one auth Supabase project. */
function validateAppId(value: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/.test(value)) {
    throw new Error(
      `[AlfadocsAuth] Invalid appId (use 1–128 chars: letters, digits, _, ., :, -): ${value}`,
    );
  }
}

function appIdEq(appId: string): string {
  return `app_id=eq.${encodeURIComponent(appId)}`;
}

export interface SupabaseStorageConfig {
  /** Project URL, e.g. from env `AUTH_SUPABASE_URL` when auth lives in a dedicated Supabase project. */
  supabaseUrl: string;
  /** Service role JWT (server-side only), e.g. from env `AUTH_SUPABASE_KEY`. */
  serviceRoleKey: string;
  /**
   * Tenant / app scope for shared auth storage (matches column `app_id`).
   * Use a stable id per Lovable project or deployment (e.g. from env `AUTH_APP_ID`).
   */
  appId: string;
  schema?: string;
  /** HTTP client for Supabase REST. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
}

interface PostgrestError {
  message?: string;
  code?: string;
}

// Centralize common headers so every request uses the same auth/profile context.
// This avoids subtle bugs where a single call accidentally targets another schema.
function buildHeaders(serviceRoleKey: string, schema: string): HeadersInit {
  return {
    apikey: serviceRoleKey,
    Authorization: `Bearer ${serviceRoleKey}`,
    "Content-Type": "application/json",
    Accept: "application/json",
    Prefer: "return=representation",
    "Accept-Profile": schema,
    "Content-Profile": schema,
  };
}

// Normalize Supabase HTTP error payloads to a predictable shape.
// Keeping this helper small makes higher-level retries and messages consistent.
async function parseError(res: Response): Promise<PostgrestError> {
  const text = await res.text();
  try {
    return JSON.parse(text) as PostgrestError;
  } catch {
    return { message: text || `HTTP ${res.status} ${res.statusText}` };
  }
}

// Preserve useful network diagnostics (including nested cause) for Supabase requests.
function wrapSupabaseNetworkError(url: string, err: unknown): Error {
  const msg = err instanceof Error ? err.message : String(err);
  const errWithCause = err instanceof Error && "cause" in err ? err.cause : undefined;
  const causePart =
    errWithCause instanceof Error
      ? errWithCause.message
      : errWithCause != null
        ? String(errWithCause)
        : "";
  const detail = causePart ? `${msg}; cause: ${causePart}` : msg;
  return new Error(`[AlfadocsAuth] Supabase request failed — ${url} — ${detail}`);
}

// Factory keeps Supabase details behind the AuthStorage contract so the core auth flow
// stays infrastructure-agnostic and bridges can be swapped later.
export function createSupabaseStorage(config: SupabaseStorageConfig): AuthStorage {
  const schema = config.schema ?? "public";
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(schema)) {
    throw new Error(`[AlfadocsAuth] Invalid schema identifier: ${schema}`);
  }
  validateAppId(config.appId);
  const appId = config.appId;
  const baseUrl = config.supabaseUrl.replace(/\/$/, "");
  const headers = buildHeaders(config.serviceRoleKey, schema);
  const httpFetch: typeof globalThis.fetch =
    config.fetch ??
    ((input, init) => globalThis.fetch(input, init));

  // Thin HTTP wrapper for PostgREST to enforce shared headers/error handling.
  // This avoids duplicating request plumbing in each storage operation.
  async function postgrest<T>(path: string, init: RequestInit): Promise<T> {
    const url = `${baseUrl}/rest/v1/${path}`;
    let res: Response;
    try {
      res = await httpFetch(url, {
        ...init,
        headers: { ...headers, ...(init.headers ?? {}) },
      });
    } catch (err) {
      throw wrapSupabaseNetworkError(url, err);
    }
    if (!res.ok) {
      throw await parseError(res);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  return {
    // Read-first lookup keeps session checks cheap and idempotent.
    async getUser(userId: string): Promise<StoredUser | null> {
      const data = await postgrest<Array<{ id: string; username: string; auth_data: Record<string, unknown> }>>(
        `${USERS_TABLE}?${appIdEq(appId)}&id=eq.${encodeURIComponent(userId)}&select=id,username,auth_data&limit=1`,
        { method: "GET", headers: { Prefer: "" } },
      );
      const row = data[0];
      if (!row) return null;
      return { id: row.id, username: row.username, authData: row.auth_data ?? {} };
    },

    // Keep identity explicit: caller chooses the stable user id persisted in storage.
    async createUser(
      userId: string,
      username: string,
      authData: Record<string, unknown>,
    ): Promise<StoredUser> {
      const rows = await postgrest<
        Array<{ id: string; username: string; auth_data: Record<string, unknown> }>
      >(USERS_TABLE, {
        method: "POST",
        body: JSON.stringify([{ app_id: appId, id: userId, username, auth_data: authData }]),
      });
      const row = rows[0];
      return { id: row.id, username: row.username, authData: row.auth_data ?? {} };
    },

    // Partial update minimizes write scope and lets callers update only changed fields.
    async updateUser(
      userId: string,
      fieldsToUpdate: Partial<Pick<StoredUser, "username" | "authData">>,
    ): Promise<StoredUser> {
      const patch: Record<string, unknown> = {};
      if (fieldsToUpdate.username !== undefined) patch.username = fieldsToUpdate.username;
      if (fieldsToUpdate.authData !== undefined) patch.auth_data = fieldsToUpdate.authData;
      const rows = await postgrest<
        Array<{ id: string; username: string; auth_data: Record<string, unknown> }>
      >(`${USERS_TABLE}?${appIdEq(appId)}&id=eq.${encodeURIComponent(userId)}`, {
        method: "PATCH",
        body: JSON.stringify(patch),
      });
      const row = rows[0];
      return { id: row.id, username: row.username, authData: row.auth_data ?? {} };
    },

    // Use opaque random cookie values so session identifiers are unguessable.
    async createSession(userId: string): Promise<StoredSession> {
      const cookieValue = crypto.randomUUID();
      const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
      const expiresAtIso = new Date(expiresAt).toISOString();
      const rows = await postgrest<Array<{ cookie_value: string; user_id: string; expires_at: string }>>(
        SESSIONS_TABLE,
        {
          method: "POST",
          body: JSON.stringify([
            { app_id: appId, cookie_value: cookieValue, user_id: userId, expires_at: expiresAtIso },
          ]),
        },
      );
      const row = rows[0];
      return {
        cookieValue: row.cookie_value,
        userId: row.user_id,
        expiresAt: Date.parse(row.expires_at),
      };
    },

    // Resolve cookie -> session mapping without exposing user details at this layer.
    // Core auth can then fetch user data separately through the UserStore contract.
    async getSession(cookieValue: string): Promise<StoredSession | null> {
      const nowIso = new Date().toISOString();
      const rows = await postgrest<Array<{ cookie_value: string; user_id: string; expires_at: string }>>(
        `${SESSIONS_TABLE}?${appIdEq(appId)}&cookie_value=eq.${encodeURIComponent(cookieValue)}&expires_at=gt.${encodeURIComponent(nowIso)}&select=cookie_value,user_id,expires_at&limit=1`,
        { method: "GET", headers: { Prefer: "" } },
      );
      const row = rows[0];
      if (!row) return null;
      return {
        cookieValue: row.cookie_value,
        userId: row.user_id,
        expiresAt: Date.parse(row.expires_at),
      };
    },
    // Explicit session deletion allows logout to invalidate server state (not only browser cookie).
    async deleteSession(cookieValue: string): Promise<void> {
      await postgrest<void>(
        `${SESSIONS_TABLE}?${appIdEq(appId)}&cookie_value=eq.${encodeURIComponent(cookieValue)}`,
        { method: "DELETE", headers: { Prefer: "" } },
      );
    },
  };
}
