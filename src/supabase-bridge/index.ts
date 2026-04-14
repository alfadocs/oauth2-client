import type { AuthStorage, StoredSession, StoredUser } from "../core/storage.js";
import { readFile } from "node:fs/promises";

export interface SupabaseStorageConfig {
  supabaseUrl: string;
  serviceRoleKey: string;
  /**
   * Required direct Postgres connection string for automatic migrations.
   * Example: postgresql://postgres:<password>@db.<project-ref>.supabase.co:5432/postgres
   */
  databaseUrl: string;
  schema?: string;
  /** HTTP client for Supabase REST + migration calls. Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
}

interface PostgrestError {
  message?: string;
  code?: string;
}

// Allow only simple SQL identifiers before interpolation in migration DDL.
// This keeps dynamic schema support without opening SQL injection risk.
function quoteIdentifier(value: string): string {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error(`[AlfadocsAuth] Invalid schema identifier: ${value}`);
  }
  return `"${value}"`;
}

const MIGRATION_FILE_URLS: URL[] = [
  new URL("./migrations/001_create_users.sql", import.meta.url),
  new URL("./migrations/002_create_sessions.sql", import.meta.url),
];

// Load SQL from migration files so DDL has a single source of truth.
// Schema is applied dynamically by replacing `public.` references in the file.
async function loadMigrations(schema: string): Promise<string[]> {
  const schemaQualified = `${quoteIdentifier(schema)}.`;
  const queries: string[] = [];
  for (const fileUrl of MIGRATION_FILE_URLS) {
    const sql = await readFile(fileUrl, "utf8");
    queries.push(sql.replaceAll("public.", schemaQualified));
  }
  return queries;
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

// Restrict optimistic migration triggers to "table/relation missing" failures.
// We intentionally avoid broad matching so application/data errors are surfaced immediately.
function isMissingTableError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const maybe = error as PostgrestError;
  if (maybe.code === "42P01") return true;
  if (maybe.code === "PGRST205") return true;
  const msg = maybe.message ?? "";
  return (
    (msg.includes("relation") && msg.includes("does not exist")) ||
    (msg.includes("Could not find the table") && msg.includes("schema cache"))
  );
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
  const baseUrl = config.supabaseUrl.replace(/\/$/, "");
  const headers = buildHeaders(config.serviceRoleKey, schema);
  const httpFetch: typeof globalThis.fetch =
    config.fetch ??
    ((input, init) => globalThis.fetch(input, init));

  let migrationPromise: Promise<void> | null = null;

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

  // Apply bridge-owned schema migrations in sequence.
  // Ordered execution keeps cross-table dependencies deterministic.
  async function runMigrations(): Promise<void> {
    try {
      const postgresModule = await import("postgres");
      const postgres = (postgresModule as { default: (url: string, opts?: unknown) => any }).default;
      const sql = postgres(config.databaseUrl, { ssl: "require" });
      try {
        const migrations = await loadMigrations(schema);
        for (const query of migrations) {
          await sql.unsafe(query);
        }
        // Ask PostgREST to refresh schema cache after DDL.
        await sql.unsafe("NOTIFY pgrst, 'reload schema'");
      } finally {
        await sql.end({ timeout: 5 });
      }
      return;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `[AlfadocsAuth] Failed running migrations via databaseUrl: ${msg}`,
      );
    }
  }

  // Deduplicate concurrent migration attempts within this process.
  // Without this guard, parallel requests could stampede the migration endpoint.
  async function ensureMigrations(): Promise<void> {
    if (!migrationPromise) {
      migrationPromise = runMigrations().finally(() => {
        migrationPromise = null;
      });
    }
    await migrationPromise;
  }

  // Optimistic strategy: run normal operation first for the fast path.
  // Only if schema is missing do we migrate once and retry transparently.
  async function withOptimisticMigrations<T>(op: () => Promise<T>): Promise<T> {
    try {
      return await op();
    } catch (err) {
      if (!isMissingTableError(err)) throw err;
      await ensureMigrations();
      // PostgREST schema cache can lag shortly after DDL; retry with small backoff.
      const RETRY_DELAYS_MS = [0, 120, 300, 700];
      let lastError: unknown = err;
      for (const delayMs of RETRY_DELAYS_MS) {
        if (delayMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, delayMs));
        }
        try {
          return await op();
        } catch (retryErr) {
          lastError = retryErr;
          if (!isMissingTableError(retryErr)) throw retryErr;
        }
      }
      throw lastError;
    }
  }

  return {
    // Read-first lookup keeps session checks cheap and idempotent.
    async getUser(userId: string): Promise<StoredUser | null> {
      return withOptimisticMigrations(async () => {
        const data = await postgrest<Array<{ id: string; username: string; auth_data: Record<string, unknown> }>>(
          `users?id=eq.${encodeURIComponent(userId)}&select=id,username,auth_data&limit=1`,
          { method: "GET", headers: { Prefer: "" } },
        );
        const row = data[0];
        if (!row) return null;
        return { id: row.id, username: row.username, authData: row.auth_data ?? {} };
      });
    },

    // Keep identity explicit: caller chooses the stable user id persisted in storage.
    async createUser(
      userId: string,
      username: string,
      authData: Record<string, unknown>,
    ): Promise<StoredUser> {
      return withOptimisticMigrations(async () => {
        const rows = await postgrest<
          Array<{ id: string; username: string; auth_data: Record<string, unknown> }>
        >("users", {
          method: "POST",
          body: JSON.stringify([{ id: userId, username, auth_data: authData }]),
        });
        const row = rows[0];
        return { id: row.id, username: row.username, authData: row.auth_data ?? {} };
      });
    },

    // Partial update minimizes write scope and lets callers update only changed fields.
    async updateUser(
      userId: string,
      fieldsToUpdate: Partial<Pick<StoredUser, "username" | "authData">>,
    ): Promise<StoredUser> {
      return withOptimisticMigrations(async () => {
        const patch: Record<string, unknown> = {};
        if (fieldsToUpdate.username !== undefined) patch.username = fieldsToUpdate.username;
        if (fieldsToUpdate.authData !== undefined) patch.auth_data = fieldsToUpdate.authData;
        const rows = await postgrest<
          Array<{ id: string; username: string; auth_data: Record<string, unknown> }>
        >(`users?id=eq.${encodeURIComponent(userId)}`, {
          method: "PATCH",
          body: JSON.stringify(patch),
        });
        const row = rows[0];
        return { id: row.id, username: row.username, authData: row.auth_data ?? {} };
      });
    },

    // Use opaque random cookie values so session identifiers are unguessable.
    async createSession(userId: string): Promise<StoredSession> {
      return withOptimisticMigrations(async () => {
        const cookieValue = crypto.randomUUID();
        const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
        const expiresAtIso = new Date(expiresAt).toISOString();
        const rows = await postgrest<Array<{ cookie_value: string; user_id: string; expires_at: string }>>(
          "sessions",
          {
            method: "POST",
            body: JSON.stringify([
              { cookie_value: cookieValue, user_id: userId, expires_at: expiresAtIso },
            ]),
          },
        );
        const row = rows[0];
        return {
          cookieValue: row.cookie_value,
          userId: row.user_id,
          expiresAt: Date.parse(row.expires_at),
        };
      });
    },

    // Resolve cookie -> session mapping without exposing user details at this layer.
    // Core auth can then fetch user data separately through the UserStore contract.
    async getSession(cookieValue: string): Promise<StoredSession | null> {
      return withOptimisticMigrations(async () => {
        const nowIso = new Date().toISOString();
        const rows = await postgrest<Array<{ cookie_value: string; user_id: string; expires_at: string }>>(
          `sessions?cookie_value=eq.${encodeURIComponent(cookieValue)}&expires_at=gt.${encodeURIComponent(nowIso)}&select=cookie_value,user_id,expires_at&limit=1`,
          { method: "GET", headers: { Prefer: "" } },
        );
        const row = rows[0];
        if (!row) return null;
        return {
          cookieValue: row.cookie_value,
          userId: row.user_id,
          expiresAt: Date.parse(row.expires_at),
        };
      });
    },
    // Explicit session deletion allows logout to invalidate server state (not only browser cookie).
    async deleteSession(cookieValue: string): Promise<void> {
      await withOptimisticMigrations(async () => {
        await postgrest<void>(
          `sessions?cookie_value=eq.${encodeURIComponent(cookieValue)}`,
          { method: "DELETE", headers: { Prefer: "" } },
        );
      });
    },
  };
}
