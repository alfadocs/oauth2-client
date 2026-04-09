/**
 * Persistence contract for `createAlfadocsAuth` (`storage` option).
 * Implement `AuthStorage` in a new module (e.g. `my-bridge`) to swap Supabase for another backend.
 */

export interface StoredUser {
  id: string;
  username: string;
  authData: Record<string, unknown>;
}

export interface StoredSession {
  userId: string;
  cookieValue: string;
}

export interface UserStore {
  getUser(userId: string): Promise<StoredUser | null>;
  /**
   * Creates a new user using a caller-provided canonical id.
   * Keeping the id explicit makes bridge implementations predictable.
   */
  createUser(userId: string, username: string, authData: Record<string, unknown>): Promise<StoredUser>;
  updateUser(
    userId: string,
    fieldsToUpdate: Partial<Pick<StoredUser, "username" | "authData">>,
  ): Promise<StoredUser>;
}

export interface SessionStore {
  createSession(userId: string): Promise<StoredSession>;
  getSession(cookieValue: string): Promise<StoredSession | null>;
}

export type AuthStorage = UserStore & SessionStore;
