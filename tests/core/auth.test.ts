import { describe, expect, it, vi, afterEach } from "vitest";
import { inferUsername, userIdFromProfile } from "../../src/core/auth-utils.js";
import { createAlfadocsAuth } from "../../src/core/auth.js";
import { encodePreAuth } from "../../src/core/session.js";
import type { AuthStorage, StoredSession, StoredUser } from "../../src/core/storage.js";

function createStorageMock(): AuthStorage {
  const users = new Map<string, StoredUser>();
  const sessions = new Map<string, StoredSession>();

  return {
    async getUser(userId: string): Promise<StoredUser | null> {
      return users.get(userId) ?? null;
    },
    async createUser(
      userId: string,
      username: string,
      authData: Record<string, unknown>,
    ): Promise<StoredUser> {
      const user = { id: userId, username, authData };
      users.set(userId, user);
      return user;
    },
    async updateUser(
      userId: string,
      fieldsToUpdate: Partial<Pick<StoredUser, "username" | "authData">>,
    ): Promise<StoredUser> {
      const existing = users.get(userId);
      if (!existing) throw new Error("missing user");
      const updated: StoredUser = {
        ...existing,
        username: fieldsToUpdate.username ?? existing.username,
        authData: fieldsToUpdate.authData ?? existing.authData,
      };
      users.set(userId, updated);
      return updated;
    },
    async createSession(userId: string): Promise<StoredSession> {
      const session = {
        userId,
        cookieValue: `cookie-${userId}`,
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      };
      sessions.set(session.cookieValue, session);
      return session;
    },
    async getSession(cookieValue: string): Promise<StoredSession | null> {
      return sessions.get(cookieValue) ?? null;
    },
    async deleteSession(cookieValue: string): Promise<void> {
      sessions.delete(cookieValue);
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("userIdFromProfile / inferUsername", () => {
  it("reads userId and userEmail from { status, data } payloads", () => {
    const profile = {
      status: "success",
      data: {
        practiceId: 26020,
        userId: 131810,
        userEmail: "skywalker@alfadocs.com",
      },
    };
    expect(userIdFromProfile(profile)).toBe("131810");
    expect(inferUsername(profile)).toBe("skywalker@alfadocs.com");
  });
});

describe("createAlfadocsAuth", () => {
  it("routes session requests and returns authenticated user", async () => {
    const storage = createStorageMock();
    const user = await storage.createUser("u-1", "john", { userId: "u-1", email: "john@example.com" });
    await storage.createSession(user.id);

    const auth = createAlfadocsAuth({
      clientId: "cid",
      clientSecret: "secret",
      redirectUri: "https://app.example/callback",
      appOrigin: "https://app.example",
      storage,
    });

    const req = new Request("https://fn.example/session", {
      headers: { cookie: "alfadocs_session=cookie-u-1" },
    });
    const res = await auth.handleRequest(req);
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      authenticated: true,
      user: { userId: "u-1", email: "john@example.com" },
    });
  });

  it("completes callback and sets session + clears preauth cookie", async () => {
    const storage = createStorageMock();
    const auth = createAlfadocsAuth({
      clientId: "cid",
      clientSecret: "secret",
      redirectUri: "https://fn.example/auth",
      appOrigin: "https://app.example",
      storage,
      baseUrl: "https://alfadocs.example",
      appPostLoginPath: "/dashboard",
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/oauth2/token")) {
        return new Response(
          JSON.stringify({
            access_token: "access",
            refresh_token: "refresh",
            expires_in: 3600,
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/api/v1/me")) {
        return new Response(JSON.stringify({ userId: "u-2", email: "mary@example.com" }), {
          status: 200,
        });
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const preauth = encodePreAuth({ codeVerifier: "verifier", state: "state-1" });
    const req = new Request("https://fn.example/auth?code=abc&state=state-1", {
      headers: { cookie: `alfadocs_preauth=${preauth}` },
    });
    const res = await auth.handleCallback(req);

    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe("https://app.example/dashboard");
    const setCookie = res.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain("alfadocs_session=");
  });

  it("rejects callback when profile does not include userId", async () => {
    const storage = createStorageMock();
    const auth = createAlfadocsAuth({
      clientId: "cid",
      clientSecret: "secret",
      redirectUri: "https://fn.example/auth",
      appOrigin: "https://app.example",
      storage,
      baseUrl: "https://alfadocs.example",
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/oauth2/token")) {
        return new Response(JSON.stringify({ access_token: "access", expires_in: 3600 }), { status: 200 });
      }
      if (url.endsWith("/api/v1/me")) {
        return new Response(JSON.stringify({ email: "missing-id@example.com" }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const preauth = encodePreAuth({ codeVerifier: "verifier", state: "state-1" });
    const res = await auth.handleCallback(
      new Request("https://fn.example/auth?code=abc&state=state-1", {
        headers: { cookie: `alfadocs_preauth=${preauth}` },
      }),
    );

    expect(res.status).toBe(500);
    await expect(res.json()).resolves.toMatchObject({
      error: expect.stringContaining("Profile does not contain `userId`"),
    });
  });

  it("sends patient:list on authorize redirect and on token exchange by default", async () => {
    const storage = createStorageMock();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/oauth2/token")) {
        return new Response(
          JSON.stringify({ access_token: "tok", expires_in: 3600 }),
          { status: 200 },
        );
      }
      if (url.endsWith("/api/v1/me")) {
        return new Response(JSON.stringify({ userId: "u-3", email: "x@y.com" }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const auth = createAlfadocsAuth({
      clientId: "cid",
      clientSecret: "secret",
      redirectUri: "https://fn.example/auth",
      appOrigin: "https://app.example",
      storage,
      baseUrl: "https://alfadocs.example",
    });

    const loginRes = await auth.handleLogin(new Request("https://fn.example/login"));
    const loc = loginRes.headers.get("Location")!;
    expect(new URL(loc).searchParams.get("scope")).toBe("patient:list");

    const preauth = encodePreAuth({ codeVerifier: "verifier", state: "state-1" });
    await auth.handleCallback(
      new Request("https://fn.example/auth?code=abc&state=state-1", {
        headers: { cookie: `alfadocs_preauth=${preauth}` },
      }),
    );

    const tokenCall = fetchMock.mock.calls.find((c) => String(c[0]).endsWith("/oauth2/token"));
    expect(tokenCall).toBeDefined();
    const requestInit: RequestInit = tokenCall
      ? ((((tokenCall as unknown as unknown[])[1] as RequestInit | undefined) ?? {}))
      : {};
    expect(typeof requestInit.body).toBe("string");
    const tp = new URLSearchParams(requestInit.body as string);
    expect(tp.get("scope")).toBe("patient:list");
    expect(tp.get("oauth_scope_list")).toBe("['patient:list']");
    expect(tp.get("grant_type")).toBe("authorization_code");
  });

  it("requires matching origin for POST logout and deletes persisted session", async () => {
    const storage = createStorageMock();
    const user = await storage.createUser("u-9", "jane", { userId: "u-9", email: "jane@example.com" });
    await storage.createSession(user.id);

    const auth = createAlfadocsAuth({
      clientId: "cid",
      clientSecret: "secret",
      redirectUri: "https://fn.example/auth",
      appOrigin: "https://app.example",
      storage,
    });

    const forbidden = await auth.handleRequest(
      new Request("https://fn.example/logout", {
        method: "POST",
        headers: { cookie: "alfadocs_session=cookie-u-9", origin: "https://evil.example" },
      }),
    );
    expect(forbidden.status).toBe(403);

    const ok = await auth.handleRequest(
      new Request("https://fn.example/logout", {
        method: "POST",
        headers: { cookie: "alfadocs_session=cookie-u-9", origin: "https://app.example" },
      }),
    );
    expect(ok.status).toBe(200);

    const session = await storage.getSession("cookie-u-9");
    expect(session).toBeNull();
  });
});
