import { afterEach, describe, expect, it, vi } from "vitest";
import { createSupabaseStorage } from "../../src/supabase-bridge/index.js";

const testAppId = "my-app-1";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("createSupabaseStorage", () => {
  it("surfaces PostgREST errors without RPC (e.g. missing table)", async () => {
    const err = { code: "42P01", message: 'relation "alfa_users" does not exist' };
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify(err), {
        status: 404,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      appId: testAppId,
    });

    await expect(storage.getUser("u1")).rejects.toEqual(err);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).not.toContain("/rpc/");
  });

  it("sends Accept-Profile when schema is non-public", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ id: "u1", username: "j", auth_data: {} }]), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      appId: testAppId,
      schema: "app",
    });
    await storage.getUser("u1");

    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers["Accept-Profile"]).toBe("app");
    expect(headers["Content-Profile"]).toBe("app");
  });

  it("propagates non-missing-table PostgREST errors", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "23505", message: "duplicate key value violates unique constraint" }), {
        status: 409,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      appId: testAppId,
    });

    await expect(storage.createUser("u1", "john", { id: "u1" })).rejects.toEqual({
      code: "23505",
      message: "duplicate key value violates unique constraint",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/rest/v1/alfa_users");
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.body).toContain('"app_id":"my-app-1"');
  });

  it("deletes session by cookie value scoped to app_id", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      appId: testAppId,
    });

    await storage.deleteSession("cookie-1");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      "https://project.supabase.co/rest/v1/alfa_sessions?app_id=eq.my-app-1&cookie_value=eq.cookie-1",
    );
    expect(init.method).toBe("DELETE");
  });

  it("getUser hits PostgREST once per call", async () => {
    const fetchMock = vi.fn().mockImplementation(
      () =>
        new Response(JSON.stringify([{ id: "u1", username: "j", auth_data: {} }]), {
          status: 200,
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      appId: testAppId,
    });
    await storage.getUser("u1");
    await storage.getUser("u1");

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls.map((c) => String(c[0])).every((u) => u.includes("/alfa_users"))).toBe(true);
    expect(fetchMock.mock.calls[0][0]).toContain("app_id=eq.my-app-1");
  });

  it("rejects invalid tenant scope", () => {
    expect(() =>
      createSupabaseStorage({
        supabaseUrl: "https://p.supabase.co",
        serviceRoleKey: "k",
        appId: "has space",
      }),
    ).toThrow(/Invalid tenant scope/);
  });

  it("uses oauthClientId as app_id when appId is omitted", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify([{ id: "u1", username: "j", auth_data: {} }]), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      oauthClientId: "alfadocs-oauth-client-99",
    });
    await storage.getUser("u1");

    expect(String(fetchMock.mock.calls[0][0])).toContain("app_id=eq.alfadocs-oauth-client-99");
  });

  it("prefers appId over oauthClientId when both are set", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify([{ id: "u1", username: "j", auth_data: {} }]), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      appId: "explicit-app",
      oauthClientId: "oauth-ignored",
    });
    await storage.getUser("u1");

    expect(String(fetchMock.mock.calls[0][0])).toContain("app_id=eq.explicit-app");
    expect(String(fetchMock.mock.calls[0][0])).not.toContain("oauth-ignored");
  });

  it("requires appId or oauthClientId", () => {
    expect(() =>
      createSupabaseStorage({
        supabaseUrl: "https://p.supabase.co",
        serviceRoleKey: "k",
      }),
    ).toThrow(/Set `appId`/);
  });
});
