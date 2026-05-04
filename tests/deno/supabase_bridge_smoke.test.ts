/**
 * Deno runtime smoke test: Supabase bridge loads and uses fetch (PostgREST) only.
 */
import { createSupabaseStorage } from "../../src/supabase-bridge/index.ts";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

Deno.test("createSupabaseStorage getUser uses PostgREST only (no /rpc/)", async () => {
  const calls: string[] = [];

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    calls.push(url);
    if (url.includes("/alfa_users")) {
      return Promise.resolve(
        new Response(JSON.stringify([{ id: "u1", username: "x", auth_data: {} }]), { status: 200 }),
      );
    }
    return Promise.resolve(new Response("unexpected", { status: 500 }));
  };

  try {
    const storage = createSupabaseStorage({
      supabaseUrl: "https://example.supabase.co",
      serviceRoleKey: "test-key",
      oauthClientId: "smoke-oauth-client",
    });
    const user = await storage.getUser("u1");
    assert(user !== null, "expected user");
    assert(user.id === "u1" && user.username === "x", "unexpected user payload");
    assert(calls.length === 1, "single fetch");
    assert(calls[0].includes("/rest/v1/alfa_users"), "users path");
    assert(!calls[0].includes("/rpc/"), "no RPC");
    assert(calls[0].includes("app_id=eq.smoke-oauth-client"), "app_id from oauthClientId");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
