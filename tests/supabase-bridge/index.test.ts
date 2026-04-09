import { afterEach, describe, expect, it, vi } from "vitest";
import { createSupabaseStorage } from "../../src/supabase-bridge/index.js";

const unsafeMock = vi.fn(async () => []);
const endMock = vi.fn(async () => undefined);

vi.mock("postgres", () => {
  return {
    default: () => ({
      unsafe: unsafeMock,
      end: endMock,
    }),
  };
});

afterEach(() => {
  vi.restoreAllMocks();
  unsafeMock.mockClear();
  endMock.mockClear();
});

describe("createSupabaseStorage", () => {
  it("runs migrations then retries when first call fails with missing table", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ code: "42P01", message: 'relation "users" does not exist' }), {
          status: 404,
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify([{ id: "u1", username: "john", auth_data: { email: "j@example.com" } }]), {
          status: 200,
        }),
      );

    vi.stubGlobal("fetch", fetchMock);
    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      databaseUrl: "postgresql://postgres:password@db.project.supabase.co:5432/postgres",
    });

    const user = await storage.getUser("u1");
    expect(user).toEqual({ id: "u1", username: "john", authData: { email: "j@example.com" } });

    const calledUrls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(calledUrls[0]).toContain("/rest/v1/users");
    expect(calledUrls[1]).toContain("/rest/v1/users");
    expect(unsafeMock).toHaveBeenCalledTimes(3);
    expect(endMock).toHaveBeenCalledTimes(1);
  });

  it("does not run migrations for non-missing-table errors", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "23505", message: "duplicate key value violates unique constraint" }), {
        status: 409,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const storage = createSupabaseStorage({
      supabaseUrl: "https://project.supabase.co",
      serviceRoleKey: "srk",
      databaseUrl: "postgresql://postgres:password@db.project.supabase.co:5432/postgres",
    });

    await expect(storage.createUser("u1", "john", { id: "u1" })).rejects.toEqual({
      code: "23505",
      message: "duplicate key value violates unique constraint",
    });

    const calledUrls = fetchMock.mock.calls.map((c) => String(c[0]));
    expect(calledUrls).toHaveLength(1);
    expect(calledUrls[0]).toContain("/rest/v1/users");
  });
});
