@alfadocs/oauth2-client
========================

Backend‑first **Alfadocs auth bridge for Supabase**.

> **Proposal**  
> This package started as a simple “OAuth 2.0 client” experiment, but the current design is a full **Alfadocs auth and Supabase identity bridge** (OAuth2/OIDC, opaque browser session, user mapping, RLS integration).  
> Because of that, the name `@alfadocs/oauth2-client` is misleading. The recommended name going forward is **`@alfadocs/alfadocs-auth`** (or similar), and this README describes that new, backend‑first design.

Despite the package name, this is no longer “just an OAuth 2.0 client”. It is a small backend library that:

- Runs the full OAuth 2.0 / OIDC flow with Alfadocs server‑side.
- Manages an opaque browser session (cookie) for your app.
- Normalizes Alfadocs user identities and maps them 1‑1 to Supabase users.
- Helps you call both **Alfadocs APIs** and **Supabase Postgres with RLS** from Supabase Edge Functions.


Package structure
-----------------

The design is split into two conceptual layers:

- **Core (backend‑agnostic)** – “Alfadocs auth”
  - Responsible only for:
    - Running the OAuth2/OIDC flow with Alfadocs.
    - Managing an opaque browser session (cookie id ↔ server‑side session).
    - Normalizing the Alfadocs user profile (`sub`, `email`, etc.).
  - Intended to live as `@alfadocs/alfadocs-auth` and be usable from any backend (Supabase Edge Functions, Next.js API routes, etc.).

- **Supabase adapter (optional)** – “Alfadocs ↔ Supabase bridge”
  - Builds on top of the core package and adds:
    - Supabase‑friendly HTTP handlers for Edge Functions (`handleLogin`, `handleCallback`, `handleSession`, `handleLogout`).
    - 1‑1 mapping between Alfadocs users and Supabase users.
    - Helpers to mint per‑request Supabase JWTs for RLS.
  - Conceptually this would live as `@alfadocs/alfadocs-auth-supabase` or `@alfadocs/alfadocs-auth/supabase`.

This README focuses on the **Supabase adapter** usage, but all Supabase‑specific pieces are intentionally kept at the edges so the core can stay backend‑agnostic.

This package is designed for **backend‑centric auth**, with Supabase Edge Functions in mind:

- The **backend is the OAuth client** (authorization code flow).
- The **browser never sees access/refresh tokens**.
- The browser only:
  - Is redirected to Alfadocs for login.
  - Is redirected back to your app after callback.
  - Calls your backend with `credentials: "include"` to use the session.

No PKCE logic, no code exchange, and no token handling are required on the frontend.


How it works
------------

```
Browser                  Supabase Edge Function             Alfadocs
  │                               │                            │
  │── GET /login ────────────────▶│                            │
  │                               │── 302 → /oauth2/authorize ─▶
  │◀─────────────────────── 302 redirect to Alfadocs ──────────│
  │                               │                            │
  │─────────────── user authenticates on Alfadocs ─────────────│
  │                               │                            │
  │◀── 302 redirect from callback ◀─ /callback?code=… ◀────────│
  │                               │                            │
  │                               │── POST /oauth2/token ─────▶│
  │                               │◀── access_token, … ────────│
  │                               │                            │
  │◀── 302 to app + Set-Cookie (httpOnly session) ─────────────│
  │                               │
  │── GET /session ──────────────▶│ (validates/refreshes cookie)
  │◀── { authenticated: true } ───│
  │
  │── fetch /functions/v1/* with credentials: "include"
  │   (Supabase reads token from cookie and calls Alfadocs APIs)
```

### Key properties

- **Backend is the OAuth 2.0 client** (confidential client with client secret).
- The browser only holds an **opaque `HttpOnly` session cookie**; the real session (Alfadocs tokens + user mapping) is stored and verified server-side by this library.
- **Frontend just uses redirects**:
  - Send user to `LOGIN_URL` (Supabase Edge Function `/login`).
  - After login, user is redirected back to your app already authenticated.
- **All Alfadocs API calls** go through Supabase, which:
  - Reads the token from the cookie.
  - Calls Alfadocs on behalf of the user.


Install
-------

```bash
npm install @alfadocs/oauth2-client
# or
pnpm add @alfadocs/oauth2-client
```


Setup overview
--------------

You set up **one Edge Function** that exposes four HTTP endpoints:

1. `GET /login` – start Alfadocs login (redirect).
2. `GET /callback` – OAuth callback from Alfadocs; exchanges `code` for tokens and sets cookie.
3. `GET /session` – checks if the session cookie is present and valid; refreshes if needed.
4. `POST /logout` – clears the session cookie.

On the frontend, you:

- Redirect to `/login` to start login.
- Call `/session` on app mount to know if the user is authenticated.
- Call your own Supabase Edge Functions with `credentials: "include"` to access Alfadocs APIs.


Step 1 – Supabase Edge Function (using this library)
----------------------------------------------------

`@alfadocs/oauth2-client` is responsible for **all OAuth 2.0 protocol details**:

- Building the Alfadocs authorize URL.
- Exchanging `code` for tokens.
- Refreshing access tokens when expired.
- Managing the `alfadocs_session` cookie (serialization, expiry, refresh).
- Setting safe CORS + cookie headers for `credentials: "include"`.

Your Edge Function only needs to:

- Configure the client once.
- Route incoming HTTP requests to the right handler.

Create `supabase/functions/alfadocs-auth/index.ts` in your project:

```ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createAlfadocsSupabaseAuth } from "@alfadocs/oauth2-client/supabase"

const auth = createAlfadocsSupabaseAuth({
  clientId: Deno.env.get("ALFADOCS_CLIENT_ID")!,
  clientSecret: Deno.env.get("ALFADOCS_CLIENT_SECRET")!,
  baseUrl: Deno.env.get("ALFADOCS_BASE_URL") ?? "https://app.alfadocs.com",

  // Where Alfadocs should redirect back to after login.
  // Must be registered as a valid redirect URI for your OAuth client.
  redirectUri: Deno.env.get("ALFADOCS_REDIRECT_URI")!,

  // Your frontend app origin, e.g. https://myapp.lovable.app
  appOrigin: Deno.env.get("APP_ORIGIN")!,

  // Where to send the user in your app after successful login
  // e.g. /dashboard or just /
  appPostLoginPath: Deno.env.get("APP_POST_LOGIN_PATH") ?? "/",

  // Optional overrides
  cookieName: "alfadocs_session",
  cookieMaxAgeSeconds: 60 * 60 * 24 * 7, // 7 days
  scopes: ["allowed"],
})

serve(async (req: Request) => {
  const url = new URL(req.url)

  // CORS preflight
  if (req.method === "OPTIONS") {
    return auth.handleOptions(req)
  }

  if (req.method === "GET" && url.pathname.endsWith("/login")) {
    return auth.handleLogin(req)
  }

  if (req.method === "GET" && url.pathname.endsWith("/callback")) {
    return auth.handleCallback(req)
  }

  if (req.method === "GET" && url.pathname.endsWith("/session")) {
    return auth.handleSession(req)
  }

  if (req.method === "POST" && url.pathname.endsWith("/logout")) {
    return auth.handleLogout(req)
  }

  return auth.notFound()
})
```


Supabase secrets to set
-----------------------

```bash
supabase secrets set ALFADOCS_CLIENT_ID=your-client-id
supabase secrets set ALFADOCS_CLIENT_SECRET=your-client-secret
supabase secrets set ALFADOCS_REDIRECT_URI=https://xyz.supabase.co/functions/v1/alfadocs-auth/callback
supabase secrets set ALFADOCS_BASE_URL=https://app.alfadocs.com
supabase secrets set APP_ORIGIN=https://myapp.lovable.app
supabase secrets set APP_POST_LOGIN_PATH=/dashboard
```

Deploy with:

```bash
supabase functions deploy alfadocs-auth
```

Your Edge Function URL will look like:

```text
https://xyz.supabase.co/functions/v1/alfadocs-auth
```

You will then have these public endpoints:

- `GET https://xyz.supabase.co/functions/v1/alfadocs-auth/login`
- `GET https://xyz.supabase.co/functions/v1/alfadocs-auth/callback`
- `GET https://xyz.supabase.co/functions/v1/alfadocs-auth/session`
- `POST https://xyz.supabase.co/functions/v1/alfadocs-auth/logout`


Step 2 – Frontend app
---------------------

The frontend does **not** manage tokens and does **not** need a JS OAuth client.

It only needs:

- A way to send the user to the Supabase `/login` URL.
- A way to check `/session` on mount.
- To call your own Supabase proxy functions with `credentials: "include"`.

### Environment variables (`.env`)

```text
VITE_SUPABASE_AUTH_BASE_URL=https://xyz.supabase.co/functions/v1/alfadocs-auth
VITE_SUPABASE_URL=https://xyz.supabase.co     # standard Supabase URL
```

### Login button

```tsx
const LOGIN_URL = `${import.meta.env.VITE_SUPABASE_AUTH_BASE_URL}/login`

export function LoginPage() {
  const handleLogin = () => {
    window.location.href = LOGIN_URL
  }

  return <button onClick={handleLogin}>Log in with Alfadocs</button>
}
```

There is **no callback page in your app** – Alfadocs redirects to the Supabase `/callback`, which:

- Exchanges the `code` for tokens.
- Sets the `alfadocs_session` httpOnly cookie.
- Redirects the browser back to your app’s origin (e.g. `https://myapp.lovable.app/dashboard`).

### Restore session on app mount

```tsx
import { useEffect, useState } from "react"

const SESSION_URL = `${import.meta.env.VITE_SUPABASE_AUTH_BASE_URL}/session`

export function App() {
  const [ready, setReady] = useState(false)
  const [loggedIn, setLoggedIn] = useState(false)

  useEffect(() => {
    fetch(SESSION_URL, {
      credentials: "include",
    })
      .then(res => res.json())
      .then(data => setLoggedIn(Boolean(data?.authenticated)))
      .finally(() => setReady(true))
  }, [])

  if (!ready) return <p>Loading…</p>
  if (!loggedIn) return <LoginPage />
  return <Dashboard />
}
```

### Logout

```tsx
const LOGOUT_URL = `${import.meta.env.VITE_SUPABASE_AUTH_BASE_URL}/logout`

async function handleLogout() {
  await fetch(LOGOUT_URL, {
    method: "POST",
    credentials: "include",
  })
  window.location.href = "/"
}
```


Step 3 – Calling Alfadocs APIs from Supabase
--------------------------------------------

All Alfadocs API calls must go through Supabase Edge Functions. The library keeps Alfadocs tokens and user info server-side and exposes helpers so you never read or trust the cookie directly.

**Example: `supabase/functions/get-patients/index.ts`**

```ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createAlfadocsSupabaseAuth } from "@alfadocs/oauth2-client/supabase"

const auth = createAlfadocsSupabaseAuth({
  clientId: Deno.env.get("ALFADOCS_CLIENT_ID")!,
  clientSecret: Deno.env.get("ALFADOCS_CLIENT_SECRET")!,
  baseUrl: Deno.env.get("ALFADOCS_BASE_URL") ?? "https://app.alfadocs.com",
  redirectUri: Deno.env.get("ALFADOCS_REDIRECT_URI")!,
  appOrigin: Deno.env.get("APP_ORIGIN")!,
})

serve(async (req: Request) => {
  // This will:
  // - Verify the opaque session cookie
  // - Refresh the Alfadocs token if needed
  // - Return a trusted session object (or 401 if missing/invalid)
  const session = await auth.requireSession(req)

  const response = await fetch(`${session.alfadocs.baseUrl}/api/patients`, {
    headers: { Authorization: `Bearer ${session.alfadocs.accessToken}` },
  })

  const data = await response.json()

  return new Response(JSON.stringify(data), {
    status: response.status,
    headers: { "Content-Type": "application/json" },
  })
})
```

From the frontend, call this with `credentials: "include"` so the session cookie is sent:

```ts
const response = await fetch(
  `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/get-patients`,
  { credentials: "include" },
)
const patients = await response.json()
```


Step 4 – Calling Supabase Database with RLS
-------------------------------------------

Once a user is authenticated, you typically want to talk to your **own Supabase Postgres database** with full RLS enforcement, using the Alfadocs↔Supabase mapping managed by this library.

At a high level:

1. Browser calls your Edge Function with the opaque cookie (`credentials: "include"`).
2. Edge Function uses `requireSession(req)` to get:
   - Alfadocs tokens (for Alfadocs APIs, if needed).
   - A mapped `supabase.userId`, representing the Supabase user.
3. Edge Function mints a short‑lived **Supabase JWT** with that `userId` as `auth.uid()`.
4. Edge Function uses `@supabase/supabase-js` with that JWT in `Authorization` to talk to Supabase PostgREST / Realtime / Storage – and RLS is applied normally.

This library is meant to be usable as an **OIDC-style identity bridge** between Alfadocs and Supabase.

### 1‑1 Alfadocs ↔ Supabase user mapping

On first successful login (inside `handleCallback`), the library:

- Normalizes the **Alfadocs user identity** (e.g. `sub`, `email`, `name`).
- Looks up an existing mapping in your Supabase database by `alfadocs_sub`.
- If none exists, **creates a new Supabase user row** (or app‑level `users` row) and stores a mapping:

```sql
-- Example app schema (you own this)
create table users (
  id uuid primary key default gen_random_uuid(),
  alfadocs_sub text unique not null,
  email text,
  created_at timestamptz default now()
);
```

The resulting `supabase_user_id` is then stored in the server-side session object the library manages (never in the cookie directly).

On every subsequent request, `getSession(req)` / `requireSession(req)` returns a trusted session like:

```ts
{
  alfadocs: {
    sub: "alfadocs|123",
    email: "user@example.com",
    accessToken: "...",
    // ...
  },
  supabase: {
    userId: "uuid-from-users-table",
  },
}
```

### Example: RLS-aware Edge Function

```ts
import { createClient } from "https://esm.sh/@supabase/supabase-js@2"
import { createAlfadocsSupabaseAuth } from "@alfadocs/oauth2-client/supabase"
import { createSupabaseJwt } from "@alfadocs/oauth2-client/supabase-jwt" // hypothetical helper

const auth = createAlfadocsSupabaseAuth({ /* ... */ })

serve(async (req: Request) => {
  const session = await auth.requireSession(req)

  // 1) Mint a short-lived Supabase JWT for this user
  const supabaseJwt = createSupabaseJwt({
    userId: session.supabase.userId,  // → becomes auth.uid()
    role: "authenticated",
    // exp, additional claims, etc.
  })

  // 2) Create a Supabase client that uses this JWT
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    {
      global: {
        headers: {
          Authorization: `Bearer ${supabaseJwt}`,
        },
      },
    },
  )

  // 3) All selects/inserts now go through RLS for this user
  const { data } = await supabase.from("patients").select("*")

  return new Response(JSON.stringify(data ?? []), {
    headers: { "Content-Type": "application/json" },
  })
})
```

In this model:

- **Browser auth** is exclusively via the opaque cookie managed by this library.
- **User identity** comes from Alfadocs and is mapped 1‑1 to a Supabase user id on the backend.
- **RLS** is enforced because the backend calls Supabase with a JWT whose `sub`/`auth.uid()` is that mapped Supabase user id – the browser never sees this JWT.


API reference
-------------

This package provides a **Supabase‑optimized OAuth 2.0 client** that hides protocol details and session storage behind a small server API.

### `createAlfadocsSupabaseAuth(config)`

Creates a configured auth handler for Supabase Edge Functions.

**Config options**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `clientId` | Yes | — | Your Alfadocs OAuth2 client ID. |
| `clientSecret` | Yes | — | Your Alfadocs OAuth2 client secret. |
| `baseUrl` | No | `https://app.alfadocs.com` | Alfadocs base URL. |
| `redirectUri` | Yes | — | Must match a registered redirect URI; should point to `/callback` of this Edge Function. |
| `appOrigin` | Yes | — | Frontend origin, e.g. `https://myapp.lovable.app`. Used for CORS and redirects. |
| `appPostLoginPath` | No | `/` | Path on your app where users land after successful login (e.g. `/dashboard`). |
| `cookieName` | No | `"alfadocs_session"` | Name of the opaque session cookie. |
| `cookieMaxAgeSeconds` | No | `7 * 24 * 60 * 60` | Cookie lifetime. |
| `scopes` | No | `["allowed"]` | Alfadocs scopes to request. `"allowed"` means all registered scopes. |

**Core HTTP handlers**

| Method | Description |
|--------|-------------|
| `handleOptions(req)` | Handles CORS preflight (`OPTIONS`) with correct headers. |
| `handleLogin(req)` | Starts OAuth flow: 302‑redirects to Alfadocs authorize URL. |
| `handleCallback(req)` | Processes Alfadocs callback, exchanges `code` for tokens, links/creates user, sets cookie, redirects to app. |
| `handleSession(req)` | Checks/refreshes session cookie, returns `{ authenticated: boolean }`. |
| `handleLogout(req)` | Clears session cookie, returns `{ ok: true }`. |
| `notFound()` | Convenience helper for a 404 with consistent CORS headers. |

**Session & user helpers**

| Method | Description |
|--------|-------------|
| `getSession(req)` | Returns `null` or a trusted session object (tokens + user info + mapping), based on the opaque cookie. |
| `requireSession(req)` | Like `getSession`, but throws/returns 401 if no valid session exists. |

The session object is designed to support:

- **Alfadocs API calls**: exposes a valid Alfadocs access token and base URL.
- **User identity**: normalized user info (e.g. `sub`, `email`) and a 1‑1 mapping to your Supabase user id (created on first login).
- **RLS‑ready backend integration**: you can use the mapped Supabase user id to mint a per‑request Supabase JWT on the backend and talk to Supabase with full RLS, without exposing that JWT to the browser.


Security notes
--------------

- The **browser never sees access or refresh tokens** – it only has an opaque `HttpOnly`, `Secure`, `SameSite=None` cookie. All real session data lives in a server-side store managed by this library.
- All calls from the browser to Supabase use `credentials: "include"`, and CORS is restricted to your exact `APP_ORIGIN` (not `*`).
- The backend uses the **authorization code flow with client secret**, which is appropriate for a confidential client (Supabase Edge Function).
