# @alfadocs/oauth2-client

Backend-first Alfadocs auth library for Supabase Edge Functions.

The entire OAuth2 + PKCE flow runs server-side. The browser never handles a token, a code verifier, or a client secret. It just follows redirects and checks its session.

## Install

```bash
npm install github:alfadocs/oauth2-client#backend-version
```

## How it works

```
Browser              Supabase Edge Function         Alfadocs
  │                          │                         │
  │── ?action=login ────────▶│                         │
  │                          │── 302 /oauth2/authorize ▶│
  │◀──────────────────── 302 redirect to Alfadocs ──────│
  │                          │                         │
  │────────── user logs in on Alfadocs ─────────────────│
  │                          │                         │
  │◀── ?code=... ────────────│◀── redirect ────────────│
  │                          │── POST /oauth2/token ───▶│
  │                          │◀── access_token ─────────│
  │                          │── GET /api/v1/me ────────▶│
  │                          │◀── user info ────────────│
  │◀── 302 /dashboard + Set-Cookie (httpOnly session) ──│
  │                          │
  │── GET (session check) ──▶│ validates cookie, auto-refreshes token
  │◀── { authenticated, user }│
```

## Setup

### 1. Supabase Edge Function

Create `supabase/functions/alfadocs-auth/index.ts`:

```ts
import { createAlfadocsSupabaseAuth } from "@alfadocs/oauth2-client/supabase"

const auth = createAlfadocsSupabaseAuth({
  clientId:         Deno.env.get("ALFADOCS_CLIENT_ID")!,
  clientSecret:     Deno.env.get("ALFADOCS_CLIENT_SECRET")!,
  redirectUri:      Deno.env.get("ALFADOCS_REDIRECT_URI")!,
  appOrigin:        Deno.env.get("ALLOWED_ORIGIN")!,
  baseUrl:          "https://app.alfadocs.com",
  appPostLoginPath: "/dashboard",
})

Deno.serve((req) => auth.handleRequest(req))
```

Set Supabase secrets:

```bash
supabase secrets set ALFADOCS_CLIENT_ID=...
supabase secrets set ALFADOCS_CLIENT_SECRET=...
supabase secrets set ALFADOCS_REDIRECT_URI=https://<project-ref>.supabase.co/functions/v1/alfadocs-auth
supabase secrets set ALLOWED_ORIGIN=https://yourapp.lovable.app
```

Deploy:

```bash
supabase functions deploy alfadocs-auth
```

### 2. Frontend — no library needed

Login is a plain link. Session check is a plain fetch.

```ts
const FUNCTION_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/alfadocs-auth`

// Login
window.location.href = `${FUNCTION_URL}?action=login`

// Session check (call on app mount)
const { authenticated, user } = await fetch(FUNCTION_URL, {
  credentials: "include",
}).then(r => r.json())

// Logout
await fetch(FUNCTION_URL, {
  method: "POST",
  credentials: "include",
  headers: { "X-Requested-With": "XMLHttpRequest" },
})
```

Protected route pattern:

```tsx
const SESSION_URL = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/alfadocs-auth`

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<"loading" | "ok" | "unauth">("loading")

  useEffect(() => {
    fetch(SESSION_URL, { credentials: "include" })
      .then(r => r.json())
      .then(({ authenticated }) => setStatus(authenticated ? "ok" : "unauth"))
      .catch(() => setStatus("unauth"))
  }, [])

  if (status === "loading") return <div>Loading…</div>
  if (status === "unauth") return <Navigate to="/login" replace />
  return <>{children}</>
}
```

### 3. Calling Alfadocs APIs from other Edge Functions

Read the token from the session cookie server-side:

```ts
import { parseCookies, decodeSession } from "@alfadocs/oauth2-client/supabase"

function getAccessToken(req: Request): string | null {
  const cookies = parseCookies(req.headers.get("cookie") ?? "")
  const session = decodeSession(cookies["alfadocs_session"] ?? "")
  return session?.accessToken ?? null
}

Deno.serve(async (req) => {
  const token = getAccessToken(req)
  if (!token) return new Response("Unauthorized", { status: 401 })

  const res = await fetch(`${Deno.env.get("ALFADOCS_BASE_URL")}/api/v1/patients`, {
    headers: { Authorization: `Bearer ${token}` },
  })

  return new Response(res.body, { status: res.status, headers: { "Content-Type": "application/json" } })
})
```

---

## API reference

### `createAlfadocsSupabaseAuth(config)`

| Option | Required | Default | Description |
|---|---|---|---|
| `clientId` | Yes | — | Alfadocs OAuth2 client ID |
| `clientSecret` | Yes | — | Alfadocs OAuth2 client secret |
| `redirectUri` | Yes | — | Your Edge Function URL (registered on Alfadocs) |
| `appOrigin` | Yes | — | Frontend URL — used for CORS and post-login redirect |
| `baseUrl` | No | `https://app.alfadocs.loc` | Alfadocs server URL |
| `appPostLoginPath` | No | `/` | Path to redirect the user to after login |
| `cookieName` | No | `alfadocs_session` | Session cookie name |
| `cookieMaxAgeSeconds` | No | `604800` (7 days) | Session cookie lifetime |
| `scopes` | No | `["allowed"]` | OAuth2 scopes to request |

### `auth.handleRequest(req)` — single endpoint

Routes all traffic automatically:

| Request | Action |
|---|---|
| `OPTIONS` | CORS preflight → 204 |
| `GET ?action=login` | Generate PKCE + state, redirect to Alfadocs |
| `GET ?code=...` | Exchange code, fetch user, set session cookie, redirect to app |
| `GET` | Session check → `{ authenticated, user? }`, auto-refreshes token |
| `POST` | Clear session cookie → `{ ok: true }` |

### Individual handlers

`handleLogin`, `handleCallback`, `handleSession`, `handleLogout`, `handleOptions` are also exported if you need to route manually.

---

## Cookie strategy

| Cookie | SameSite | Why |
|---|---|---|
| `alfadocs_preauth` (10 min) | `Lax` | Set on `/login`, read on callback redirect — top-level navigation, Lax is sufficient |
| `alfadocs_session` (7 days) | `None; Secure` | Read by cross-origin `fetch()` from the frontend app — requires None |
