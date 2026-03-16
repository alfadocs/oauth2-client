# @alfadocs/oauth2-client

Drop-in OAuth2 PKCE client for Alfadocs authentication.
Built for Lovable apps using Supabase — secure by default, session persists across page refreshes.

## How it works

```
Browser                      Supabase Edge Function         Alfadocs
  │                                  │                          │
  │── login() ──────────────────────────────────────────────── redirect ──▶
  │◀─────────────────────────────────────────────── redirect with code ────
  │                                  │                          │
  │── handleCallback() ─────────────▶│                          │
  │                                  │── POST /oauth2/token ───▶│
  │                                  │◀── access_token ─────────│
  │                                  │                          │
  │◀── Set-Cookie: session (httpOnly)─│
  │                                  │
  │── refreshSession() ─────────────▶│ (validates cookie)
  │◀── { authenticated: true } ──────│
```

The browser **never sees the access token**. It lives only in the Supabase Edge Function and is sent to Alfadocs APIs server-side. The session is stored as an `httpOnly` cookie — invisible to JavaScript, persistent across page refreshes, secure against XSS.

## Install

```bash
npm install @alfadocs/oauth2-client
# or
pnpm add @alfadocs/oauth2-client
```

## Setup overview

Two things to set up:

1. **Supabase Edge Function** — handles token exchange server-side, sets the cookie
2. **Browser app** — calls `login()`, `handleCallback()`, `refreshSession()`

---

## Step 1 — Supabase Edge Function

Create `supabase/functions/alfadocs-auth/index.ts` in your project:

```ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"

const ALFADOCS_BASE_URL = Deno.env.get("ALFADOCS_BASE_URL") ?? "https://app.alfadocs.com"
const ALFADOCS_TOKEN_URL = `${ALFADOCS_BASE_URL}/oauth2/token`
const CLIENT_ID = Deno.env.get("ALFADOCS_CLIENT_ID")!
const CLIENT_SECRET = Deno.env.get("ALFADOCS_CLIENT_SECRET")!
const REDIRECT_URI = Deno.env.get("ALFADOCS_REDIRECT_URI")!
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN")!  // e.g. https://myapp.lovable.app
const COOKIE_NAME = "alfadocs_session"
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7 // 7 days

// IMPORTANT: ALLOWED_ORIGIN must be your exact frontend URL (not *).
// credentials: "include" requires a specific origin, never a wildcard.
const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Credentials": "true",
}

function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", ...extraHeaders },
  })
}

function cookieHeader(value: string, maxAge: number) {
  return [
    `${COOKIE_NAME}=${value}`,
    "HttpOnly",
    "Secure",
    "SameSite=None",   // required for cross-origin (Supabase ↔ Lovable app)
    "Path=/",
    `Max-Age=${maxAge}`,
  ].join("; ")
}

function getCookie(req: Request): string | null {
  const header = req.headers.get("cookie") ?? ""
  const match = header.match(new RegExp(`${COOKIE_NAME}=([^;]+)`))
  return match ? decodeURIComponent(match[1]) : null
}

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders })
  }

  const path = new URL(req.url).pathname

  // POST / — exchange auth code for tokens, set httpOnly cookie
  if (req.method === "POST" && !path.endsWith("/session") && !path.endsWith("/logout")) {
    const { code, code_verifier } = await req.json()

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code,
    })
    if (code_verifier) params.set("code_verifier", code_verifier)

    const tokenRes = await fetch(ALFADOCS_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    })

    if (!tokenRes.ok) {
      const detail = await tokenRes.text()
      return json({ error: "Token exchange failed", detail }, 400)
    }

    const tokens = await tokenRes.json()
    const session = encodeURIComponent(JSON.stringify({
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token ?? null,
      expires_at: Date.now() + (tokens.expires_in ?? 3600) * 1000,
    }))

    return json({ ok: true }, 200, { "Set-Cookie": cookieHeader(session, COOKIE_MAX_AGE) })
  }

  // GET /session — check if cookie is still valid
  if (req.method === "GET" && path.endsWith("/session")) {
    const raw = getCookie(req)
    if (!raw) return json({ authenticated: false })

    try {
      const session = JSON.parse(raw)
      if (Date.now() < session.expires_at) {
        return json({ authenticated: true })
      }
      // Token expired — attempt refresh if refresh_token is available
      if (session.refresh_token) {
        const refreshRes = await fetch(ALFADOCS_TOKEN_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            refresh_token: session.refresh_token,
          }).toString(),
        })
        if (refreshRes.ok) {
          const refreshed = await refreshRes.json()
          const newSession = encodeURIComponent(JSON.stringify({
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token ?? session.refresh_token,
            expires_at: Date.now() + (refreshed.expires_in ?? 3600) * 1000,
          }))
          return json({ authenticated: true }, 200, {
            "Set-Cookie": cookieHeader(newSession, COOKIE_MAX_AGE),
          })
        }
      }
      return json({ authenticated: false }, 200, {
        "Set-Cookie": cookieHeader("", 0), // clear expired cookie
      })
    } catch {
      return json({ authenticated: false })
    }
  }

  // POST /logout — clear cookie
  if (req.method === "POST" && path.endsWith("/logout")) {
    return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("", 0) })
  }

  return new Response("Not found", { status: 404, headers: corsHeaders })
})
```

### Supabase secrets to set

```bash
supabase secrets set ALFADOCS_CLIENT_ID=your-client-id
supabase secrets set ALFADOCS_CLIENT_SECRET=your-client-secret
supabase secrets set ALFADOCS_REDIRECT_URI=https://myapp.lovable.app/callback
supabase secrets set ALFADOCS_BASE_URL=https://app.alfadocs.com
supabase secrets set ALLOWED_ORIGIN=https://myapp.lovable.app
```

Deploy with:
```bash
supabase functions deploy alfadocs-auth
```

---

## Step 2 — Browser app

### Environment variables (`.env`)

```
VITE_ALFADOCS_CLIENT_ID=your-client-id
VITE_SUPABASE_EXCHANGE_URL=https://xyz.supabase.co/functions/v1/alfadocs-auth
```

### Create the auth client (`src/auth.ts`)

```ts
import { initAlfadocsAuth } from '@alfadocs/oauth2-client'

export const auth = initAlfadocsAuth({
  clientId:    import.meta.env.VITE_ALFADOCS_CLIENT_ID,
  redirectUri: `${window.location.origin}/callback`,
  exchangeUrl: import.meta.env.VITE_SUPABASE_EXCHANGE_URL,
  baseUrl:     'https://app.alfadocs.com',
})
```

### Restore session on app mount (`src/App.tsx`)

```tsx
import { useEffect, useState } from 'react'
import { auth } from './auth'

export function App() {
  const [ready, setReady] = useState(false)
  const [loggedIn, setLoggedIn] = useState(false)

  useEffect(() => {
    auth.refreshSession()
      .then(setLoggedIn)
      .finally(() => setReady(true))
  }, [])

  if (!ready) return <p>Loading…</p>
  if (!loggedIn) return <LoginPage />
  return <Dashboard />
}
```

### Login button

```tsx
import { auth } from '../auth'

export function LoginPage() {
  return <button onClick={() => auth.login()}>Log in with Alfadocs</button>
}
```

### Callback page (`src/pages/CallbackPage.tsx`)

```tsx
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { auth } from '../auth'

export function CallbackPage() {
  const navigate = useNavigate()

  useEffect(() => {
    auth.handleCallback()
      .then(() => navigate('/dashboard'))
      .catch(err => {
        console.error('Login failed:', err)
        navigate('/login')
      })
  }, [])

  return <p>Logging you in…</p>
}
```

### Logout

```tsx
import { auth } from '../auth'

async function handleLogout() {
  await auth.logout()
  window.location.href = '/'
}
```

---

## Step 3 — Calling Alfadocs APIs from Supabase

Since the token lives in the httpOnly cookie on Supabase, all Alfadocs API calls must go through Supabase Edge Functions. Add a shared helper to read the token:

**`supabase/functions/_shared/session.ts`**
```ts
const COOKIE_NAME = "alfadocs_session"

export function getAccessToken(req: Request): string | null {
  const header = req.headers.get("cookie") ?? ""
  const match = header.match(new RegExp(`${COOKIE_NAME}=([^;]+)`))
  if (!match) return null
  try {
    const session = JSON.parse(decodeURIComponent(match[1]))
    return session.access_token ?? null
  } catch {
    return null
  }
}
```

Every Alfadocs API proxy function then looks like this:

**`supabase/functions/get-patients/index.ts`**
```ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { getAccessToken } from "../_shared/session.ts"

const ALFADOCS_BASE_URL = Deno.env.get("ALFADOCS_BASE_URL") ?? "https://app.alfadocs.com"

serve(async (req: Request) => {
  const token = getAccessToken(req)
  if (!token) return new Response("Unauthorized", { status: 401 })

  const response = await fetch(`${ALFADOCS_BASE_URL}/api/patients`, {
    headers: { Authorization: `Bearer ${token}` },
  })

  const data = await response.json()
  return new Response(JSON.stringify(data), {
    status: response.status,
    headers: { "Content-Type": "application/json" },
  })
})
```

From the Lovable frontend, call it with `credentials: "include"` so the cookie is sent:

```ts
const response = await fetch(
  `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/get-patients`,
  { credentials: "include" }
)
const patients = await response.json()
```

---

## API reference

### `initAlfadocsAuth(config)`

| Option | Required | Default | Description |
|---|---|---|---|
| `clientId` | Yes | — | Your Alfadocs OAuth2 client ID |
| `redirectUri` | Yes | — | Must match a registered redirect URI |
| `exchangeUrl` | Yes | — | Your Supabase Edge Function URL |
| `baseUrl` | No | `https://app.alfadocs.loc` | Alfadocs server URL |
| `scopes` | No | `["allowed"]` | OAuth2 scopes to request. Defaults to `"allowed"` (all registered scopes). |

### `auth.login()`
Redirects to Alfadocs login. Handles PKCE internally.

### `auth.handleCallback(url?)`
Call on your `/callback` route. Sends the code to your Supabase Edge Function, which sets the session cookie. Safe to call from a React `useEffect` (handles StrictMode double-invocation).

### `auth.refreshSession()`
Call once on app mount. Checks the session cookie via your Supabase Edge Function and restores auth state. Returns `true` if authenticated.

### `auth.isAuthenticated()`
Synchronous. Returns the in-memory auth state. Always `false` until `refreshSession()` or `handleCallback()` completes.

### `auth.logout()`
Calls your Supabase Edge Function to clear the cookie, then clears local state.

---

## Migration from v0.1.x

| v0.1 | v0.2 |
|---|---|
| `exchangeCodeForToken()` | handled by Supabase Edge Function |
| `refreshAccessToken()` | handled by Supabase Edge Function (`/session` auto-refreshes) |
| `getAccessToken()` | removed — browser never holds a token |
| `isTokenExpiredOrExpiringSoon()` | removed — handled server-side |
| `OAuth2ClientConfig` | `AlfadocsAuthConfig` (add `exchangeUrl`) |
