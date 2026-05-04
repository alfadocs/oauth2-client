# Local test app (no Supabase function required)

This is a local app that uses this library directly.

It runs:
- local backend endpoints at `/login`, `/callback`, `/session`, `/logout` using `createAlfadocsAuth(...)`
- a simple frontend page at `/` with Login/Session/Logout buttons

## OAuth scopes

Default authorize scopes are **`patient:list`**. The Alfadocs server expects OAuth **`scope`** as a **single parameter** with **space-separated** values (e.g. `scope=patient:list` or `scope=a b c` when URL-encoded). The library sends the same space-separated `scope` on the **authorize** query string and on the **token** `POST` body.

### Prove what is sent (debug)

Set in `.env`:

```bash
ALFADOCS_DEBUG_OAUTH=1
```

Restart `server.mjs`. On **Login** you’ll see the full authorize URL including `scope=patient:list`. On **callback** you’ll see the token `POST` form fields; **`scope` should be `patient:list`**.

There is a **unit test** that asserts this: `tests/core/auth.test.ts` (“sends patient:list on authorize redirect and on token exchange by default”).

This library always uses OAuth token client auth via **request body** (`client_id` + `client_secret` in form) to match the known working flow.

If **`/api/v1/me`** still returns **“Access token scopes are empty”**:

1. Inspect the token JSON: **`scope`** may list granted scopes; if the access token is a JWT, the library fills **`tokenResponse.scope`** from the payload when the JSON body omits it.
2. Fix **Alfadocs** so `/api/v1/me` accepts tokens issued for `patient:list`, or
3. Bypass **`/me`** with **`resolveProfile`** in `createAlfadocsAuth` and build `Record<string, unknown>` from a JWT or another endpoint your app trusts.

## 1) Configure env vars

Export these before starting:

```bash
export ALFADOCS_CLIENT_ID="..."
export ALFADOCS_CLIENT_SECRET="..."
export ALFADOCS_BASE_URL="https://app.alfadocs.com"
# Auth storage Supabase (recommended names — distinct from a “main” app Supabase):
export AUTH_SUPABASE_URL="https://<project-ref>.supabase.co"
export AUTH_SUPABASE_KEY="..."
# Optional: override tenant scope for `app_id` (defaults to Alfadocs OAuth client id in local-app):
export AUTH_APP_ID="my-lovable-project-slug"
# Or legacy: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY
```

Create **`alfa_users`** / **`alfa_sessions`** in your auth Supabase project (see root [README.md](../../README.md) **Supabase tables**). The local app uses PostgREST only (no Postgres connection string).

Optional:

```bash
export PORT=8787
export APP_ORIGIN="http://localhost:8787"
# Optional: override OAuth scopes (space- or comma-separated); default is patient:list in the library.
export ALFADOCS_SCOPES="patient:list"
```

## 2) Register redirect URI in Alfadocs

Use:

```text
http://localhost:8787/callback
```

## 3) Build and run

From repo root:

```bash
npm run build
node tests/local-app/server.mjs
```

Then open:

```text
http://localhost:8787
```

## Notes

- This local app sets `cookieSecure: false` to allow HTTP localhost testing.
- For production, keep secure cookies enabled (default library behavior).

## Token exchange `HTTP 401`

The authorize step worked, but **`POST .../oauth2/token`** rejected the request. Common causes:

1. **`ALFADOCS_CLIENT_SECRET` wrong** or copied with extra spaces/quotes.
2. **`redirect_uri` mismatch** — in Alfadocs, the registered redirect must match **exactly** what this app sends: `{APP_ORIGIN}/callback` (e.g. `http://localhost:8787/callback`). Same scheme, host, port, path, no trailing slash unless you registered one.
3. **`ALFADOCS_BASE_URL` wrong** — dev vs production; OAuth client may exist only on one environment.
4. **Authorization code reused or stale** — start login again from **Login** (single-use code).
5. **Token client auth mode** is fixed to body (`client_id` + `client_secret` in form) to match the old working integration.

After the latest library changes, the error body is parsed when the server returns JSON or `application/x-www-form-urlencoded` errors (e.g. `invalid_client`).

## Self-signed HTTPS (skip certificate verification)

Only for local development against Alfadocs (or similar) with a **self-signed** or **untrusted CA**
certificate on the **server-to-server** `fetch` calls from Node.

In `tests/local-app/.env` set:

```bash
TLS_INSECURE=1
```

This applies to Alfadocs token/`/me` requests and Supabase storage requests from `server.mjs`.
**Never enable in production.**

Alternative (whole process): `NODE_TLS_REJECT_UNAUTHORIZED=0` — avoid if possible; it is global and easy to misuse.

## Troubleshooting `{"error":"fetch failed"}` (or similar)

That usually means **no TCP/TLS connection** to the URL (not an HTTP 4xx/5xx body). Check:

1. **`ALFADOCS_BASE_URL`** must be reachable from the machine running `server.mjs` (real HTTPS host or your local Alfadocs dev URL). A typo or an internal hostname only valid in the browser will fail here.
2. **`AUTH_SUPABASE_URL`** (or `SUPABASE_URL`) must be exactly `https://<project-ref>.supabase.co` with no trailing slash issues; corporate VPN or offline mode can block it.
3. If storage calls fail (e.g. missing table or 401), confirm you applied [`supabase/migrations/`](../../supabase/migrations/) and that **`AUTH_SUPABASE_KEY`** (or `SUPABASE_SERVICE_ROLE_KEY`) is the **service role** secret.
