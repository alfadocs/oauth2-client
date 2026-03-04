# @alfadocs/oauth2-client

Minimal OAuth2 Authorization Code + PKCE helper for integrating external apps with the AlfaDocs OAuth2 server.

Supports:

- Browser SPAs (PKCE + redirect handling)
- Node.js backends (authorization code exchange + refresh token flow)

## Install

```bash
npm install @alfadocs/oauth2-client
# or
pnpm add @alfadocs/oauth2-client
# or
yarn add @alfadocs/oauth2-client
```

## Supported environments

This library relies on standard web platform APIs: `fetch`, `URL`, `URLSearchParams`, and Web Crypto (`crypto.subtle`).

- **Browser**: modern browsers are supported out of the box.
- **Node.js 18+**: `fetch`, `URL`, `URLSearchParams`, and `crypto.subtle` are available globally; no polyfills required.
- **Node.js < 18**:
  - You must provide a `fetch` polyfill (for example, `node-fetch`).
  - For `createPkcePair`, you also need a Web Crypto–compatible polyfill, or generate PKCE values yourself.

**Recommended architecture**

- Frontend (browser): start the authorization flow using PKCE (`createPkcePair`, `buildAuthorizeUrl`, `parseCallback`).
- Backend (Node.js): perform token exchange and refresh using `exchangeCodeForToken` and `refreshAccessToken`.

## Usage – Browser SPA (PKCE)

```ts
import {
  createPkcePair,
  buildAuthorizeUrl,
  parseCallback,
} from '@alfadocs/oauth2-client';

const config = {
  // You can omit these to use production defaults:
  // authorizeEndpoint: 'https://app.alfadocs.com/oauth2/authorize',
  // tokenEndpoint: 'https://app.alfadocs.com/oauth2/token',
  clientId: 'your-client-id',
  redirectUri: 'https://your-app.example.com/oauth/callback',
  scopes: ['patient:view'],
};

// 1) On "Login with AlfaDocs" click
async function startLogin() {
  const pkce = await createPkcePair();
  sessionStorage.setItem('pkce_verifier', pkce.codeVerifier);

  const state = crypto.randomUUID();
  sessionStorage.setItem('oauth_state', state);

  const url = buildAuthorizeUrl(config, { state, pkce });
  window.location.href = url;
}

// 2) On /oauth/callback route
async function handleCallback() {
  const { code, state, error, error_description } = parseCallback(window.location.href);
  if (error) throw new Error(error_description || error);
  if (!code) throw new Error('Missing authorization code');

  const expectedState = sessionStorage.getItem('oauth_state');
  if (state !== expectedState) throw new Error('Invalid state');

  const codeVerifier = sessionStorage.getItem('pkce_verifier') || undefined;

  // Typically you would POST `code` (and `codeVerifier`) to your backend,
  // and call `exchangeCodeForToken` there. See the Node.js example below.
}
```

## Usage – Node.js backend (authorization code + refresh)

```ts
import {
  exchangeCodeForToken,
  refreshAccessToken,
  type OAuth2ClientConfig,
} from '@alfadocs/oauth2-client';

const config: OAuth2ClientConfig = {
  // You can omit these to use production defaults:
  // authorizeEndpoint: 'https://app.alfadocs.com/oauth2/authorize',
  // tokenEndpoint: 'https://app.alfadocs.com/oauth2/token',
  clientId: process.env.ALFADOCS_CLIENT_ID!,
  redirectUri: 'https://your-app.example.com/oauth/callback',
  scopes: ['patient:view'],
};

// 1) Exchange authorization code for tokens
async function exchangeCode(authCode: string, codeVerifier?: string) {
  const tokenResponse = await exchangeCodeForToken({
    config,
    code: authCode,
    codeVerifier,
    clientSecret: process.env.ALFADOCS_CLIENT_SECRET, // for confidential clients
  });

  // Persist tokenResponse.access_token and tokenResponse.refresh_token securely
  return tokenResponse;
}

// 2) Refresh access token using refresh_token
async function refreshTokens(refreshToken: string) {
  const refreshed = await refreshAccessToken({
    config,
    refreshToken,
    clientSecret: process.env.ALFADOCS_CLIENT_SECRET, // for confidential clients
  });

  // Persist refreshed.access_token (and refreshed.refresh_token if rotated)
  return refreshed;
}
```

## Token expiry and refresh

Before using the access token, call `isTokenExpiredOrExpiringSoon(tokenResponse, { obtainedAt, bufferSeconds })` to decide if you should refresh.

- **If it returns `true`** and you have a `refresh_token`, call `refreshAccessToken(...)`, then replace the stored token response and store a new `obtainedAt` (e.g. `Date.now()`). Your app is responsible for storage; the library only provides the predicate and `refreshAccessToken`.
- **Options:**
  - `obtainedAt`: timestamp in ms when the access token was issued (default `0` if omitted).
  - `bufferSeconds`: treat the token as expiring if it expires within this many seconds (default `10`).

Example:

```ts
import {
  isTokenExpiredOrExpiringSoon,
  refreshAccessToken,
  type TokenExpiryCheckOptions,
} from '@alfadocs/oauth2-client';

// When about to use the token (e.g. before an API call):
const options: TokenExpiryCheckOptions = {
  obtainedAt: storedObtainedAt, // ms when you received the token
  bufferSeconds: 10,
};
if (isTokenExpiredOrExpiringSoon(storedTokenResponse, options) && storedTokenResponse.refresh_token) {
  const refreshed = await refreshAccessToken({ config, refreshToken: storedTokenResponse.refresh_token, clientSecret });
  storedTokenResponse = refreshed;
  storedObtainedAt = Date.now();
}
// Use storedTokenResponse.access_token
```

