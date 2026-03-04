# @alfadocs/oauth2-client

Minimal OAuth2 Authorization Code + PKCE helper for integrating external apps with the AlfaDocs OAuth2 server.

## Install

```bash
npm install @alfadocs/oauth2-client
# or
pnpm add @alfadocs/oauth2-client
# or
yarn add @alfadocs/oauth2-client
```

## Usage (browser SPA)

```ts
import {
  createPkcePair,
  buildAuthorizeUrl,
  parseCallback,
  exchangeCodeForToken,
} from '@alfadocs/oauth2-client';

const config = {
  authorizeEndpoint: 'https://app.alfadocs.loc/oauth2/authorize',
  tokenEndpoint: 'https://app.alfadocs.loc/oauth2/token',
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

  const tokenResponse = await exchangeCodeForToken({
    config,
    code,
    codeVerifier,
  });

  // tokenResponse.access_token is the Bearer token to call your APIs
}
```

This package assumes a browser environment with `window.crypto` and `fetch`. For Node.js, you need to provide compatible polyfills.

