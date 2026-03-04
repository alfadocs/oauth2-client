"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_TOKEN_ENDPOINT = exports.DEFAULT_AUTHORIZE_ENDPOINT = void 0;
exports.createPkcePair = createPkcePair;
exports.buildAuthorizeUrl = buildAuthorizeUrl;
exports.parseCallback = parseCallback;
exports.exchangeCodeForToken = exchangeCodeForToken;
// --- Defaults for production AlfaDocs environment ---
exports.DEFAULT_AUTHORIZE_ENDPOINT = "https://app.alfadocs.com/oauth2/authorize";
exports.DEFAULT_TOKEN_ENDPOINT = "https://app.alfadocs.com/oauth2/token";
// --- PKCE helpers (browser) ---
function getCrypto() {
    // Works in both browser and Node 18+ (Web Crypto on globalThis)
    if (typeof globalThis !== "undefined" && globalThis.crypto) {
        return globalThis.crypto;
    }
    throw new Error("globalThis.crypto is not available; PKCE helpers require a browser or a crypto polyfill");
}
function base64UrlEncode(bytes) {
    const binary = String.fromCharCode(...new Uint8Array(bytes));
    const base64 = btoa(binary);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function createPkcePair(length = 64) {
    const crypto = getCrypto();
    const random = new Uint8Array(length);
    crypto.getRandomValues(random);
    const codeVerifier = Array.from(random)
        .map(b => (b % 36).toString(36))
        .join("");
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const codeChallenge = base64UrlEncode(digest);
    return { codeVerifier, codeChallenge };
}
// --- Authorization URL builder ---
function buildAuthorizeUrl(config, params = {}) {
    var _a;
    const url = new URL((_a = config.authorizeEndpoint) !== null && _a !== void 0 ? _a : exports.DEFAULT_AUTHORIZE_ENDPOINT);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    if (config.scopes && config.scopes.length > 0) {
        url.searchParams.set("scope", config.scopes.join(" "));
    }
    if (params.state) {
        url.searchParams.set("state", params.state);
    }
    if (params.pkce) {
        url.searchParams.set("code_challenge", params.pkce.codeChallenge);
        url.searchParams.set("code_challenge_method", "S256");
    }
    if (params.extraParams) {
        for (const [key, value] of Object.entries(params.extraParams)) {
            url.searchParams.set(key, value);
        }
    }
    return url.toString();
}
function parseCallback(urlLike) {
    const url = new URL(urlLike, "http://dummy");
    const params = url.searchParams;
    const result = {};
    if (params.has("code")) {
        result.code = params.get("code") || undefined;
    }
    if (params.has("state")) {
        result.state = params.get("state") || undefined;
    }
    if (params.has("error")) {
        result.error = params.get("error") || undefined;
        result.error_description = params.get("error_description") || undefined;
    }
    return result;
}
async function exchangeCodeForToken({ config, code, codeVerifier, clientSecret, extraParams = {}, }) {
    var _a;
    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", config.redirectUri);
    body.set("client_id", config.clientId);
    if (codeVerifier) {
        body.set("code_verifier", codeVerifier);
    }
    if (clientSecret) {
        body.set("client_secret", clientSecret);
    }
    for (const [key, value] of Object.entries(extraParams)) {
        body.set(key, value);
    }
    const tokenEndpoint = (_a = config.tokenEndpoint) !== null && _a !== void 0 ? _a : exports.DEFAULT_TOKEN_ENDPOINT;
    const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
    });
    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Token endpoint returned ${response.status}: ${text}`);
    }
    return (await response.json());
}
