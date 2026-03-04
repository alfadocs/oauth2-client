export interface OAuth2ClientConfig {
    /**
     * Optional override for the authorization endpoint.
     * Defaults to production: https://app.alfadocs.com/oauth2/authorize
     */
    authorizeEndpoint?: string;
    /**
     * Optional override for the token endpoint.
     * Defaults to production: https://app.alfadocs.com/oauth2/token
     */
    tokenEndpoint?: string;
    clientId: string;
    redirectUri: string;
    scopes?: string[];
}
export interface PkcePair {
    codeVerifier: string;
    codeChallenge: string;
}
export interface AuthorizeUrlParams {
    state?: string;
    pkce?: PkcePair;
    extraParams?: Record<string, string>;
}
export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    scope?: string;
    [key: string]: unknown;
}
export declare const DEFAULT_AUTHORIZE_ENDPOINT = "https://app.alfadocs.com/oauth2/authorize";
export declare const DEFAULT_TOKEN_ENDPOINT = "https://app.alfadocs.com/oauth2/token";
export declare function createPkcePair(length?: number): Promise<PkcePair>;
export declare function buildAuthorizeUrl(config: OAuth2ClientConfig, params?: AuthorizeUrlParams): string;
export interface ParsedCallback {
    code?: string;
    state?: string;
    error?: string;
    error_description?: string;
}
export declare function parseCallback(urlLike: string): ParsedCallback;
export interface ExchangeCodeParams {
    config: OAuth2ClientConfig;
    code: string;
    codeVerifier?: string;
    clientSecret?: string;
    extraParams?: Record<string, string>;
}
export declare function exchangeCodeForToken({ config, code, codeVerifier, clientSecret, extraParams, }: ExchangeCodeParams): Promise<TokenResponse>;
