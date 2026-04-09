import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import dotenv from "dotenv";
import { Agent, fetch as undiciFetch } from "undici";
import { createAlfadocsAuth } from "../../dist/index.js";
import { createSupabaseStorage } from "../../dist/supabase-bridge/index.js";

if (!globalThis.btoa) {
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
dotenv.config({ path: join(__dirname, ".env") });

const PORT = Number(process.env.PORT ?? 8787);
const APP_ORIGIN = process.env.APP_ORIGIN ?? `http://localhost:${PORT}`;

const required = [
  "ALFADOCS_CLIENT_ID",
  "ALFADOCS_CLIENT_SECRET",
  "ALFADOCS_BASE_URL",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "SUPABASE_DB_URL",
];
for (const key of required) {
  if (!process.env[key]) {
    throw new Error(`Missing required env var: ${key}`);
  }
}

/** Dev-only: self-signed or private CA HTTPS (Alfadocs + Supabase HTTP calls from this server). */
function createTlsInsecureFetch() {
  const agent = new Agent({ connect: { rejectUnauthorized: false } });
  return (input, init) => undiciFetch(input, { ...init, dispatcher: agent });
}

const tlsInsecure =
  process.env.TLS_INSECURE === "1" || process.env.TLS_INSECURE === "true";
const devFetch = tlsInsecure ? createTlsInsecureFetch() : undefined;
if (tlsInsecure) {
  console.warn("[local-app] TLS_INSECURE enabled — do not use in production");
}

/** Optional: space- or comma-separated scopes (default in library is `patient:list`). */
const alfadocsScopes = process.env.ALFADOCS_SCOPES
  ? process.env.ALFADOCS_SCOPES.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  : undefined;

const auth = createAlfadocsAuth({
  clientId: process.env.ALFADOCS_CLIENT_ID,
  clientSecret: process.env.ALFADOCS_CLIENT_SECRET,
  baseUrl: process.env.ALFADOCS_BASE_URL,
  redirectUri: `${APP_ORIGIN}/auth`,
  appOrigin: APP_ORIGIN,
  appPostLoginPath: "/",
  cookieSecure: false,
  oauthDebug: process.env.ALFADOCS_DEBUG_OAUTH === "1",
  ...(alfadocsScopes && alfadocsScopes.length > 0 ? { scopes: alfadocsScopes } : {}),
  ...(devFetch ? { fetch: devFetch } : {}),
  storage: createSupabaseStorage({
    supabaseUrl: process.env.SUPABASE_URL,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    databaseUrl: process.env.SUPABASE_DB_URL,
    ...(devFetch ? { fetch: devFetch } : {}),
  }),
});

function toRequest(req) {
  const url = new URL(req.url ?? "/", APP_ORIGIN);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) headers.set(k, v.join(", "));
    else if (typeof v === "string") headers.set(k, v);
  }

  if (req.method === "GET" || req.method === "HEAD") {
    return new Request(url, { method: req.method, headers });
  }

  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      resolve(new Request(url, { method: req.method, headers, body }));
    });
  });
}

async function writeResponse(nodeRes, webRes) {
  nodeRes.statusCode = webRes.status;
  // Preserve multiple Set-Cookie headers; collapsing them breaks cookie handling.
  const setCookies =
    typeof webRes.headers.getSetCookie === "function"
      ? webRes.headers.getSetCookie()
      : [];
  if (setCookies.length > 0) {
    nodeRes.setHeader("Set-Cookie", setCookies);
  }
  webRes.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") return;
    nodeRes.setHeader(key, value);
  });
  if (!webRes.body) {
    nodeRes.end();
    return;
  }
  const text = await webRes.text();
  nodeRes.end(text);
}

const server = createServer(async (req, res) => {
  const pathname = new URL(req.url ?? "/", APP_ORIGIN).pathname;

  if (pathname === "/") {
    const html = await readFile(join(__dirname, "index.html"), "utf8");
    res.statusCode = 200;
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.end(html);
    return;
  }

  if (pathname === "/auth") {
    const webReq = await toRequest(req);
    const webRes = await auth.handleRequest(webReq);
    await writeResponse(res, webRes);
    return;
  }

  res.statusCode = 404;
  res.end("Not Found");
});

server.listen(PORT, () => {
  console.log(`Local auth test app running at ${APP_ORIGIN}`);
  console.log(`Open ${APP_ORIGIN}`);
});
