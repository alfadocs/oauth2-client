@alfadocs/oauth2-client
========================

Backend‑first **Alfadocs auth library and Supabase identity bridge**.

> **Proposal**  
> This package started as a simple “OAuth 2.0 client” experiment, but the current design is a full **Alfadocs auth library and Supabase identity bridge** (OAuth2/OIDC, opaque browser session, user mapping, RLS integration).  
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
  - Intended to live as `@alfadocs/auth` and be usable from any backend (Supabase Edge Functions, Next.js API routes, etc.).

- **Supabase adapter (optional)** – “Alfadocs ↔ Supabase bridge”
  - Builds on top of the core package and adds:
    - 1‑1 mapping between Alfadocs users and Supabase users.
    - Helpers to mint per‑request Supabase JWTs for RLS.
  - Conceptually this would live as `@alfadocs/auth-supabase` or `@alfadocs/auth/supabase`.

## How will it work conceptually

Below is the pseudo code explaining how it should work


======= Supabase edge function called auth ========

import { createAlfadocsAuth } from "@alfadocs/auth"

const auth = createAlfadocsAuth({
  clientId: process.env.ALFADOCS_CLIENT_ID,
  clientSecret: process.env.ALFADOCS_CLIENT_SECRET,
  redirectUri: process.env.ALFADOCS_REDIRECT_URI,
  storageAccessKey: process.env.ALFADOCS_STORAGE_ACCESS_KEY,
})

return auth.handleAuthRequest(req);


======= handleAuthRequest function in the @alfadocs/auth package ========

export const handleAuthRequest = async (req: NextRequest) => {
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
}

======= handleLogin function in the @alfadocs/auth package ========

export const handleLogin = async (req: NextRequest) => {
    // check if the sesssion is already there in the cookie
    const cookie = req.cookies.get("alfadocs_session");
    if (cookie) {
        return NextResponse.json({ error: "Already logged in" }, { status: 400 });
    }
    // redirect to the Alfadocs login page
    return NextResponse.redirect(new URL("https://app.alfadocs.com/login", req.url));
}

======= handleCallback function in the @alfadocs/auth package ========

export const handleCallback = async (req: NextRequest) => {
    // check if the sesssion is already there in the cookie
    const cookie = req.cookies.get("alfadocs_session");
    if (cookie) {
        return NextResponse.json({ error: "Already logged in" }, { status: 400 });
    }

    // get the code from the query params
    const code = req.nextUrl.searchParams.get("code");
    if (!code) {
        return NextResponse.json({ error: "No code provided" }, { status: 400 });
    }
    // exchange the code for a session
    const session = await auth.exchangeCodeForSession(code);
    if (!session) {
        return NextResponse.json({ error: "Failed to exchange code for session" }, { status: 400 });
    }


    consr user = await Storage.getUser(session.userId);

    if (!user) {
        // create a new user in the database
        const newUser = await Storage.createUser(session.userId);
        if (!newUser) {
            return NextResponse.json({ error: "Failed to create user" }, { status: 400 });
        }

        for (const plugin of this.plugins) {
            extraData = await plugin.onUserCreated(newUser);
            if (extraData) {
                newUser.extraData = extraData;
                Storage.updateUser(newUser);
            }
        }

    }

    // create a new session in the database
    const newSession = await Storage.createSession(session.userId, session.accessToken, session.refreshToken, session.expiresAt);
    if (!newSession) {
        return NextResponse.json({ error: "Failed to create session" }, { status: 400 });
    }

    // set the session in the cookie
    req.cookies.set("alfadocs_session", newSession.id);

    return NextResponse.redirect(new URL("/", req.url));
}

======= Supabase edge function called getAlfadocsPatients ========

import { createAlfadocsAuth } from "@alfadocs/auth"

const auth = createAlfadocsAuth({
  clientId: process.env.ALFADOCS_CLIENT_ID,
  clientSecret: process.env.ALFADOCS_CLIENT_SECRET,
  redirectUri: process.env.ALFADOCS_REDIRECT_URI,
})

$userSession = auth.requireUser(req);

// request Alfadocs API with the access token
const response = await fetch("https://api.alfadocs.com/v1/patients", {
    headers: {
        "Authorization": `Bearer ${userSession.alfadocs.accessToken}`
    }
});
const data = await response.json();
return data;


======= requireUser function in the @alfadocs/auth package ========

export const requireUser = async (req: NextRequest) => {
    // check the cookie
    const cookie = req.cookies.get("alfadocs_session");
    if (!cookie) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    // check the session
    const session = storage.getSession(cookie.value);
    if (!session) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    return session;
}

======= Supabase edge function called saveDentalStateOfPatient ========


import { createAlfadocsAuth } from "@alfadocs/auth"
import { createSupabaseJwtBasedOnAlfadocsSession } from "@alfadocs/auth/supabase-bridge"

const auth = createAlfadocsAuth({
  clientId: process.env.ALFADOCS_CLIENT_ID,
  clientSecret: process.env.ALFADOCS_CLIENT_SECRET,
  redirectUri: process.env.ALFADOCS_REDIRECT_URI,
})

$userSession = auth.requireUser(req);

const session = await auth.requireSession(req)

  // 1) Mint a short-lived Supabase JWT for this user
  const supabaseJwt = createSupabaseJwtBasedOnAlfadocsSession({
    alfadocsSession: userSession,
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
  const { data } = await supabase.from("dental_state_of_patient").insert({
    patient_id: patientId,
    dental_state: dentalState,
  })

  return data;
