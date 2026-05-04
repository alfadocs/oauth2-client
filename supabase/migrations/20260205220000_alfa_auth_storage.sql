-- Alfadocs auth: multi-tenant `alfa_users` / `alfa_sessions` in `public` (no RPC — bridge uses PostgREST only).
-- Drops legacy helper if present. Idempotent.

DROP FUNCTION IF EXISTS public.alfadocs_auth_ensure_schema(text);

CREATE TABLE IF NOT EXISTS public.alfa_users (
  app_id text NOT NULL,
  id text NOT NULL,
  username text NOT NULL,
  auth_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, id)
);

CREATE TABLE IF NOT EXISTS public.alfa_sessions (
  app_id text NOT NULL,
  cookie_value text NOT NULL,
  user_id text NOT NULL,
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, cookie_value),
  FOREIGN KEY (app_id, user_id) REFERENCES public.alfa_users (app_id, id) ON DELETE CASCADE
);

ALTER TABLE public.alfa_sessions
  ADD COLUMN IF NOT EXISTS expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days');

CREATE INDEX IF NOT EXISTS alfa_sessions_app_user_idx ON public.alfa_sessions (app_id, user_id);
CREATE INDEX IF NOT EXISTS alfa_sessions_app_expires_idx ON public.alfa_sessions (app_id, expires_at);

-- RLS on, no policies: blocks anon/authenticated PostgREST access if keys leak to the browser.
-- The service_role JWT used by this bridge bypasses RLS in Supabase.
ALTER TABLE public.alfa_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alfa_sessions ENABLE ROW LEVEL SECURITY;

NOTIFY pgrst, 'reload schema';
