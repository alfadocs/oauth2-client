create table if not exists public.users (
  id text primary key,
  username text not null,
  auth_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
