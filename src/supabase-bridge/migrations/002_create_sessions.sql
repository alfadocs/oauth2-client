create table if not exists public.sessions (
  cookie_value text primary key,
  user_id text not null references public.users(id) on delete cascade,
  expires_at timestamptz not null default (now() + interval '7 days'),
  created_at timestamptz not null default now()
);

alter table public.sessions
  add column if not exists expires_at timestamptz not null default (now() + interval '7 days');

create index if not exists sessions_user_id_idx on public.sessions(user_id);
create index if not exists sessions_expires_at_idx on public.sessions(expires_at);
