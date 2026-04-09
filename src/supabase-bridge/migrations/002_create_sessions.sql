create table if not exists public.sessions (
  cookie_value text primary key,
  user_id text not null references public.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create index if not exists sessions_user_id_idx on public.sessions(user_id);
