-- Hooked: cloud saves table. Paste this into Supabase > SQL Editor > New query > Run.
create table if not exists public.saves (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null,
  xp integer default 0,
  updated_at timestamptz default now()
);
alter table public.saves enable row level security;
drop policy if exists "read own save" on public.saves;
drop policy if exists "create own save" on public.saves;
drop policy if exists "update own save" on public.saves;
create policy "read own save"   on public.saves for select using (auth.uid() = user_id);
create policy "create own save" on public.saves for insert with check (auth.uid() = user_id);
create policy "update own save" on public.saves for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
