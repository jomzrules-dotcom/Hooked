-- Hooked: player saves. Paste into Supabase > SQL Editor > New query > Run.
-- Safe to run more than once.
create table if not exists public.saves (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null,
  updated_at timestamptz default now()
);
alter table public.saves add column if not exists username        text;
alter table public.saves add column if not exists level           integer default 1;
alter table public.saves add column if not exists xp              integer default 0;
alter table public.saves add column if not exists coins           integer default 0;
alter table public.saves add column if not exists species         integer default 0;
alter table public.saves add column if not exists fish_caught     text[]  default '{}';
alter table public.saves add column if not exists fish_best_cm    jsonb   default '{}';
alter table public.saves add column if not exists fish_counts     jsonb   default '{}';
alter table public.saves add column if not exists rods_owned      text[]  default '{}';
alter table public.saves add column if not exists rod_equipped    text;
alter table public.saves add column if not exists bait            jsonb   default '{}';
alter table public.saves add column if not exists bait_equipped   text;
alter table public.saves add column if not exists hats            text[]  default '{}';
alter table public.saves add column if not exists maps_completed  text[]  default '{}';
alter table public.saves add column if not exists character       jsonb;

alter table public.saves enable row level security;
drop policy if exists "read own save"   on public.saves;
drop policy if exists "create own save" on public.saves;
drop policy if exists "update own save" on public.saves;
create policy "read own save"   on public.saves for select using (auth.uid() = user_id);
create policy "create own save" on public.saves for insert with check (auth.uid() = user_id);
create policy "update own save" on public.saves for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
notify pgrst, 'reload schema';
