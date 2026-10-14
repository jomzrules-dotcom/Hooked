-- Hooked: username + password accounts and player saves (no email needed).
-- Paste ALL of this into Supabase > SQL Editor > New query > Run. Safe to run again.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.hk_accounts (
  id           uuid primary key default gen_random_uuid(),
  username     text not null,
  username_lc  text not null unique,
  pass_hash    text not null,
  fails        int  not null default 0,
  locked_until timestamptz,
  created_at   timestamptz not null default now()
);

create table if not exists public.hk_sessions (
  token      text primary key,
  account_id uuid not null references public.hk_accounts(id) on delete cascade,
  created_at timestamptz not null default now(),
  last_used  timestamptz not null default now()
);

create table if not exists public.hk_saves (
  account_id     uuid primary key references public.hk_accounts(id) on delete cascade,
  username       text,
  level          int  default 1,
  xp             int  default 0,
  coins          int  default 0,
  species        int  default 0,
  fish_caught    text[] default '{}',
  fish_best_cm   jsonb default '{}',
  fish_counts    jsonb default '{}',
  rods_owned     text[] default '{}',
  rod_equipped   text,
  bait           jsonb default '{}',
  bait_equipped  text,
  hats           text[] default '{}',
  maps_completed text[] default '{}',
  character      jsonb,
  lures_owned    text[] default '{}',
  lure_equipped  text,
  data           jsonb not null default '{}',
  updated_at     timestamptz not null default now()
);

-- Lock the tables: no direct access from the game. Everything goes through the functions below.
alter table public.hk_accounts enable row level security;
alter table public.hk_sessions enable row level security;
alter table public.hk_saves    enable row level security;
revoke all on public.hk_accounts, public.hk_sessions, public.hk_saves from anon, authenticated;

alter table public.hk_saves add column if not exists lures_owned text[] default '{}';
alter table public.hk_saves add column if not exists lure_equipped text;

create or replace function public.hk_txt(j jsonb) returns text[] language sql immutable as $$
  select coalesce(array(select jsonb_array_elements_text(case when jsonb_typeof(j)='array' then j else '[]'::jsonb end)), '{}')
$$;

create or replace function public.hk_write(p_acc uuid, p_data jsonb, p_cols jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into hk_saves(account_id, username, level, xp, coins, species, fish_caught, fish_best_cm, fish_counts,
                       rods_owned, rod_equipped, bait, bait_equipped, hats, maps_completed, character, lures_owned, lure_equipped, data, updated_at)
  select p_acc, a.username,
         coalesce((p_cols->>'level')::int,1), coalesce((p_cols->>'xp')::int,0), coalesce((p_cols->>'coins')::int,0),
         coalesce((p_cols->>'species')::int,0), hk_txt(p_cols->'fish_caught'), coalesce(p_cols->'fish_best_cm','{}'),
         coalesce(p_cols->'fish_counts','{}'), hk_txt(p_cols->'rods_owned'), p_cols->>'rod_equipped',
         coalesce(p_cols->'bait','{}'), p_cols->>'bait_equipped', hk_txt(p_cols->'hats'), hk_txt(p_cols->'maps_completed'),
         p_cols->'character', hk_txt(p_cols->'lures_owned'), p_cols->>'lure_equipped', coalesce(p_data,'{}'), now()
  from hk_accounts a where a.id = p_acc
  on conflict (account_id) do update set
    username=excluded.username, level=excluded.level, xp=excluded.xp, coins=excluded.coins, species=excluded.species,
    fish_caught=excluded.fish_caught, fish_best_cm=excluded.fish_best_cm, fish_counts=excluded.fish_counts,
    rods_owned=excluded.rods_owned, rod_equipped=excluded.rod_equipped, bait=excluded.bait, bait_equipped=excluded.bait_equipped,
    hats=excluded.hats, maps_completed=excluded.maps_completed, character=excluded.character, lures_owned=excluded.lures_owned, lure_equipped=excluded.lure_equipped, data=excluded.data, updated_at=now();
end $$;

create or replace function public.hk_new_session(p_acc uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(gen_random_bytes(24), 'hex');
begin
  insert into hk_sessions(token, account_id) values (t, p_acc);
  return t;
end $$;

create or replace function public.hk_register(p_username text, p_password text, p_data jsonb default null, p_cols jsonb default '{}')
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare a uuid; u text := btrim(p_username);
begin
  if u !~ '^[A-Za-z0-9_]{3,20}$' then raise exception 'bad_username'; end if;
  if length(coalesce(p_password,'')) < 6 then raise exception 'short_password'; end if;
  if exists(select 1 from hk_accounts where username_lc = lower(u)) then raise exception 'username_taken'; end if;
  insert into hk_accounts(username, username_lc, pass_hash) values (u, lower(u), crypt(p_password, gen_salt('bf', 8))) returning id into a;
  if p_data is not null then perform hk_write(a, p_data, p_cols); end if;
  return jsonb_build_object('token', hk_new_session(a), 'username', u, 'account', a);
exception when unique_violation then raise exception 'username_taken';
end $$;

create or replace function public.hk_login(p_username text, p_password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare r hk_accounts%rowtype; d jsonb;
begin
  select * into r from hk_accounts where username_lc = lower(btrim(p_username));
  if not found then return jsonb_build_object('error', 'bad_login'); end if;
  if r.locked_until is not null and r.locked_until > now() then return jsonb_build_object('error', 'locked'); end if;
  if r.pass_hash <> crypt(p_password, r.pass_hash) then
    update hk_accounts set
      locked_until = case when fails + 1 >= 10 then now() + interval '5 minutes' else null end,
      fails = case when fails + 1 >= 10 then 0 else fails + 1 end
    where id = r.id;
    return jsonb_build_object('error', 'bad_login');
  end if;
  update hk_accounts set fails = 0, locked_until = null where id = r.id;
  select data into d from hk_saves where account_id = r.id;
  return jsonb_build_object('token', hk_new_session(r.id), 'username', r.username, 'account', r.id, 'data', d);
end $$;

create or replace function public.hk_acc(p_token text) returns uuid
language plpgsql security definer set search_path = public as $$
declare a uuid;
begin
  update hk_sessions set last_used = now() where token = p_token returning account_id into a;
  if a is null then raise exception 'bad_session'; end if;
  return a;
end $$;

create or replace function public.hk_load(p_token text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare a uuid := hk_acc(p_token); d jsonb; u text;
begin
  select username into u from hk_accounts where id = a;
  select data into d from hk_saves where account_id = a;
  return jsonb_build_object('username', u, 'account', a, 'data', d);
end $$;

create or replace function public.hk_save(p_token text, p_data jsonb, p_cols jsonb default '{}') returns timestamptz
language plpgsql security definer set search_path = public as $$
begin
  perform hk_write(hk_acc(p_token), p_data, p_cols);
  return now();
end $$;

create or replace function public.hk_logout(p_token text) returns void
language sql security definer set search_path = public as $$ delete from hk_sessions where token = p_token $$;

create or replace function public.hk_change_password(p_token text, p_old text, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare a uuid := hk_acc(p_token);
begin
  if length(coalesce(p_new,'')) < 6 then raise exception 'short_password'; end if;
  if not exists(select 1 from hk_accounts where id = a and pass_hash = crypt(p_old, pass_hash)) then raise exception 'bad_login'; end if;
  update hk_accounts set pass_hash = crypt(p_new, gen_salt('bf', 8)) where id = a;
  delete from hk_sessions where account_id = a and token <> p_token;
end $$;

-- Only these actions are callable from the game.
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.hk_register(text,text,jsonb,jsonb), public.hk_login(text,text), public.hk_load(text),
  public.hk_save(text,jsonb,jsonb), public.hk_logout(text), public.hk_change_password(text,text,text) to anon, authenticated;

notify pgrst, 'reload schema';
