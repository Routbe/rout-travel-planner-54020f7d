-- 0242: 2-of-3 recovery ceremony (passkey + 24 paper words + ROUT's server piece).
--
-- One row per member. It holds only RVE1 envelopes (base64): the Master Key
-- sealed under a one-off ceremony key, and the three Shamir shares of that key,
-- each sealed to one factor. The server can open only its own share, so ROUT
-- alone never reaches the Master Key; any two factors do.
--
-- rout_app has no rights on the table. The functions below take the member from
-- the transaction context (rout_current_user_id()), never from an argument.
create table if not exists public.recovery_ceremonies (
  user_id uuid primary key references public.users(id) on delete cascade,
  ceremony_id text not null check (ceremony_id ~ '^[0-9a-f]{32}$'),
  key_id text not null check (char_length(key_id) between 8 and 200),
  sealed_master text not null check (char_length(sealed_master) between 40 and 400 and sealed_master ~ '^[A-Za-z0-9+/]+={0,2}$'),
  device_shard text not null check (char_length(device_shard) between 64 and 6000 and device_shard ~ '^[A-Za-z0-9+/]+={0,2}$'),
  paper_shard text not null check (char_length(paper_shard) between 64 and 6000 and paper_shard ~ '^[A-Za-z0-9+/]+={0,2}$'),
  server_shard text not null check (char_length(server_shard) between 64 and 6000 and server_shard ~ '^[A-Za-z0-9+/]+={0,2}$'),
  device_credential text not null check (char_length(device_credential) between 8 and 1400 and device_credential ~ '^[A-Za-z0-9+/=_-]+$'),
  created_at timestamptz not null default now()
);
alter table public.recovery_ceremonies enable row level security;
alter table public.recovery_ceremonies force row level security;
revoke all on table public.recovery_ceremonies from public, rout_app;

create or replace function public.rout_recovery_ceremony_put(
  p_ceremony_id text, p_key_id text, p_sealed_master text,
  p_device_shard text, p_paper_shard text, p_server_shard text, p_device_credential text)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null then raise exception 'no member context' using errcode = '42501'; end if;
  insert into public.recovery_ceremonies as c
    (user_id, ceremony_id, key_id, sealed_master, device_shard, paper_shard, server_shard, device_credential, created_at)
  values (v_user, p_ceremony_id, p_key_id, p_sealed_master, p_device_shard, p_paper_shard, p_server_shard, p_device_credential, pg_catalog.now())
  on conflict (user_id) do update set
    ceremony_id = excluded.ceremony_id, key_id = excluded.key_id, sealed_master = excluded.sealed_master,
    device_shard = excluded.device_shard, paper_shard = excluded.paper_shard, server_shard = excluded.server_shard,
    device_credential = excluded.device_credential, created_at = excluded.created_at;
end $$;

-- Status only: no envelope leaves through this function.
create or replace function public.rout_recovery_ceremony_status()
returns table (ceremony_id text, key_id text, created_at timestamptz)
language sql stable security definer set search_path = pg_catalog as $$
  select c.ceremony_id, c.key_id, c.created_at from public.recovery_ceremonies c
   where c.user_id = public.rout_current_user_id();
$$;

-- The full row for a restore on a signed-in device (rate limited and mailed by the app).
create or replace function public.rout_recovery_ceremony_get()
returns table (ceremony_id text, key_id text, sealed_master text, device_shard text, paper_shard text, server_shard text, device_credential text)
language sql stable security definer set search_path = pg_catalog as $$
  select c.ceremony_id, c.key_id, c.sealed_master, c.device_shard, c.paper_shard, c.server_shard, c.device_credential
    from public.recovery_ceremonies c
   where c.user_id = public.rout_current_user_id();
$$;

create or replace function public.rout_recovery_ceremony_delete()
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare n int;
begin
  delete from public.recovery_ceremonies where user_id = public.rout_current_user_id();
  get diagnostics n = row_count;
  return n > 0;
end $$;

do $$
declare f text;
begin
  foreach f in array array[
    'public.rout_recovery_ceremony_put(text,text,text,text,text,text,text)',
    'public.rout_recovery_ceremony_status()',
    'public.rout_recovery_ceremony_get()',
    'public.rout_recovery_ceremony_delete()'] loop
    execute format('revoke all on function %s from public', f);
    execute format('grant execute on function %s to rout_app', f);
  end loop;
end $$;

-- Account merge: a secondary account with its own ceremony blocks the merge
-- (its shards are bound to its own member id and Master Key). Same mechanism as 0215.
do $own$ begin execute format('grant rout_merge_executor to %I with inherit true, set true', current_user); end $own$;
grant create on schema public to rout_merge_executor;

do $m$
declare
  v_def text;
  v_new text;
begin
  grant select (user_id) on public.recovery_ceremonies to rout_merge_executor;
  drop policy if exists atomic_merge_guard on public.recovery_ceremonies;
  create policy atomic_merge_guard on public.recovery_ceremonies for select to rout_merge_executor using (true);
  select pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) into v_def;
  if position('merge_blocked:recovery_ceremonies''' in v_def) > 0 then return; end if;
  v_new := regexp_replace(v_def, E'([^\\n]*''merge_blocked:wallets''[^\\n]*\\n)',
    E'\\1 perform public.rout_merge_assert((not exists (select 1 from public.recovery_ceremonies where user_id = v_secondary)), ''merge_blocked:recovery_ceremonies'');\n');
  if v_new = v_def then
    raise exception 'execute_account_merge: guard anchor merge_blocked:wallets not found';
  end if;
  execute v_new;
end $m$;

revoke create on schema public from rout_merge_executor;
do $own$ begin execute format('revoke rout_merge_executor from %I', current_user); end $own$;
