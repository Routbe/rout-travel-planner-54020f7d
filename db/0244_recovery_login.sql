-- 0244: sign-in by recovery (/recovery) for a member who is locked out.
--
-- 1. Each ceremony stores the PUBLIC half of an Ed25519 login key derived from
--    the Master Key. Only a Master Key rebuilt from two factors can sign the
--    server's one-time challenge. Ceremonies made before this file have no
--    login key and must be set up again before they can be used to sign in.
-- 2. The ceremony save function takes that key (old 7-argument form dropped).
-- 3. A login-key read for the server, still scoped to the member context.
-- 4. E-mail security codes accept the purpose 'recovery' (ROUT's own factor
--    is released only after the member proves access to the account e-mail).
alter table public.recovery_ceremonies add column if not exists login_key text
  check (login_key is null or login_key ~ '^[A-Za-z0-9+/]{43}=$');

drop function if exists public.rout_recovery_ceremony_put(text, text, text, text, text, text, text);
create or replace function public.rout_recovery_ceremony_put(
  p_ceremony_id text, p_key_id text, p_sealed_master text,
  p_device_shard text, p_paper_shard text, p_server_shard text, p_device_credential text, p_login_key text)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null then raise exception 'no member context' using errcode = '42501'; end if;
  if p_login_key is null then raise exception 'login key required' using errcode = '22023'; end if;
  insert into public.recovery_ceremonies as c
    (user_id, ceremony_id, key_id, sealed_master, device_shard, paper_shard, server_shard, device_credential, login_key, created_at)
  values (v_user, p_ceremony_id, p_key_id, p_sealed_master, p_device_shard, p_paper_shard, p_server_shard, p_device_credential, p_login_key, pg_catalog.now())
  on conflict (user_id) do update set
    ceremony_id = excluded.ceremony_id, key_id = excluded.key_id, sealed_master = excluded.sealed_master,
    device_shard = excluded.device_shard, paper_shard = excluded.paper_shard, server_shard = excluded.server_shard,
    device_credential = excluded.device_credential, login_key = excluded.login_key, created_at = excluded.created_at;
end $$;

create or replace function public.rout_recovery_ceremony_login_key()
returns text language sql stable security definer set search_path = pg_catalog as $$
  select c.login_key from public.recovery_ceremonies c where c.user_id = public.rout_current_user_id();
$$;

do $$
declare f text;
begin
  foreach f in array array[
    'public.rout_recovery_ceremony_put(text,text,text,text,text,text,text,text)',
    'public.rout_recovery_ceremony_login_key()'] loop
    execute format('revoke all on function %s from public', f);
    execute format('grant execute on function %s to rout_app', f);
  end loop;
end $$;

create or replace function public.rout_security_code_issue(p_user uuid, p_purpose text, p_code_hash text, p_ttl_minutes integer)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null or p_user is distinct from v_user then return 'no_context'; end if;
  if p_purpose is null or p_purpose not in ('merge', 'password', 'two_factor', 'workspace_convert',
       'delete_account', 'identity_link', 'step_up', 'step_up_sms', 'recovery')
     or p_code_hash is null or p_code_hash !~ '^[A-Za-z0-9+/]{43}=$'
     or p_ttl_minutes is null or p_ttl_minutes not between 1 and 15 then
    return 'invalid';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('rout.security_code:' || v_user::text || ':' || p_purpose, 0));
  if (select count(*) from public.security_codes
       where user_id = v_user and purpose = p_purpose and created_at > now() - interval '15 minutes') >= 5 then
    return 'rate_limited';
  end if;
  update public.security_codes set consumed_at = now()
   where user_id = v_user and purpose = p_purpose and consumed_at is null;
  insert into public.security_codes (user_id, purpose, code_hash, expires_at)
  values (v_user, p_purpose, p_code_hash, now() + make_interval(mins => p_ttl_minutes));
  return 'ok';
end $$;
