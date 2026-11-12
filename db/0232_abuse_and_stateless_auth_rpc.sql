-- 0232: anti-abuse stores and sign-in steps without a member session through
-- database functions (0223 phase 4, batch 5). EXPAND step: adds functions next
-- to the legacy "rout_server" policies so the deployed code keeps working;
-- db-pending/0233 removes the free table access afterwards.
--
-- Every function works on exactly one key the caller already holds (a hashed
-- bucket, a proof signature, a hashed e-mail, a pending-login hash, a chat id,
-- an instance + redirect pair). Nothing lists rows, so a compromised app role
-- cannot read these stores in bulk. Times always come from the database clock.

-- ------------------------------------------------------------------ rate limits
-- Two-bucket sliding window: increments the current window and returns the
-- previous one; older windows of this bucket are removed on every call and
-- stale windows of all buckets are swept now and then.
create or replace function public.rout_rate_limit_check_and_increment(p_bucket text, p_window_sec int)
returns table (hits int, prev int, now_ms bigint)
language plpgsql volatile security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.now();
  v_start timestamptz;
  v_hits int;
  v_prev int;
begin
  if p_bucket is null or p_bucket !~ '^[^[:space:]]{1,200}$' or p_window_sec is null or p_window_sec not between 1 and 604800 then
    raise exception 'invalid rate limit' using errcode = '22023';
  end if;
  v_start := pg_catalog.to_timestamp(pg_catalog.floor(extract(epoch from v_now) / p_window_sec) * p_window_sec);
  insert into public.rate_limits as r (bucket, window_start, hits) values (p_bucket, v_start, 1)
  on conflict (bucket, window_start) do update set hits = r.hits + 1
  returning r.hits into v_hits;
  select r.hits into v_prev from public.rate_limits r
   where r.bucket = p_bucket and r.window_start = v_start - pg_catalog.make_interval(secs => p_window_sec);
  delete from public.rate_limits r
   where r.bucket = p_bucket and r.window_start < v_start - pg_catalog.make_interval(secs => p_window_sec);
  if pg_catalog.random() < 0.02 then
    delete from public.rate_limits r
     where r.ctid = any (array(select x.ctid from public.rate_limits x
                                where x.window_start < v_now - interval '1 day' limit 500));
  end if;
  hits := v_hits;
  prev := coalesce(v_prev, 0);
  now_ms := (extract(epoch from v_now) * 1000)::bigint;
  return next;
end $$;

-- Read-only: hits of one bucket in the last p_since_sec seconds (never increments).
create or replace function public.rout_rate_limit_peek(p_bucket text, p_since_sec int)
returns int language plpgsql stable security definer set search_path = pg_catalog as $$
declare v int;
begin
  if p_bucket is null or p_bucket !~ '^[^[:space:]]{1,200}$' or p_since_sec is null or p_since_sec not between 1 and 604800 then
    raise exception 'invalid rate limit' using errcode = '22023';
  end if;
  select coalesce(sum(r.hits), 0)::int into v from public.rate_limits r
   where r.bucket = p_bucket and r.window_start > pg_catalog.now() - pg_catalog.make_interval(secs => p_since_sec);
  return v;
end $$;

-- ------------------------------------------------------------------ ALTCHA proofs
-- The app checks the HMAC and the solution (it holds the key); the database
-- burns the signature exactly once and refuses expired or far-future proofs.
create or replace function public.rout_altcha_verify_and_burn(p_signature text, p_expires_at timestamptz)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v text;
begin
  if p_signature is null or p_signature !~ '^[0-9a-f]{64}$' or p_expires_at is null then return 'invalid'; end if;
  if p_expires_at <= pg_catalog.now() then return 'expired'; end if;
  if p_expires_at > pg_catalog.now() + interval '1 day' then return 'invalid'; end if;
  insert into public.altcha_used (signature, expires_at) values (p_signature, p_expires_at)
  on conflict (signature) do nothing
  returning signature into v;
  return case when v is null then 'replayed' else 'ok' end;
end $$;

create or replace function public.rout_altcha_purge()
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare n int;
begin
  delete from public.altcha_used where expires_at < pg_catalog.now();
  get diagnostics n = row_count;
  return n;
end $$;

-- Health check for the status page: the replay store is reachable.
create or replace function public.rout_altcha_store_ready()
returns boolean language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  perform 1 from public.altcha_used limit 1;
  return true;
end $$;

-- ------------------------------------------------------------------ sign-in throttle
create or replace function public.rout_signin_throttle_failures(p_identity_hash text)
returns int language sql stable security definer set search_path = pg_catalog as $$
  select coalesce((select t.failures from public.signin_throttle t
                    where t.identity_hash = p_identity_hash
                      and t.window_started_at > pg_catalog.now() - interval '15 minutes'), 0)
$$;

-- ------------------------------------------------------------------ one-time codes without a session
-- Kinds and their fixed rules (never chosen by the caller):
--   login_code  key = sha256(e-mail), payload = magic link; 15 min max; 5 wrong tries burn the code
--   fediverse   key = sha256(pending login), payload = e-mail; 10 min max; 3 wrong tries lock 15 min
alter table public.login_codes add column if not exists attempts int not null default 0;

create or replace function public.rout_stateless_otp_issue(p_kind text, p_key text, p_code_hash text, p_payload text, p_ttl_sec int)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_lock timestamptz;
begin
  if p_key is null or p_key !~ '^[0-9a-f]{64}$' or p_code_hash is null or p_code_hash !~ '^[0-9a-f]{64}$'
     or p_payload is null or pg_catalog.length(p_payload) not between 1 and 4000 then
    raise exception 'invalid code' using errcode = '22023';
  end if;
  if p_kind = 'login_code' then
    if p_ttl_sec is null or p_ttl_sec not between 60 and 900 then raise exception 'invalid code' using errcode = '22023'; end if;
    delete from public.login_codes where email_hash = p_key or expires_at < pg_catalog.now();
    insert into public.login_codes (email_hash, code_hash, link, expires_at, attempts)
    values (p_key, p_code_hash, p_payload, pg_catalog.now() + pg_catalog.make_interval(secs => p_ttl_sec), 0);
    return 'issued';
  elsif p_kind = 'fediverse' then
    if p_ttl_sec is null or p_ttl_sec not between 60 and 600 then raise exception 'invalid code' using errcode = '22023'; end if;
    select o.locked_until into v_lock from public.fediverse_email_otp o where o.pending_key = p_key for update;
    if v_lock is not null and v_lock > pg_catalog.now() then return 'locked'; end if;
    insert into public.fediverse_email_otp as o (pending_key, email, code_hash, attempts, locked_until, expires_at)
    values (p_key, p_payload, p_code_hash, 0, null, pg_catalog.now() + pg_catalog.make_interval(secs => p_ttl_sec))
    on conflict (pending_key) do update
      set email = excluded.email, code_hash = excluded.code_hash, attempts = 0, locked_until = null,
          expires_at = excluded.expires_at, created_at = pg_catalog.now();
    return 'issued';
  end if;
  raise exception 'unknown code kind' using errcode = '22023';
end $$;

-- Verifies a typed 6-digit code. The hash is computed here with the same
-- formula the app used when issuing, so the stored hash never leaves the database.
-- outcome: ok | wrong | locked | expired | missing ; payload only on ok.
create or replace function public.rout_stateless_otp_verify(p_kind text, p_key text, p_code text)
returns table (outcome text, payload text, attempts_left int)
language plpgsql volatile security definer set search_path = pg_catalog as $$
declare
  f public.fediverse_email_otp;
  l public.login_codes;
  v_hash text;
  v_attempts int;
begin
  if p_key is null or p_key !~ '^[0-9a-f]{64}$' then
    outcome := 'missing'; return next; return;
  end if;
  if p_code is null or p_code !~ '^[0-9]{6}$' then
    outcome := 'wrong'; return next; return;
  end if;
  if p_kind = 'login_code' then
    v_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_key || ':' || p_code, 'UTF8')), 'hex');
    delete from public.login_codes c
     where c.email_hash = p_key and c.code_hash = v_hash and c.expires_at > pg_catalog.now() and c.attempts < 5
    returning * into l;
    if l.id is not null then
      outcome := 'ok'; payload := l.link; return next; return;
    end if;
    update public.login_codes c set attempts = c.attempts + 1
     where c.email_hash = p_key and c.expires_at > pg_catalog.now()
    returning c.attempts into v_attempts;
    if v_attempts is null then outcome := 'missing'; return next; return; end if;
    if v_attempts >= 5 then
      delete from public.login_codes c where c.email_hash = p_key;
      outcome := 'locked'; attempts_left := 0; return next; return;
    end if;
    outcome := 'wrong'; attempts_left := 5 - v_attempts; return next; return;
  elsif p_kind = 'fediverse' then
    select * into f from public.fediverse_email_otp o where o.pending_key = p_key for update;
    if not found then outcome := 'missing'; return next; return; end if;
    if f.locked_until is not null and f.locked_until > pg_catalog.now() then
      outcome := 'locked'; attempts_left := 0; return next; return;
    end if;
    if f.expires_at < pg_catalog.now() then outcome := 'expired'; return next; return; end if;
    v_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_key || '|' || f.email || '|' || p_code, 'UTF8')), 'hex');
    if v_hash = f.code_hash then
      delete from public.fediverse_email_otp o where o.pending_key = p_key;
      outcome := 'ok'; payload := f.email; return next; return;
    end if;
    v_attempts := f.attempts + 1;
    update public.fediverse_email_otp o
       set attempts = v_attempts,
           locked_until = case when v_attempts >= 3 then pg_catalog.now() + interval '15 minutes' else null end
     where o.pending_key = p_key;
    outcome := case when v_attempts >= 3 then 'locked' else 'wrong' end;
    attempts_left := greatest(3 - v_attempts, 0);
    return next; return;
  end if;
  raise exception 'unknown code kind' using errcode = '22023';
end $$;

-- ------------------------------------------------------------------ Telegram phone check
-- One encrypted phone number per chat, 15 minutes, addressed only by chat id.
create or replace function public.rout_telegram_contact_remember(p_chat_id bigint, p_phone_enc text)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_chat_id is null or p_phone_enc is null or pg_catalog.length(p_phone_enc) not between 1 and 2000 then
    raise exception 'invalid contact' using errcode = '22023';
  end if;
  insert into public.telegram_verify_sessions (chat_id, phone_enc, expires_at)
  values (p_chat_id, p_phone_enc, pg_catalog.now() + interval '15 minutes')
  on conflict (chat_id) do update set phone_enc = excluded.phone_enc, expires_at = excluded.expires_at;
  delete from public.telegram_verify_sessions where expires_at < pg_catalog.now() - interval '1 hour';
end $$;

create or replace function public.rout_telegram_contact_get(p_chat_id bigint)
returns text language sql stable security definer set search_path = pg_catalog as $$
  select s.phone_enc from public.telegram_verify_sessions s
   where s.chat_id = p_chat_id and s.expires_at > pg_catalog.now() limit 1
$$;

create or replace function public.rout_telegram_contact_forget(p_chat_id bigint)
returns void language sql volatile security definer set search_path = pg_catalog as $$
  delete from public.telegram_verify_sessions where chat_id = p_chat_id
$$;

-- ------------------------------------------------------------------ Mastodon app registrations
-- ROUT's own OAuth app per Mastodon instance; read only for one exact instance + redirect pair.
create or replace function public.rout_mastodon_app_get(p_instance text, p_redirect_uri text)
returns table (client_id text, client_secret text)
language sql stable security definer set search_path = pg_catalog as $$
  select r.client_id, r.client_secret from public.mastodon_app_registrations r
   where r.instance = p_instance and r.redirect_uri = p_redirect_uri limit 1
$$;

create or replace function public.rout_mastodon_app_put(p_instance text, p_redirect_uri text, p_client_id text, p_client_secret text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_instance is null or p_instance !~ '^[a-z0-9.-]{1,253}$' or p_redirect_uri is null or pg_catalog.length(p_redirect_uri) not between 8 and 2000
     or p_redirect_uri !~ '^https?://' or coalesce(pg_catalog.length(p_client_id), 0) not between 1 and 500
     or coalesce(pg_catalog.length(p_client_secret), 0) not between 1 and 500 then
    raise exception 'invalid registration' using errcode = '22023';
  end if;
  insert into public.mastodon_app_registrations (instance, redirect_uri, client_id, client_secret)
  values (p_instance, p_redirect_uri, p_client_id, p_client_secret)
  on conflict (instance, redirect_uri) do nothing;
  return found;
end $$;

-- ------------------------------------------------------------------ execute rights
do $$
declare f regprocedure;
begin
  for f in
    select p.oid::regprocedure from pg_catalog.pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and p.proname = any (array[
         'rout_rate_limit_check_and_increment', 'rout_rate_limit_peek',
         'rout_altcha_verify_and_burn', 'rout_altcha_purge', 'rout_altcha_store_ready',
         'rout_signin_throttle_failures', 'rout_stateless_otp_issue', 'rout_stateless_otp_verify',
         'rout_telegram_contact_remember', 'rout_telegram_contact_get', 'rout_telegram_contact_forget',
         'rout_mastodon_app_get', 'rout_mastodon_app_put'])
  loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    execute pg_catalog.format('grant execute on function %s to rout_app', f);
  end loop;
end $$;
