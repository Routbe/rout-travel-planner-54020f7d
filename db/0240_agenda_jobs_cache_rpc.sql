-- 0240: agenda, background jobs and caches without the free "rout_server"
-- access (0223 phase 4, batch 9 — the last tables). EXPAND step: adds functions
-- and strict policies next to the legacy policies; db-pending/0241 removes the
-- free access once every deployment runs the matching code.
--
--   availability_jobs               enqueue / claim (skip locked) / retry through functions
--   booking_requests                anonymous request and signed-link decision through functions;
--                                   the host reads own requests (data export)
--   alias_sync_jobs                 queue, drain bookkeeping and admin summary through functions
--   forwarding_confirmation_sends   one atomic check-and-record per confirmation mail
--   ambient_weather_cache           read / lease / store one hashed city key through functions
--   platform_integration_switches   everyone reads provider + mode; admins with the
--                                   manage_integrations permission list and change them
-- alias_sync_jobs keeps its touch_updated_at trigger: it only stamps the row itself.

-- ------------------------------------------------------------------ availability jobs
create or replace function public.rout_availability_enqueue(p_user uuid, p_reason text, p_delay_seconds int default 0, p_replace_reason boolean default true)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_user is null or p_reason is null or p_reason !~ '^[a-z_]{1,40}$'
     or p_delay_seconds is null or p_delay_seconds not between 0 and 86400 then
    raise exception 'invalid availability job' using errcode = '22023';
  end if;
  insert into public.availability_jobs (user_id, reason, run_after)
  values (p_user, p_reason, pg_catalog.now() + pg_catalog.make_interval(secs => p_delay_seconds))
  on conflict (user_id) do update
    set reason = case when p_replace_reason then excluded.reason else public.availability_jobs.reason end,
        run_after = least(public.availability_jobs.run_after, excluded.run_after);
end $$;

-- Claims due jobs by deleting them; parallel workers never claim the same member.
create or replace function public.rout_availability_claim_due(p_limit int)
returns table (user_id uuid, attempts int)
language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_limit is null or p_limit not between 1 and 100 then
    raise exception 'invalid limit' using errcode = '22023';
  end if;
  return query
    delete from public.availability_jobs j where j.user_id in (
      select d.user_id from public.availability_jobs d where d.run_after <= pg_catalog.now()
       order by d.run_after limit p_limit for update skip locked)
    returning j.user_id, j.attempts;
end $$;

-- Re-queues a failed recompute with exponential backoff, at most five attempts.
create or replace function public.rout_availability_retry(p_user uuid, p_attempts int)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_user is null or p_attempts is null or p_attempts < 0 or p_attempts >= 5 then return false; end if;
  insert into public.availability_jobs (user_id, reason, run_after, attempts)
  values (p_user, 'retry', pg_catalog.now() + pg_catalog.make_interval(mins => (2 ^ p_attempts)::int), p_attempts + 1)
  on conflict (user_id) do nothing;
  return found;
end $$;

-- ------------------------------------------------------------------ booking requests
-- Only for a profile that really shows a booking form.
create or replace function public.rout_booking_request_create(p_profile uuid, p_guest_name text, p_guest_email text,
  p_date date, p_time text, p_message text, p_duration int, p_title text)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_id uuid;
begin
  if p_profile is null or p_guest_name is null or pg_catalog.length(p_guest_name) not between 2 and 120
     or p_guest_email is null or pg_catalog.length(p_guest_email) not between 3 and 254 or pg_catalog.strpos(p_guest_email, '@') = 0
     or p_date is null or p_time is null or p_time !~ '^[0-9]{2}:[0-9]{2}$'
     or coalesce(pg_catalog.length(p_message), 0) > 500
     or p_duration is null or p_duration not between 5 and 1440
     or coalesce(pg_catalog.length(p_title), 0) > 200 then
    raise exception 'invalid booking request' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.profiles p
     cross join lateral pg_catalog.jsonb_array_elements(case when pg_catalog.jsonb_typeof(p.blocks) = 'array' then p.blocks else '[]'::jsonb end) b(el)
     where p.id = p_profile and b.el->>'kind' = 'booking_request'
       and coalesce(b.el->'hidden', 'false'::jsonb) <> 'true'::jsonb) then
    raise exception 'no booking form' using errcode = 'P0002';
  end if;
  insert into public.booking_requests (profile_id, guest_name, guest_email, preferred_date, preferred_time,
    guest_message, duration_minutes, title)
  values (p_profile, p_guest_name, p_guest_email, p_date, p_time, p_message, p_duration, p_title)
  returning id into v_id;
  return v_id;
end $$;

-- The host's signed accept/decline link (verified in the app) decides a pending request once.
create or replace function public.rout_booking_request_resolve(p_id uuid, p_action text)
returns table (id uuid, profile_id uuid, guest_name text, guest_email text, preferred_date date, preferred_time text,
               guest_message text, duration_minutes int, title text)
language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_action not in ('accept', 'decline') then
    raise exception 'invalid booking action' using errcode = '22023';
  end if;
  return query
    update public.booking_requests r
       set status = case when p_action = 'accept' then 'accepted' else 'declined' end, updated_at = pg_catalog.now()
     where r.id = p_id and r.status = 'pending'
    returning r.id, r.profile_id, r.guest_name, r.guest_email, r.preferred_date, r.preferred_time,
              r.guest_message, r.duration_minutes, r.title;
end $$;

drop policy if exists booking_requests_host_read on public.booking_requests;
create policy booking_requests_host_read on public.booking_requests for select to rout_app
  using (profile_id = (select public.rout_current_user_id()));

-- ------------------------------------------------------------------ alias sync queue
create or replace function public.rout_alias_job_enqueue(p_user uuid, p_action text, p_payload jsonb, p_max_attempts int)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_id uuid;
begin
  if p_user is null or p_action not in ('provision', 'rename', 'pause', 'resume', 'delete', 'freeze')
     or pg_catalog.octet_length(coalesce(p_payload, '{}'::jsonb)::text) > 4096
     or p_max_attempts is null or p_max_attempts not between 1 and 10 then
    raise exception 'invalid alias job' using errcode = '22023';
  end if;
  insert into public.alias_sync_jobs (user_id, action, payload, max_attempts)
  values (p_user, p_action, coalesce(p_payload, '{}'::jsonb), p_max_attempts)
  returning id into v_id;
  return v_id;
end $$;

create or replace function public.rout_alias_jobs_pending(p_limit int)
returns table (id uuid, user_id uuid, action text, payload jsonb, attempts int, max_attempts int)
language sql stable security definer set search_path = pg_catalog as $$
  select j.id, j.user_id, j.action, j.payload, j.attempts, j.max_attempts from public.alias_sync_jobs j
   where j.status = 'pending' and p_limit between 1 and 100
   order by j.created_at asc limit p_limit
$$;

-- Records the outcome of one pending job; finished jobs are never rewritten.
create or replace function public.rout_alias_job_finish(p_id uuid, p_status text, p_attempts int, p_error text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_status not in ('done', 'failed', 'pending') or p_attempts is null or p_attempts not between 0 and 100
     or coalesce(pg_catalog.length(p_error), 0) > 2000 then
    raise exception 'invalid alias job result' using errcode = '22023';
  end if;
  update public.alias_sync_jobs j
     set status = p_status, attempts = p_attempts, last_error = case when p_status = 'done' then null else p_error end,
         updated_at = pg_catalog.now()
   where j.id = p_id and j.status = 'pending';
  return found;
end $$;

create or replace function public.rout_alias_jobs_retry_failed()
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare n int;
begin
  update public.alias_sync_jobs j set status = 'pending', attempts = 0, last_error = null, updated_at = pg_catalog.now()
   where j.status = 'failed';
  get diagnostics n = row_count;
  return n;
end $$;

-- Requeues one member's failed jobs; false when the member has no open job at all.
create or replace function public.rout_alias_job_requeue_user(p_user uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not exists (select 1 from public.alias_sync_jobs j where j.user_id = p_user and j.status in ('failed', 'pending')) then
    return false;
  end if;
  update public.alias_sync_jobs j set status = 'pending', attempts = 0, last_error = null, updated_at = pg_catalog.now()
   where j.user_id = p_user and j.status = 'failed';
  return true;
end $$;

create or replace function public.rout_alias_queue_summary()
returns table (status text, count int)
language sql stable security definer set search_path = pg_catalog as $$
  select j.status, pg_catalog.count(*)::int from public.alias_sync_jobs j
   where j.status in ('pending', 'failed', 'done') group by j.status
$$;

-- ------------------------------------------------------------------ forwarding confirmations
-- Check and record in one transaction, serialised per member, so parallel
-- requests can never slip past the limits together. Returns null when allowed.
create or replace function public.rout_forwarding_send_check(p_user uuid, p_recipient text,
  p_per_10min int, p_per_day int, p_per_recipient_day int)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_recipient text := pg_catalog.lower(pg_catalog.btrim(coalesce(p_recipient, ''))); r_recent int; r_daily int; r_rcpt int;
begin
  if p_user is null or pg_catalog.length(v_recipient) not between 3 and 320 or pg_catalog.strpos(v_recipient, '@') = 0
     or p_per_10min not between 1 and 100 or p_per_day not between 1 and 100 or p_per_recipient_day not between 1 and 100 then
    raise exception 'invalid forwarding check' using errcode = '22023';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('rout_fwd:' || p_user::text, 0));
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('rout_fwd_rcpt:' || v_recipient, 0));
  select pg_catalog.count(*) filter (where s.sent_at > pg_catalog.now() - interval '10 minutes'),
         pg_catalog.count(*) filter (where s.sent_at > pg_catalog.now() - interval '1 day')
    into r_recent, r_daily
    from public.forwarding_confirmation_sends s where s.user_id = p_user;
  select pg_catalog.count(*) into r_rcpt from public.forwarding_confirmation_sends s
   where pg_catalog.lower(s.recipient) = v_recipient and s.sent_at > pg_catalog.now() - interval '1 day';
  if r_recent >= p_per_10min or r_daily >= p_per_day then return 'rate_limited_user'; end if;
  if r_rcpt >= p_per_recipient_day then return 'rate_limited_recipient'; end if;
  insert into public.forwarding_confirmation_sends (user_id, recipient) values (p_user, v_recipient);
  return null;
end $$;

-- ------------------------------------------------------------------ ambient weather cache
-- Keys are SHA-256 hex digests of a normalised city name; no visitor data.
create or replace function public.rout_weather_cache_read(p_key text)
returns table (state text, checked_at json)
language sql stable security definer set search_path = pg_catalog as $$
  select c.state, pg_catalog.to_json(c.checked_at) from public.ambient_weather_cache c
   where p_key ~ '^[0-9a-f]{64}$' and c.city_key = p_key limit 1
$$;

-- Atomic 30-minute lease: only one visitor at a time refreshes a city.
create or replace function public.rout_weather_cache_lease(p_key text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_key is null or p_key !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid weather key' using errcode = '22023';
  end if;
  insert into public.ambient_weather_cache (city_key, refresh_after) values (p_key, pg_catalog.now() + interval '30 minutes')
  on conflict (city_key) do update set refresh_after = excluded.refresh_after
   where public.ambient_weather_cache.refresh_after <= pg_catalog.now();
  return found;
end $$;

create or replace function public.rout_weather_cache_store(p_key text, p_state text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_key is null or p_key !~ '^[0-9a-f]{64}$'
     or (p_state is not null and p_state not in ('Clear', 'Rain', 'Snow', 'Thunderstorm', 'Clouds/Fog')) then
    raise exception 'invalid weather state' using errcode = '22023';
  end if;
  update public.ambient_weather_cache c set state = p_state, checked_at = pg_catalog.now() where c.city_key = p_key;
  return found;
end $$;

-- ------------------------------------------------------------------ integration switches
drop policy if exists platform_integration_switches_read on public.platform_integration_switches;
create policy platform_integration_switches_read on public.platform_integration_switches for select to rout_app using (true);

create or replace function public.rout_integration_switches_admin_list()
returns table (provider text, mode text, note text, updated_at timestamptz, updated_by_email text, links int)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_caller_has_admin_permission('manage_integrations') then
    raise exception 'admin only' using errcode = '42501';
  end if;
  return query
    select s.provider, s.mode, s.note, s.updated_at, u.email,
           (select pg_catalog.count(*)::int from public.user_integrations i where i.provider = s.provider)
      from public.platform_integration_switches s
      left join public.users u on u.id = s.updated_by;
end $$;

create or replace function public.rout_integration_switch_set(p_provider text, p_mode text, p_note text)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not public.rout_caller_has_admin_permission('manage_integrations') then
    raise exception 'admin only' using errcode = '42501';
  end if;
  if p_provider is null or p_provider !~ '^[a-z0-9_-]{1,40}$' or p_mode not in ('on', 'paused', 'off')
     or coalesce(pg_catalog.length(p_note), 0) > 500 then
    raise exception 'invalid integration switch' using errcode = '22023';
  end if;
  insert into public.platform_integration_switches (provider, mode, note, updated_by, updated_at)
  values (p_provider, p_mode, p_note, public.rout_current_user_id(), pg_catalog.now())
  on conflict (provider) do update set mode = excluded.mode, note = excluded.note,
    updated_by = excluded.updated_by, updated_at = pg_catalog.now();
end $$;

-- ------------------------------------------------------------------ execute rights
do $$
declare f regprocedure;
begin
  for f in
    select p.oid::regprocedure from pg_catalog.pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and p.proname = any (array[
         'rout_availability_enqueue', 'rout_availability_claim_due', 'rout_availability_retry',
         'rout_booking_request_create', 'rout_booking_request_resolve',
         'rout_alias_job_enqueue', 'rout_alias_jobs_pending', 'rout_alias_job_finish', 'rout_alias_jobs_retry_failed',
         'rout_alias_job_requeue_user', 'rout_alias_queue_summary', 'rout_forwarding_send_check',
         'rout_weather_cache_read', 'rout_weather_cache_lease', 'rout_weather_cache_store',
         'rout_integration_switches_admin_list', 'rout_integration_switch_set'])
  loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    execute pg_catalog.format('grant execute on function %s to rout_app', f);
  end loop;
end $$;
