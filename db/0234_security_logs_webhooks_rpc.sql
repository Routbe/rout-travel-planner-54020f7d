-- 0234: security logs, webhook bookkeeping and the SEPA review queue through
-- database functions (0223 phase 4, batch 6). EXPAND step: adds functions and
-- strict policies next to the legacy "rout_server" policies; db-pending/0235
-- removes the free access once every deployment runs the matching code.
--
--   * writes from server code without a member session (signed webhooks, cron,
--     system flows) go through narrow functions that validate every field;
--   * admins read webhook events and SEPA reviews, and decide reviews, through
--     session-bound admin policies (rout_caller_is_admin, 0229);
--   * a due account purge may still delete the member's own rows.
-- Nothing here can update or delete a security log entry: the append-only
-- triggers of security_audit_logs stay the last word.

-- ------------------------------------------------------------------ security events
create or replace function public.rout_security_event_write(p_user uuid, p_kind text, p_severity text, p_message text, p_details jsonb)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_kind is null or p_kind !~ '^[a-z0-9_]{1,64}$' or p_severity not in ('info', 'warning', 'error', 'critical')
     or p_message is null or pg_catalog.length(p_message) not between 1 and 1000
     or pg_catalog.octet_length(coalesce(p_details, '{}'::jsonb)::text) > 16384 then
    raise exception 'invalid security event' using errcode = '22023';
  end if;
  insert into public.security_events (user_id, kind, severity, message, details)
  values (p_user, p_kind, p_severity, p_message, coalesce(p_details, '{}'::jsonb));
end $$;

-- ------------------------------------------------------------------ hash-chained audit log
-- The chain trigger computes prev/current hash; callers never choose them.
create or replace function public.rout_audit_write(p_event_type text, p_user text, p_actor text, p_ip_hash text, p_ua_hash text, p_payload jsonb)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_event_type is null or p_event_type !~ '^[A-Za-z0-9_.:-]{1,80}$'
     or coalesce(pg_catalog.length(p_user), 0) > 80 or coalesce(pg_catalog.length(p_actor), 0) > 80
     or (p_ip_hash is not null and p_ip_hash !~ '^[0-9a-f]{1,64}$')
     or (p_ua_hash is not null and p_ua_hash !~ '^[0-9a-f]{1,64}$')
     or pg_catalog.octet_length(coalesce(p_payload, '{}'::jsonb)::text) > 16384 then
    raise exception 'invalid audit entry' using errcode = '22023';
  end if;
  insert into public.security_audit_logs (event_type, user_id, actor_id, ip_hash, user_agent_hash, payload_json, prev_hash, current_hash)
  values (p_event_type, p_user, p_actor, p_ip_hash, p_ua_hash, coalesce(p_payload, '{}'::jsonb), '', '');
end $$;

-- Chain head for the daily signed checkpoint (no row contents).
create or replace function public.rout_audit_head(p_day date)
returns table (id bigint, current_hash text, n bigint)
language sql stable security definer set search_path = pg_catalog as $$
  select l.id, l.current_hash,
         (select pg_catalog.count(*) from public.security_audit_logs c where c.created_at < (p_day + 1))
    from public.security_audit_logs l where l.created_at < (p_day + 1)
   order by l.id desc limit 1
$$;

-- Retention: only rows older than the fixed 365-day window (the trigger re-checks).
create or replace function public.rout_audit_purge_expired()
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare n int;
begin
  perform pg_catalog.set_config('rout.audit_retention', 'on', true);
  delete from public.security_audit_logs where created_at < pg_catalog.now() - interval '365 days';
  get diagnostics n = row_count;
  perform pg_catalog.set_config('rout.audit_retention', '', true);
  return n;
end $$;

-- ------------------------------------------------------------------ webhook events (inbound idempotency + transport log)
-- Claims one inbound provider event: true for the first delivery, and again only after a failed attempt.
create or replace function public.rout_webhook_event_claim(p_id text, p_source text, p_kind text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v text;
begin
  if p_id is null or p_id !~ '^[A-Za-z0-9_:.-]{1,200}$' or p_source not in ('stripe')
     or coalesce(pg_catalog.length(p_kind), 0) > 120 then
    raise exception 'invalid webhook event' using errcode = '22023';
  end if;
  insert into public.webhook_events as w (id, source, kind, status, direction)
  values (p_id, p_source, p_kind, 'processing', 'inbound')
  on conflict (id) do update
     set status = 'processing', attempts = w.attempts + 1, error = null, updated_at = pg_catalog.now()
   where w.status = 'failed'
  returning w.id into v;
  return v is not null;
end $$;

create or replace function public.rout_webhook_event_finish(p_id text, p_status text, p_result text, p_error text, p_http_status int)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_status not in ('done', 'failed') then raise exception 'invalid webhook status' using errcode = '22023'; end if;
  update public.webhook_events
     set status = p_status, result = pg_catalog.left(p_result, 500), error = pg_catalog.left(p_error, 500),
         http_status = p_http_status, direction = 'inbound',
         completed_at = case when p_status = 'done' then pg_catalog.now() else completed_at end,
         updated_at = pg_catalog.now()
   where id = p_id and status = 'processing';
  return found;
end $$;

-- Transport metadata only (outbound calls, inbound bank e-mails); never bodies, URLs or credentials.
create or replace function public.rout_webhook_event_record(p_id text, p_source text, p_kind text, p_direction text, p_http_status int, p_status text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_id is null or p_id !~ '^(outbound|inbound):[A-Za-z0-9_.:-]{1,200}$' or p_source !~ '^[a-z0-9_-]{1,40}$'
     or coalesce(pg_catalog.length(p_kind), 0) > 120 or p_direction not in ('inbound', 'outbound')
     or p_status not in ('processing', 'done', 'failed') then
    raise exception 'invalid webhook event' using errcode = '22023';
  end if;
  insert into public.webhook_events (id, source, kind, direction, http_status, status, completed_at)
  values (p_id, p_source, p_kind, p_direction, p_http_status, p_status,
          case when p_status = 'processing' then null else pg_catalog.now() end)
  on conflict (id) do nothing;
  return found;
end $$;

-- ------------------------------------------------------------------ outbound webhook deliveries
create or replace function public.rout_webhook_delivery_enqueue(p_owner uuid, p_event_type text, p_payload jsonb)
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare n int;
begin
  if p_owner is null or p_event_type is null or p_event_type !~ '^[a-z0-9_.:-]{1,80}$'
     or pg_catalog.octet_length(coalesce(p_payload, '{}'::jsonb)::text) > 65536 then
    raise exception 'invalid webhook delivery' using errcode = '22023';
  end if;
  insert into public.webhook_deliveries (endpoint_id, event_type, payload_json)
  select e.id, p_event_type, coalesce(p_payload, '{}'::jsonb) from public.webhook_endpoints e
   where e.owner_user_id = p_owner and e.active and (p_event_type = any (e.events) or pg_catalog.cardinality(e.events) = 0);
  get diagnostics n = row_count;
  return n;
end $$;

-- Dispatcher (cron): the due deliveries with their endpoint and its sealed secret.
create or replace function public.rout_webhook_delivery_due(p_limit int)
returns table (id uuid, event_type text, payload_json jsonb, attempts int, url text, secret_ciphertext text, secret_iv text, endpoint_id uuid)
language sql stable security definer set search_path = pg_catalog as $$
  select d.id, d.event_type, d.payload_json, d.attempts, e.url, e.secret_ciphertext, e.secret_iv, e.id
    from public.webhook_deliveries d join public.webhook_endpoints e on e.id = d.endpoint_id
   where d.delivered_at is null and d.failed_at is null and d.next_attempt_at <= pg_catalog.now() and e.active
   order by d.next_attempt_at limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;

-- One delivery attempt finished: delivered, retry after p_delay_sec, or failed for good.
create or replace function public.rout_webhook_delivery_result(p_id uuid, p_http_status int, p_outcome text, p_delay_sec int)
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v int;
begin
  if p_outcome not in ('delivered', 'retry', 'failed')
     or (p_outcome = 'retry' and (p_delay_sec is null or p_delay_sec not between 1 and 604800)) then
    raise exception 'invalid delivery result' using errcode = '22023';
  end if;
  update public.webhook_deliveries
     set attempts = attempts + 1, last_status = p_http_status,
         delivered_at = case when p_outcome = 'delivered' then pg_catalog.now() else delivered_at end,
         failed_at = case when p_outcome = 'failed' then pg_catalog.now() else failed_at end,
         next_attempt_at = case when p_outcome = 'retry' then pg_catalog.now() + pg_catalog.make_interval(secs => p_delay_sec)
                                else next_attempt_at end
   where id = p_id and delivered_at is null and failed_at is null
  returning attempts into v;
  return v;
end $$;

-- ------------------------------------------------------------------ SEPA review queue
-- Bank webhook (no session): one open review per payment, re-deliveries update it.
create or replace function public.rout_sepa_review_queue(
  p_payment uuid, p_user uuid, p_reason text, p_reference text, p_amount int, p_expected int,
  p_payer_name text, p_holder_name text, p_match_score numeric, p_notes text)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid;
begin
  if coalesce(p_reason, 'name_mismatch') !~ '^[a-z_]{1,40}$' or coalesce(pg_catalog.length(p_reference), 0) > 80
     or coalesce(pg_catalog.length(p_payer_name), 0) > 300 or coalesce(pg_catalog.length(p_holder_name), 0) > 300
     or coalesce(pg_catalog.length(p_notes), 0) > 2000 then
    raise exception 'invalid review' using errcode = '22023';
  end if;
  insert into public.sepa_review_queue as q
    (payment_id, user_id, reason, reference, amount_cents, expected_cents, payer_name, holder_name, match_score, notes)
  values (p_payment, p_user, coalesce(p_reason, 'name_mismatch'), p_reference, p_amount, p_expected,
          p_payer_name, p_holder_name, p_match_score, p_notes)
  on conflict (payment_id) where status = 'open' and payment_id is not null
  do update set reference = coalesce(excluded.reference, q.reference), amount_cents = excluded.amount_cents,
                payer_name = coalesce(excluded.payer_name, q.payer_name), match_score = excluded.match_score
  returning q.id into v;
  return v;
end $$;

-- ------------------------------------------------------------------ strict policies
drop policy if exists webhook_events_admin_read on public.webhook_events;
create policy webhook_events_admin_read on public.webhook_events for select to rout_app
  using (public.rout_caller_is_admin());

drop policy if exists sepa_review_admin_read on public.sepa_review_queue;
create policy sepa_review_admin_read on public.sepa_review_queue for select to rout_app
  using (public.rout_caller_is_admin());
drop policy if exists sepa_review_admin_update on public.sepa_review_queue;
create policy sepa_review_admin_update on public.sepa_review_queue for update to rout_app
  using (public.rout_caller_is_admin()) with check (public.rout_caller_is_admin());
drop policy if exists sepa_review_purge_read on public.sepa_review_queue;
create policy sepa_review_purge_read on public.sepa_review_queue for select to rout_app
  using (public.rout_purge_due(user_id));
drop policy if exists sepa_review_purge on public.sepa_review_queue;
create policy sepa_review_purge on public.sepa_review_queue for delete to rout_app
  using (public.rout_purge_due(user_id));

-- user_id is text here; CASE keeps the uuid cast from ever failing.
drop policy if exists security_audit_purge_read on public.security_audit_logs;
create policy security_audit_purge_read on public.security_audit_logs for select to rout_app
  using (public.rout_purge_due(case when user_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then user_id::uuid end));
drop policy if exists security_audit_purge on public.security_audit_logs;
create policy security_audit_purge on public.security_audit_logs for delete to rout_app
  using (public.rout_purge_due(case when user_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then user_id::uuid end));

-- ------------------------------------------------------------------ execute rights
do $$
declare f regprocedure;
begin
  for f in
    select p.oid::regprocedure from pg_catalog.pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and p.proname = any (array[
         'rout_security_event_write', 'rout_audit_write', 'rout_audit_head', 'rout_audit_purge_expired',
         'rout_webhook_event_claim', 'rout_webhook_event_finish', 'rout_webhook_event_record',
         'rout_webhook_delivery_enqueue', 'rout_webhook_delivery_due', 'rout_webhook_delivery_result',
         'rout_sepa_review_queue'])
  loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    execute pg_catalog.format('grant execute on function %s to rout_app', f);
  end loop;
end $$;
