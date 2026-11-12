-- 0238: public profiles, statistics and visitor forms without the free
-- "rout_server" access (0223 phase 4, batch 8). EXPAND step: adds functions and
-- strict policies next to the legacy policies; db-pending/0239 removes the free
-- access once every deployment runs the matching code.
--
--   links                  the signed-in owner (or an admin) reads and deletes own rows
--   profile_link_clicks    anonymous clicks only through one function; the owner reads own counts
--   qr_scans               anonymous scans through log_qr_scan (capped); owners, workspace
--                          colleagues and admins read/delete scans of codes they may see
--   poll_votes             vote and tally through functions (one vote per poll and voter)
--   showcase_profiles      public catalogue; only an admin replaces the list (atomically)
--   lead_captures          anonymous messages through one function; the profile owner reads them
--   contact_submissions    anonymous submissions through functions; only admins read them
--   onboarding_drafts      put / get / drop by exact key; deleted by a due account purge
-- None of these tables has an invoker trigger or function that touches another
-- table (touch_updated_at only stamps the row itself).

-- ------------------------------------------------------------------ links
drop policy if exists links_owner_read on public.links;
create policy links_owner_read on public.links for select to rout_app
  using (profile_id = (select public.rout_current_user_id()) or (select public.rout_caller_is_admin()));
drop policy if exists links_owner_delete on public.links;
create policy links_owner_delete on public.links for delete to rout_app
  using (profile_id = (select public.rout_current_user_id()) or (select public.rout_caller_is_admin()));

-- ------------------------------------------------------------------ link clicks
-- The owner is resolved in the database from the public handle (root profile
-- first, then an alias space); callers can never attribute a click to someone else.
create or replace function public.rout_link_click_record(p_handle text, p_block_id text, p_label text, p_space text, p_visitor_hash text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare
  v_handle text := pg_catalog.lower(pg_catalog.btrim(coalesce(p_handle, '')));
  v_owner uuid;
begin
  if pg_catalog.length(v_handle) not between 1 and 64
     or p_block_id is null or pg_catalog.length(p_block_id) not between 1 and 64
     or coalesce(pg_catalog.length(p_label), 0) > 120
     or p_space not in ('root', 'alias')
     or (p_visitor_hash is not null and pg_catalog.length(p_visitor_hash) > 128) then
    raise exception 'invalid link click' using errcode = '22023';
  end if;
  select p.id into v_owner from public.profiles p where pg_catalog.lower(p.username) = v_handle limit 1;
  if v_owner is null then
    select a.user_id into v_owner from public.alias_profiles a where pg_catalog.lower(a.handle) = v_handle limit 1;
  end if;
  if v_owner is null then return false; end if;
  insert into public.profile_link_clicks (profile_user_id, handle, block_id, label, space, visitor_hash)
  values (v_owner, v_handle, p_block_id, nullif(p_label, ''), p_space, p_visitor_hash);
  return true;
end $$;

drop policy if exists profile_link_clicks_owner_read on public.profile_link_clicks;
create policy profile_link_clicks_owner_read on public.profile_link_clicks for select to rout_app
  using (profile_user_id = (select public.rout_current_user_id()));

-- ------------------------------------------------------------------ qr scans
-- Tracked codes the caller may see: their own (personal or created in a
-- workspace) and every code of a workspace they belong to. Evaluated once per
-- statement (uncorrelated sub-select), not once per scan row.
create or replace function public.rout_accessible_tracked_qr_ids()
returns setof uuid language sql stable security definer set search_path = pg_catalog as $$
  select t.id from public.tracked_qrs t
   where public.rout_current_user_id() is not null
     and (t.user_id = public.rout_current_user_id()
          or (t.workspace_id is not null and public.rout_is_workspace_member(t.workspace_id)))
$$;

drop policy if exists qr_scans_scope_read on public.qr_scans;
create policy qr_scans_scope_read on public.qr_scans for select to rout_app
  using ((select public.rout_caller_is_admin()) or tracked_qr_id in (select public.rout_accessible_tracked_qr_ids()));
drop policy if exists qr_scans_scope_delete on public.qr_scans;
create policy qr_scans_scope_delete on public.qr_scans for delete to rout_app
  using ((select public.rout_caller_is_admin()) or tracked_qr_id in (select public.rout_accessible_tracked_qr_ids()));
-- Anonymous scans: public.log_qr_scan (SECURITY DEFINER, max 60 per code per minute).
-- Token dashboards: public.short_link_stats (SECURITY DEFINER, exact token).

-- ------------------------------------------------------------------ poll votes
create or replace function public.rout_poll_tally(p_poll_key text)
returns table (option_index int, n int)
language sql stable security definer set search_path = pg_catalog as $$
  select v.option_index, pg_catalog.count(*)::int from public.poll_votes v
   where p_poll_key is not null and pg_catalog.length(p_poll_key) between 1 and 200 and v.poll_key = p_poll_key
   group by v.option_index order by v.option_index
$$;

-- One vote per poll and server-derived voter key; a repeat is ignored, never counted twice.
create or replace function public.rout_poll_vote(p_poll_key text, p_option int, p_voter_key text)
returns table (option_index int, n int)
language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_poll_key is null or pg_catalog.length(p_poll_key) not between 1 and 200
     or p_option is null or p_option not between 0 and 5
     or p_voter_key is null or p_voter_key !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid poll vote' using errcode = '22023';
  end if;
  insert into public.poll_votes (poll_key, option_index, voter_key) values (p_poll_key, p_option, p_voter_key)
  on conflict (poll_key, voter_key) do nothing;
  return query select t.option_index, t.n from public.rout_poll_tally(p_poll_key) t;
end $$;

-- ------------------------------------------------------------------ showcase
drop policy if exists showcase_profiles_public_read on public.showcase_profiles;
create policy showcase_profiles_public_read on public.showcase_profiles for select to rout_app using (true);

-- Admin replaces the whole ordered list in one transaction (no half-written list).
create or replace function public.rout_showcase_replace(p_handles text[])
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare h text; i int := 0;
begin
  if not public.rout_caller_is_admin() then
    raise exception 'admin only' using errcode = '42501';
  end if;
  if p_handles is null or coalesce(pg_catalog.array_length(p_handles, 1), 0) > 20 then
    raise exception 'invalid showcase list' using errcode = '22023';
  end if;
  foreach h in array p_handles loop
    if h is null or h !~ '^[a-z0-9._-]{1,64}$' then
      raise exception 'invalid showcase handle' using errcode = '22023';
    end if;
  end loop;
  delete from public.showcase_profiles where true;
  foreach h in array p_handles loop
    insert into public.showcase_profiles (handle, display_name, position, sort_order)
    values (h, h, i, i) on conflict (handle) do nothing;
    i := i + 1;
  end loop;
  return i;
end $$;

-- ------------------------------------------------------------------ lead captures
-- Only for a profile that really shows a contact form.
create or replace function public.rout_lead_capture_insert(p_handle text, p_name text, p_email text, p_message text)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_handle text := pg_catalog.lower(pg_catalog.btrim(coalesce(p_handle, ''))); v_id uuid;
begin
  if pg_catalog.length(v_handle) not between 1 and 64
     or coalesce(pg_catalog.length(p_name), 0) > 120
     or p_email is null or pg_catalog.length(p_email) not between 3 and 254 or pg_catalog.strpos(p_email, '@') = 0
     or coalesce(pg_catalog.length(p_message), 0) > 1000 then
    raise exception 'invalid lead' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.profiles p
     cross join lateral pg_catalog.jsonb_array_elements(case when pg_catalog.jsonb_typeof(p.blocks) = 'array' then p.blocks else '[]'::jsonb end) b(el)
     where pg_catalog.lower(p.username) = v_handle and b.el->>'kind' = 'contact_form'
       and coalesce(b.el->'hidden', 'false'::jsonb) <> 'true'::jsonb) then
    raise exception 'no contact form' using errcode = 'P0002';
  end if;
  insert into public.lead_captures (handle, name, email, message) values (v_handle, p_name, p_email, p_message)
  returning id into v_id;
  return v_id;
end $$;

create or replace function public.rout_current_username()
returns text language sql stable security definer set search_path = pg_catalog as $$
  select pg_catalog.lower(p.username) from public.profiles p where p.id = public.rout_current_user_id()
$$;

drop policy if exists lead_captures_owner_read on public.lead_captures;
create policy lead_captures_owner_read on public.lead_captures for select to rout_app
  using (pg_catalog.lower(handle) = (select public.rout_current_username()));

-- ------------------------------------------------------------------ contact form
create or replace function public.rout_contact_submission_create(
  p_name text, p_email text, p_subject text, p_message text, p_locale text, p_sender_hash text,
  p_portal_category text, p_category text, p_priority text, p_meta jsonb,
  p_attachment_key text, p_attachment_name text, p_attachment_size bigint, p_attachment_mime text)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_id uuid;
begin
  if p_name is null or pg_catalog.length(p_name) not between 1 and 100
     or p_email is null or pg_catalog.length(p_email) not between 3 and 255 or pg_catalog.strpos(p_email, '@') = 0
     or p_subject is null or pg_catalog.length(p_subject) not between 1 and 150
     or p_message is null or pg_catalog.length(p_message) not between 1 and 2000
     or p_locale not in ('nl', 'en', 'fr', 'de')
     or coalesce(pg_catalog.length(p_sender_hash), 0) > 128
     or coalesce(pg_catalog.length(p_portal_category), 0) > 40
     or coalesce(pg_catalog.length(p_category), 0) > 40
     or coalesce(pg_catalog.length(p_priority), 0) > 40
     or pg_catalog.octet_length(coalesce(p_meta, '{}'::jsonb)::text) > 4096
     or coalesce(pg_catalog.length(p_attachment_key), 0) > 300
     or coalesce(pg_catalog.length(p_attachment_name), 0) > 120
     or (p_attachment_size is not null and p_attachment_size not between 1 and 5242880)
     or (p_attachment_mime is not null and p_attachment_mime not in ('image/png', 'image/jpeg', 'text/plain', 'application/json')) then
    raise exception 'invalid contact submission' using errcode = '22023';
  end if;
  insert into public.contact_submissions (name, email, subject, message, locale, status, sender_hash, portal_category,
    category, priority, meta, attachment_key, attachment_name, attachment_size, attachment_mime)
  values (p_name, p_email, p_subject, p_message, p_locale, 'pending', p_sender_hash, p_portal_category,
    p_category, p_priority, p_meta, p_attachment_key, p_attachment_name, p_attachment_size, p_attachment_mime)
  returning id into v_id;
  return v_id;
end $$;

-- Delivery outcome, once, for a fresh submission that is still pending.
create or replace function public.rout_contact_submission_finish(p_id uuid, p_status text, p_error text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_status not in ('sent', 'sent_partial', 'failed') or coalesce(pg_catalog.length(p_error), 0) > 1000 then
    raise exception 'invalid contact status' using errcode = '22023';
  end if;
  update public.contact_submissions s set status = p_status, error_detail = p_error
   where s.id = p_id and s.status = 'pending' and s.created_at > pg_catalog.now() - interval '1 hour';
  return found;
end $$;

drop policy if exists contact_submissions_admin_read on public.contact_submissions;
create policy contact_submissions_admin_read on public.contact_submissions for select to rout_app
  using ((select public.rout_caller_is_admin()));

-- ------------------------------------------------------------------ onboarding drafts
-- Key: a lower-case e-mail address or "token:<random>"; only exact keys, never lists.
create or replace function public.rout_onboarding_key_ok(p_key text)
returns boolean language sql immutable set search_path = pg_catalog as $$
  select p_key is not null and pg_catalog.length(p_key) between 3 and 320
     and ((p_key like 'token:%' and pg_catalog.length(p_key) between 7 and 86)
          or (p_key not like 'token:%' and pg_catalog.strpos(p_key, '@') > 1 and p_key = pg_catalog.lower(p_key)))
$$;

create or replace function public.rout_onboarding_draft_put(p_key text, p_draft jsonb)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not public.rout_onboarding_key_ok(p_key) or p_draft is null or pg_catalog.octet_length(p_draft::text) > 262144 then
    raise exception 'invalid onboarding draft' using errcode = '22023';
  end if;
  insert into public.onboarding_drafts (email, draft, updated_at) values (p_key, p_draft, pg_catalog.now())
  on conflict (email) do update set draft = excluded.draft, updated_at = pg_catalog.now();
end $$;

create or replace function public.rout_onboarding_draft_get(p_key text)
returns jsonb language sql stable security definer set search_path = pg_catalog as $$
  select d.draft from public.onboarding_drafts d where public.rout_onboarding_key_ok(p_key) and d.email = p_key limit 1
$$;

create or replace function public.rout_onboarding_draft_drop(p_key text)
returns void language sql volatile security definer set search_path = pg_catalog as $$
  delete from public.onboarding_drafts d where public.rout_onboarding_key_ok(p_key) and d.email = p_key
$$;

-- Account purge: only inside the purge transaction of an account that is due.
create or replace function public.rout_onboarding_drafts_purge(p_user uuid)
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare n int;
begin
  if not public.rout_purge_due(p_user) then return 0; end if;
  delete from public.onboarding_drafts d
   where pg_catalog.lower(d.email) in (select pg_catalog.lower(u.email) from public.users u where u.id = p_user and u.email is not null);
  get diagnostics n = row_count;
  return n;
end $$;

-- ------------------------------------------------------------------ execute rights
do $$
declare f regprocedure;
begin
  for f in
    select p.oid::regprocedure from pg_catalog.pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and p.proname = any (array[
         'rout_link_click_record', 'rout_accessible_tracked_qr_ids', 'rout_poll_tally', 'rout_poll_vote',
         'rout_showcase_replace', 'rout_lead_capture_insert', 'rout_current_username',
         'rout_contact_submission_create', 'rout_contact_submission_finish', 'rout_onboarding_key_ok',
         'rout_onboarding_draft_put', 'rout_onboarding_draft_get', 'rout_onboarding_draft_drop', 'rout_onboarding_drafts_purge'])
  loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    execute pg_catalog.format('grant execute on function %s to rout_app', f);
  end loop;
end $$;
