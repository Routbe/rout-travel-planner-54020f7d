-- 0236: identity, credentials and entitlements without the free "rout_server"
-- access (0223 phase 4, batch 7). EXPAND step: adds functions and strict
-- policies next to the legacy policies; db-pending/0237 removes the free access
-- once every deployment runs the matching code.
--
--   badges, reserved_handles     public catalogues: read-only for the app, written only by migrations
--   api_keys                     the signed-in owner manages their own keys (policies)
--   entitlement_overrides        exact-scope reads; grants and the Plus credit only through functions
--   referrals                    claim / count / verify through functions (signup and payment flows)
--   didit_monthly_usage          one atomic monthly counter
--   identity_labels              only for the caller's own sign-in accounts, or an admin
--   account_merge_tickets        create / look up by hash / bind through functions
--   credential_issue_*           unused by the app: closed in 0237 without replacement

-- The early-verified trigger on profiles wrote entitlement_overrides with the
-- caller's rights; it must keep working once the table is closed.
alter function public.grant_early_verified_promo() security definer set search_path = pg_catalog;

-- ------------------------------------------------------------------ catalogues
drop policy if exists badges_public_read on public.badges;
create policy badges_public_read on public.badges for select to rout_app using (true);
drop policy if exists reserved_handles_public_read on public.reserved_handles;
create policy reserved_handles_public_read on public.reserved_handles for select to rout_app using (true);

-- ------------------------------------------------------------------ api keys (owner)
drop policy if exists api_keys_owner_read on public.api_keys;
create policy api_keys_owner_read on public.api_keys for select to rout_app
  using (user_id = public.rout_current_user_id());
drop policy if exists api_keys_owner_insert on public.api_keys;
create policy api_keys_owner_insert on public.api_keys for insert to rout_app
  with check (user_id = public.rout_current_user_id()
              and (workspace_id is null or public.rout_is_workspace_member(workspace_id)));
drop policy if exists api_keys_owner_update on public.api_keys;
create policy api_keys_owner_update on public.api_keys for update to rout_app
  using (user_id = public.rout_current_user_id()) with check (user_id = public.rout_current_user_id());
drop policy if exists api_keys_owner_delete on public.api_keys;
create policy api_keys_owner_delete on public.api_keys for delete to rout_app
  using (user_id = public.rout_current_user_id());

-- ------------------------------------------------------------------ entitlements
create or replace function public.rout_entitlement_overrides(p_scope_type text, p_scope_id uuid)
returns table (entitlement_key text, value text)
language sql stable security definer set search_path = pg_catalog as $$
  select o.entitlement_key, o.value from public.entitlement_overrides o
   where o.scope_type = p_scope_type and o.scope_id = p_scope_id
$$;

-- Early Verified bonus of the workspace owner (PRO_FOR_LIFE), as db/0122 reads it.
create or replace function public.rout_workspace_owner_pro_for_life(p_workspace uuid)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from public.workspace_members m
                   join public.entitlement_overrides o on o.scope_type = 'user' and o.scope_id = m.user_id
                    and o.entitlement_key = 'PRO_FOR_LIFE' and o.value = 'true'
                  where m.workspace_id = p_workspace and m.role = 'owner')
$$;

-- Same grant as the profiles trigger, only for a member who really is verified.
create or replace function public.rout_entitlement_grant_early_verified(p_user uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not exists (select 1 from public.profiles p where p.id = p_user and p.verified) then return false; end if;
  insert into public.entitlement_overrides (scope_type, scope_id, entitlement_key, value, granted_by)
  values ('user', p_user, 'PRO_FOR_LIFE', 'true', 'early_verified_promo'),
         ('user', p_user, 'INCLUDED_PLUS_WORKSPACE', '1', 'early_verified_promo')
  on conflict (scope_type, scope_id, entitlement_key) do nothing;
  return true;
end $$;

-- Spends one included Plus credit on a workspace the member owns; one statement
-- decrements, so two parallel redemptions can never both spend the last credit.
create or replace function public.rout_entitlement_redeem_plus(p_user uuid, p_workspace uuid)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid;
begin
  if not exists (select 1 from public.workspace_members m
                  where m.workspace_id = p_workspace and m.user_id = p_user and m.role = 'owner') then
    return 'forbidden';
  end if;
  update public.entitlement_overrides o
     set value = ((case when o.value ~ '^[0-9]{1,6}$' then o.value::int else 0 end) - 1)::text
   where o.scope_type = 'user' and o.scope_id = p_user and o.entitlement_key = 'INCLUDED_PLUS_WORKSPACE'
     and (case when o.value ~ '^[0-9]{1,6}$' then o.value::int else 0 end) > 0
  returning o.id into v;
  if v is null then return 'no_credit'; end if;
  insert into public.entitlement_overrides (scope_type, scope_id, entitlement_key, value, granted_by)
  values ('workspace', p_workspace, 'WORKSPACE_PLAN', 'plus', 'user:' || p_user::text)
  on conflict (scope_type, scope_id, entitlement_key) do update set value = 'plus';
  return 'ok';
end $$;

-- ------------------------------------------------------------------ referrals
-- One inviter per member, never yourself, only for an account younger than 24 hours.
create or replace function public.rout_referral_claim(p_inviter uuid, p_invitee uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid;
begin
  if p_inviter is null or p_invitee is null or p_inviter = p_invitee then return false; end if;
  if not exists (select 1 from public.users u where u.id = p_invitee and u.created_at > pg_catalog.now() - interval '24 hours') then
    return false;
  end if;
  insert into public.referrals (inviter_id, invitee_id) values (p_inviter, p_invitee)
  on conflict (invitee_id) do nothing returning id into v;
  return v is not null;
end $$;

create or replace function public.rout_referral_counts(p_inviter uuid)
returns table (invited int, verified_invites int)
language sql stable security definer set search_path = pg_catalog as $$
  select pg_catalog.count(*)::int, (pg_catalog.count(*) filter (where r.verified))::int
    from public.referrals r where r.inviter_id = p_inviter
$$;

create or replace function public.rout_referral_mark_verified(p_invitee uuid)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid;
begin
  update public.referrals set verified = true, verified_at = pg_catalog.now()
   where invitee_id = p_invitee and not verified
  returning inviter_id into v;
  return v;
end $$;

-- ------------------------------------------------------------------ Didit monthly usage (UTC month, fixed by the database)
create or replace function public.rout_didit_usage_count()
returns int language sql stable security definer set search_path = pg_catalog as $$
  select coalesce((select u.success_count from public.didit_monthly_usage u
                    where u.month = pg_catalog.date_trunc('month', pg_catalog.now() at time zone 'UTC')::date), 0)
$$;

create or replace function public.rout_didit_usage_bump(p_limit int)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare m date := pg_catalog.date_trunc('month', pg_catalog.now() at time zone 'UTC')::date; v int;
begin
  if p_limit is null or p_limit not between 1 and 100000 then raise exception 'invalid limit' using errcode = '22023'; end if;
  insert into public.didit_monthly_usage as u (month, success_count) values (m, 1)
  on conflict (month) do update set success_count = u.success_count + 1 where u.success_count < p_limit
  returning u.success_count into v;
  return v is not null;
end $$;

create or replace function public.rout_didit_usage_release()
returns void language sql volatile security definer set search_path = pg_catalog as $$
  update public.didit_monthly_usage set success_count = greatest(success_count - 1, 0)
   where month = pg_catalog.date_trunc('month', pg_catalog.now() at time zone 'UTC')::date
$$;

-- ------------------------------------------------------------------ identity labels
-- True for the caller's own sign-in account, or for an admin.
create or replace function public.rout_identity_account_visible(p_account text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_caller_is_admin() or exists (
    select 1 from neon_auth.account a join public.users u on u.auth_user_id = a."userId" or u.id = a."userId"
     where a.id::text = p_account and u.id = public.rout_current_user_id())
$$;

create or replace function public.rout_identity_labels_get(p_ids text[])
returns table (account_id text, label text)
language sql stable security definer set search_path = pg_catalog as $$
  select l.account_id, l.label from public.identity_labels l
   where pg_catalog.cardinality(p_ids) <= 50 and l.account_id = any (p_ids)
     and public.rout_identity_account_visible(l.account_id)
$$;

create or replace function public.rout_identity_label_put(p_account text, p_provider text, p_label text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_account is null or pg_catalog.length(p_account) > 80 or p_provider is null or p_provider !~ '^[A-Za-z0-9_.:-]{1,40}$'
     or p_label is null or pg_catalog.length(p_label) not between 1 and 200 then
    raise exception 'invalid label' using errcode = '22023';
  end if;
  if not public.rout_identity_account_visible(p_account) then return false; end if;
  insert into public.identity_labels (account_id, provider, label) values (p_account, p_provider, p_label)
  on conflict (account_id) do update set label = excluded.label, updated_at = pg_catalog.now();
  return true;
end $$;

-- ------------------------------------------------------------------ account merge tickets
create or replace function public.rout_merge_ticket_create(p_primary uuid, p_pin_hash text, p_token_hash text, p_ttl_minutes int)
returns table (id uuid, expires_at timestamptz)
language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_primary is null or p_pin_hash !~ '^[A-Za-z0-9+/]{43}=$' or p_token_hash !~ '^[A-Za-z0-9+/]{43}=$'
     or p_pin_hash = p_token_hash or p_ttl_minutes is null or p_ttl_minutes not between 1 and 60 then
    raise exception 'invalid ticket' using errcode = '22023';
  end if;
  update public.account_merge_tickets t set used_at = pg_catalog.now() where t.primary_user_id = p_primary and t.used_at is null;
  return query
    insert into public.account_merge_tickets as t (primary_user_id, pin_hash, token_hash, expires_at)
    values (p_primary, p_pin_hash, p_token_hash, pg_catalog.now() + pg_catalog.make_interval(mins => p_ttl_minutes))
    returning t.id, t.expires_at;
end $$;

-- Exact hash lookup of one live ticket; never lists tickets.
create or replace function public.rout_merge_ticket_find(p_hash text)
returns table (id uuid, primary_user_id uuid, preview_user_id uuid, expires_at timestamptz)
language sql stable security definer set search_path = pg_catalog as $$
  select t.id, t.primary_user_id, t.preview_user_id, t.expires_at from public.account_merge_tickets t
   where p_hash ~ '^[A-Za-z0-9+/]{43}=$' and t.used_at is null and t.expires_at > pg_catalog.now()
     and (t.pin_hash = p_hash or t.token_hash = p_hash)
   order by t.created_at desc limit 1
$$;

-- Binds a ticket to the first account that previews it; nobody else can redeem it.
create or replace function public.rout_merge_ticket_bind(p_ticket uuid, p_secondary uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  update public.account_merge_tickets t set preview_user_id = p_secondary
   where t.id = p_ticket and t.used_at is null and t.expires_at > pg_catalog.now() and t.primary_user_id <> p_secondary
     and (t.preview_user_id is null or t.preview_user_id = p_secondary);
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
         'rout_entitlement_overrides', 'rout_workspace_owner_pro_for_life', 'rout_entitlement_grant_early_verified',
         'rout_entitlement_redeem_plus', 'rout_referral_claim', 'rout_referral_counts', 'rout_referral_mark_verified',
         'rout_didit_usage_count', 'rout_didit_usage_bump', 'rout_didit_usage_release',
         'rout_identity_account_visible', 'rout_identity_labels_get', 'rout_identity_label_put',
         'rout_merge_ticket_create', 'rout_merge_ticket_find', 'rout_merge_ticket_bind'])
  loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    execute pg_catalog.format('grant execute on function %s to rout_app', f);
  end loop;
end $$;
