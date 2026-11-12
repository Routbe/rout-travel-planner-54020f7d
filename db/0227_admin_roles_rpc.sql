-- 0227: roles, admin permissions, admin audit log and first-admin tokens only
-- through database functions (0223 phase 3, batch "roles & administration").
--
-- user_roles / admin_permissions: rout_app keeps SELECT on its OWN rows only
-- (account screen) and deletion by a due account purge; every write and every
-- cross-member read goes through the SECURITY DEFINER functions below, which
-- decide themselves whether the caller (transaction context) is allowed.
-- admin_audit_log: no table rights at all. Entries are append-only through
-- rout_audit_write (actor must be a real admin, e-mail derived in the database)
-- and rout_audit_write_system (fixed list of automatic actions); reading goes
-- through rout_audit_search, which binds every filter as a value and escapes
-- LIKE wildcards, so a search term can never change the query.
-- admin_bootstrap_tokens: no table rights; claimed only by rout_admin_bootstrap_claim.
-- admin_owner_emails: new owner allowlist the database checks before granting
-- the admin role automatically; seeded with the current admins' e-mails.

create table if not exists public.admin_owner_emails (
  email text primary key check (email = lower(email)),
  created_at timestamptz not null default now()
);
alter table public.admin_owner_emails enable row level security;
revoke all on table public.admin_owner_emails from rout_app;
insert into public.admin_owner_emails (email)
  select distinct lower(u.email) from public.user_roles r join public.users u on u.id = r.user_id
   where r.role::text = 'admin' and u.email is not null
on conflict do nothing;

-- ------------------------------------------------------------------ reads
create or replace function public.rout_has_role(p_user uuid, p_role text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select p_user is not null and exists (select 1 from public.user_roles r where r.user_id = p_user and r.role::text = p_role)
$$;

create or replace function public.rout_admin_permissions_of(p_user uuid)
returns text[] language sql stable security definer set search_path = pg_catalog as $$
  select coalesce(array_agg(p.permission order by p.permission), '{}'::text[])
    from public.admin_permissions p where p.user_id = p_user
$$;

create or replace function public.rout_is_admin_member(p_user uuid)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select p_user is not null and (public.rout_has_role(p_user, 'admin')
      or exists (select 1 from public.admin_permissions p where p.user_id = p_user))
$$;

create or replace function public.rout_caller_has_admin_permission(p_permission text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_has_role(public.rout_current_user_id(), 'admin')
      or exists (select 1 from public.admin_permissions p
                  where p.user_id = public.rout_current_user_id() and p.permission = p_permission)
$$;

-- Pre-login (sign-in method choice): only a yes/no, never who.
create or replace function public.rout_admin_email_eligible(p_email text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from public.users u
                  where lower(u.email) = lower(pg_catalog.btrim(p_email))
                    and public.rout_is_admin_member(u.id))
$$;

create or replace function public.rout_any_admin()
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from public.user_roles r where r.role::text = 'admin')
$$;

-- Admin attributed to token-link review decisions (no session present).
create or replace function public.rout_reviewer_admin_id()
returns uuid language sql stable security definer set search_path = pg_catalog as $$
  select r.user_id from public.user_roles r where r.role::text = 'admin' order by r.user_id limit 1
$$;

create or replace function public.rout_admin_grants_list()
returns table (user_id uuid, email text, username text, permissions text[], full_admin boolean)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_caller_has_admin_permission('manage_admins') then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query
    select u.id, u.email::text, p.username::text,
           public.rout_admin_permissions_of(u.id), public.rout_has_role(u.id, 'admin')
      from public.users u left join public.profiles p on p.id = u.id
     where public.rout_is_admin_member(u.id)
     order by u.email nulls last limit 100;
end $$;

-- ------------------------------------------------------------------ audit
create or replace function public.rout_audit_insert(p_admin uuid, p_email text, p_action text,
  p_target uuid, p_label text, p_notes text)
returns void language sql volatile security definer set search_path = pg_catalog as $$
  insert into public.admin_audit_log (admin_id, admin_email, action, target_user_id, target_label, notes)
  values (p_admin, p_email, left(p_action, 80), p_target, left(p_label, 300), left(p_notes, 2000))
$$;
revoke all on function public.rout_audit_insert(uuid, text, text, uuid, text, text) from public;

create or replace function public.rout_audit_write(p_action text, p_target uuid, p_label text, p_notes text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_actor uuid := public.rout_current_user_id(); v_email text;
begin
  if v_actor is null or not public.rout_is_admin_member(v_actor)
     or p_action is null or p_action !~ '^[A-Za-z0-9_.:-]{1,80}$' then
    return false;
  end if;
  select u.email into v_email from public.users u where u.id = v_actor;
  perform public.rout_audit_insert(v_actor, v_email, p_action, p_target, p_label, p_notes);
  return true;
end $$;

create or replace function public.rout_audit_write_system(p_action text, p_target uuid, p_label text, p_notes text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_action is null or p_action not in ('AUTO_PAYMENT_VERIFIED', 'PAYMENT_REVIEW_REQUIRED') then
    return false;
  end if;
  perform public.rout_audit_insert(coalesce(p_target, '00000000-0000-0000-0000-000000000000'::uuid),
    'system@rout.be', p_action, p_target, p_label, p_notes);
  return true;
end $$;

-- Escape LIKE metacharacters so user input is always a literal substring.
create or replace function public.rout_like_literal(p text)
returns text language sql immutable set search_path = pg_catalog as $$
  select '%' || replace(replace(replace(p, '\', '\\'), '%', '\%'), '_', '\_') || '%'
$$;

create or replace function public.rout_audit_search(
  p_admin_email text, p_action text, p_actions text[], p_search text,
  p_from timestamptz, p_to timestamptz, p_cursor_at timestamptz, p_cursor_id uuid,
  p_offset integer, p_limit integer)
returns table (id uuid, admin_email text, action text, target_user_id uuid, target_label text,
  notes text, created_at timestamptz, total bigint)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_is_admin_member(public.rout_current_user_id()) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return query
    select a.id, a.admin_email, a.action, a.target_user_id, a.target_label, a.notes, a.created_at,
           count(*) over ()
      from public.admin_audit_log a
     where (nullif(p_admin_email, '') is null or a.admin_email ilike public.rout_like_literal(p_admin_email))
       and (nullif(p_action, '') is null or a.action = p_action)
       and (p_actions is null or a.action = any (p_actions))
       and (nullif(p_search, '') is null
            or a.action ilike public.rout_like_literal(p_search)
            or a.admin_email ilike public.rout_like_literal(p_search)
            or a.target_label ilike public.rout_like_literal(p_search)
            or a.notes ilike public.rout_like_literal(p_search))
       and (p_from is null or a.created_at >= p_from)
       and (p_to is null or a.created_at <= p_to)
       and (p_cursor_at is null or a.created_at < p_cursor_at
            or (a.created_at = p_cursor_at and a.id < p_cursor_id))
     order by a.created_at desc, a.id desc
     offset greatest(coalesce(p_offset, 0), 0)
     limit least(greatest(coalesce(p_limit, 20), 1), 1000);
end $$;

create or replace function public.rout_audit_actions()
returns text[] language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_is_admin_member(public.rout_current_user_id()) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  return (select coalesce(array_agg(distinct a.action order by a.action), '{}'::text[])
            from (select action from public.admin_audit_log order by created_at desc limit 1000) a);
end $$;

-- ------------------------------------------------------------------ writes
create or replace function public.rout_user_role_ensure_member()
returns void language sql volatile security definer set search_path = pg_catalog as $$
  insert into public.user_roles (user_id, role)
  select public.rout_current_user_id(), 'user'::public.app_role
   where public.rout_current_user_id() is not null
  on conflict (user_id, role) do nothing
$$;

-- Owner auto-grant: only for the caller and only when the database lists the
-- caller's account e-mail as an owner address.
create or replace function public.rout_admin_grant_owner()
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null or not exists (
    select 1 from public.users u join public.admin_owner_emails o on o.email = lower(u.email)
     where u.id = v_user) then
    return false;
  end if;
  insert into public.user_roles (user_id, role) values (v_user, 'admin') on conflict (user_id, role) do nothing;
  return true;
end $$;

-- First admin: only while no admin exists, only for the oldest account = caller,
-- and each token digest only once.
create or replace function public.rout_admin_bootstrap_claim(p_token_hash text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('rout.admin_bootstrap', 0));
  if public.rout_any_admin() then return false; end if;
  if (select u.id from public.users u order by u.created_at asc limit 1) is distinct from v_user then return false; end if;
  insert into public.admin_bootstrap_tokens (token_hash, consumed_by, consumed_at)
  values (p_token_hash, v_user, now()) on conflict (token_hash) do nothing;
  if not found then return false; end if;
  insert into public.user_roles (user_id, role) values (v_user, 'admin') on conflict (user_id, role) do nothing;
  perform public.rout_audit_insert(v_user, (select email from public.users where id = v_user),
    'ADMIN_BOOTSTRAP_CLAIMED', v_user, null, null);
  return true;
end $$;

create or replace function public.rout_admin_permission_set(p_target uuid, p_permission text, p_granted boolean)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_actor uuid := public.rout_current_user_id();
begin
  if not public.rout_caller_has_admin_permission('manage_admins') then
    raise exception 'forbidden' using errcode = '42501';
  end if;
  if p_target is null or p_permission is null or p_permission not in ('verify_users', 'edit_names',
       'manage_promos', 'view_device_data', 'block_features', 'manage_admins', 'approve_sepa',
       'grant_badges', 'manage_integrations', 'review_apps', 'export_data', 'triage_contact') then
    return false;
  end if;
  if p_granted then
    insert into public.admin_permissions (user_id, permission, granted_by)
    values (p_target, p_permission, v_actor) on conflict (user_id, permission) do nothing;
  else
    delete from public.admin_permissions where user_id = p_target and permission = p_permission;
  end if;
  perform public.rout_audit_insert(v_actor, (select email from public.users where id = v_actor),
    case when p_granted then 'admin_permission_grant' else 'admin_permission_revoke' end,
    p_target, p_permission, null);
  return true;
end $$;

-- ------------------------------------------------------------------ privileges
do $$
declare f text;
begin
  foreach f in array array[
    'rout_has_role(uuid, text)', 'rout_admin_permissions_of(uuid)', 'rout_is_admin_member(uuid)',
    'rout_caller_has_admin_permission(text)', 'rout_admin_email_eligible(text)', 'rout_any_admin()',
    'rout_reviewer_admin_id()', 'rout_admin_grants_list()',
    'rout_audit_write(text, uuid, text, text)', 'rout_audit_write_system(text, uuid, text, text)',
    'rout_audit_search(text, text, text[], text, timestamptz, timestamptz, timestamptz, uuid, integer, integer)',
    'rout_audit_actions()', 'rout_user_role_ensure_member()', 'rout_admin_grant_owner()',
    'rout_admin_bootstrap_claim(text)', 'rout_admin_permission_set(uuid, text, boolean)'] loop
    execute format('revoke all on function public.%s from public', f);
    execute format('grant execute on function public.%s to rout_app', f);
  end loop;
end $$;

do $$
declare t text;
begin
  foreach t in array array['user_roles', 'admin_permissions'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('drop policy if exists rout_owner on public.%I', t);
    execute format('drop policy if exists rout_owner_purge on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
    execute format('grant select, delete on table public.%I to rout_app', t);
    execute format($p$create policy rout_owner on public.%I for select to rout_app
      using ((user_id)::text = current_setting('rout.current_user_id', true))$p$, t);
    execute format($p$create policy rout_owner_purge on public.%I for delete to rout_app
      using (public.rout_purge_due(user_id))$p$, t);
  end loop;

  drop policy if exists rout_server on public.admin_audit_log;
  revoke all on table public.admin_audit_log from rout_app;

  drop policy if exists rout_server on public.admin_bootstrap_tokens;
  drop policy if exists rout_owner_purge on public.admin_bootstrap_tokens;
  revoke all on table public.admin_bootstrap_tokens from rout_app;
  grant delete on table public.admin_bootstrap_tokens to rout_app;
  create policy rout_owner_purge on public.admin_bootstrap_tokens for delete to rout_app
    using (public.rout_purge_due(consumed_by));
end $$;
