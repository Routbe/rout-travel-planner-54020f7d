-- 0228: ROUT ID / OAuth provider through database functions (0223 phase 3,
-- batch "ROUT ID"). EXPAND step: only adds functions and strict policies next
-- to the legacy "rout_server" policies, so code that still queries the tables
-- directly keeps working. 0230 removes the free access once every deployment
-- runs the code that uses these functions.
--
-- Also repairs the no-user paths of the provider: since oauth_clients, users
-- and the token tables are owner-scoped, the token, userinfo, introspection,
-- revocation and refresh endpoints (which run without a member context) could
-- not see the app, the code owner or the tokens. They now go through the
-- narrow functions below, each deciding for itself what the caller may see.
--
-- Rules every function follows: SECURITY DEFINER with search_path pg_catalog,
-- caller taken from the transaction context (rout_current_user_id), secrets
-- never returned except the peppered client-secret hash and sealed signing
-- keys (both useless without server-side keys), and no function returns more
-- than the one caller-facing fact it exists for.

-- ------------------------------------------------------------------ helpers
-- Who may manage an app in the Developer Console (mirrors client-access.ts):
-- personal apps by their creator, workspace apps by owner/admin/developer members.
create or replace function public.rout_oauth_can_manage(p_client text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_current_user_id() is not null and exists (
    select 1 from public.oauth_clients c
     where c.client_id = p_client
       and ((c.workspace_id is null and c.owner_user_id = public.rout_current_user_id())
         or (c.workspace_id is not null and exists (
               select 1 from public.workspace_members m
                where m.workspace_id = c.workspace_id and m.user_id = public.rout_current_user_id()
                  and m.role::text in ('owner', 'admin', 'developer')))))
$$;

create or replace function public.rout_oauth_b64url_sha256(p text)
returns text language sql immutable set search_path = pg_catalog as $$
  select pg_catalog.translate(pg_catalog.rtrim(pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p, 'UTF8')), 'base64'), '='), '+/', '-_')
$$;
revoke all on function public.rout_oauth_b64url_sha256(text) from public;

-- ------------------------------------------------------------------ clients
-- Public app metadata for the consent screen and the token endpoints. Never the
-- secret hash or the sealed webhook secrets.
create or replace function public.rout_oauth_client_get(p_client text)
returns jsonb language sql stable security definer set search_path = pg_catalog as $$
  select (pg_catalog.to_jsonb(c) - 'secret_hash' - 'backchannel_webhook_secret_sealed' - 'backchannel_webhook_secret_iv')
         || pg_catalog.jsonb_build_object('has_secret', c.secret_hash is not null)
    from public.oauth_clients c where c.client_id = p_client limit 1
$$;

-- Client authentication at the token endpoints: the peppered hash only, active apps only.
create or replace function public.rout_oauth_client_secret_hash(p_client text)
returns text language sql stable security definer set search_path = pg_catalog as $$
  select c.secret_hash from public.oauth_clients c where c.client_id = p_client and c.status = 'active' limit 1
$$;

-- May the signed-in member log in to this app now (testing mode rules)?
create or replace function public.rout_oauth_user_may_use(p_client text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_current_user_id() is not null and exists (
    select 1 from public.oauth_clients c
     where c.client_id = p_client and c.status = 'active'
       and (c.publishing_status = 'production'
         or (c.owner_user_id is null and c.workspace_id is null)
         or c.owner_user_id = public.rout_current_user_id()
         or (c.workspace_id is not null and exists (
               select 1 from public.workspace_members m
                where m.workspace_id = c.workspace_id and m.user_id = public.rout_current_user_id()
                  and m.role::text in ('owner', 'admin', 'developer')))
         or exists (
               select 1 from public.oauth_client_test_users t
                where t.client_id = c.client_id
                  and (t.identifier = (select pg_catalog.lower(u.email) from public.users u where u.id = public.rout_current_user_id())
                    or t.identifier in (select pg_catalog.lower(p.username) from public.profiles p
                                         where p.id = public.rout_current_user_id()
                                           and p.username is not null)))))
$$;

-- Back-channel targets for a member's e-mail change: only apps this member gave the e-mail scope.
create or replace function public.rout_oauth_email_webhook_targets(p_clients text[])
returns table (client_id text, url text, secret_sealed text, secret_iv text)
language sql stable security definer set search_path = pg_catalog as $$
  select c.client_id, c.backchannel_webhook_url, c.backchannel_webhook_secret_sealed, c.backchannel_webhook_secret_iv
    from public.oauth_clients c
   where c.client_id = any (p_clients) and c.backchannel_webhook_url is not null
     and exists (select 1 from public.oauth_consents k
                  where k.user_id = public.rout_current_user_id() and k.client_id = c.client_id
                    and k.revoked_at is null and 'email' = any (k.scopes))
$$;

-- ------------------------------------------------------------------ codes
-- Issued for the signed-in member only, to an active app, for a registered
-- redirect URI (byte-exact), with a lifetime of at most 10 minutes.
create or replace function public.rout_oauth_code_issue(p_code_hash text, p_client text, p_redirect text,
  p_scopes text[], p_challenge text, p_nonce text, p_acr text, p_rich boolean, p_ttl_seconds integer)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null then raise exception 'forbidden' using errcode = '42501'; end if;
  if p_code_hash is null or pg_catalog.length(p_code_hash) not between 20 and 200 then return false; end if;
  if not exists (select 1 from public.oauth_clients c where c.client_id = p_client and c.status = 'active'
                   and p_redirect = any (c.redirect_uris)) then
    return false;
  end if;
  insert into public.oauth_auth_codes (code_hash, client_id, user_id, redirect_uri, scopes, code_challenge,
    nonce, expires_at, acr, rich_identity)
  values (p_code_hash, p_client, v_user, p_redirect, coalesce(p_scopes, '{}'), coalesce(p_challenge, ''),
    p_nonce, now() + pg_catalog.make_interval(secs => least(greatest(coalesce(p_ttl_seconds, 60), 1), 600)),
    p_acr, coalesce(p_rich, false));
  return true;
end $$;

-- Atomic, single use: the code is burnt on the first presentation, whatever
-- the outcome, exactly as RFC 6749 asks. PKCE (S256) is checked here.
create or replace function public.rout_oauth_code_consume(p_code_hash text, p_client text, p_redirect text, p_verifier text)
returns table (result text, user_id uuid, scopes text[], nonce text, acr text, auth_time timestamptz,
  rich_identity boolean, redirect_uri text, has_pkce boolean)
language plpgsql volatile security definer set search_path = pg_catalog as $$
declare r public.oauth_auth_codes%rowtype;
begin
  update public.oauth_auth_codes c set consumed_at = now()
   where c.code_hash = p_code_hash and c.consumed_at is null and c.expires_at > now()
  returning c.* into r;
  if not found then
    return query select 'invalid'::text, null::uuid, null::text[], null::text, null::text, null::timestamptz, null::boolean, null::text, null::boolean;
    return;
  end if;
  if r.client_id is distinct from p_client then
    return query select 'client_mismatch'::text, null::uuid, null::text[], null::text, null::text, null::timestamptz, null::boolean, null::text, null::boolean;
    return;
  end if;
  if r.redirect_uri is distinct from p_redirect then
    return query select 'redirect_mismatch'::text, null::uuid, null::text[], null::text, null::text, null::timestamptz, null::boolean, r.redirect_uri, null::boolean;
    return;
  end if;
  if coalesce(r.code_challenge, '') <> '' then
    if coalesce(p_verifier, '') = '' then
      return query select 'pkce_missing'::text, null::uuid, null::text[], null::text, null::text, null::timestamptz, null::boolean, null::text, true;
      return;
    end if;
    if public.rout_oauth_b64url_sha256(p_verifier) <> r.code_challenge then
      return query select 'pkce_failed'::text, null::uuid, null::text[], null::text, null::text, null::timestamptz, null::boolean, null::text, true;
      return;
    end if;
  end if;
  return query select 'ok'::text, r.user_id, r.scopes, r.nonce, r.acr, r.auth_time, r.rich_identity, r.redirect_uri,
    coalesce(r.code_challenge, '') <> '';
end $$;

create or replace function public.rout_oauth_client_code_stats(p_client text)
returns table (total integer, failed integer)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  return query select count(*)::int, (count(*) filter (where c.consumed_at is null and c.expires_at < now()))::int
    from public.oauth_auth_codes c where c.client_id = p_client and c.created_at > now() - interval '30 days';
end $$;

-- ------------------------------------------------------------------ signing keys
-- Private parts leave only sealed (ROUT_PROVIDER_SIGNING_KEK stays server-side)
-- or as a legacy plaintext key that sealLegacyKeys() retires.
create or replace function public.rout_oauth_signing_keys_list()
returns table (kid text, created_at timestamptz, retired_at timestamptz, revoked_at timestamptz, public_jwk jsonb,
  private_jwk jsonb, private_jwk_sealed text, private_jwk_iv text, kek_fingerprint text)
language sql stable security definer set search_path = pg_catalog as $$
  select k.kid, k.created_at, k.retired_at, k.revoked_at, k.public_jwk, k.private_jwk, k.private_jwk_sealed,
         k.private_jwk_iv, k.kek_fingerprint
    from public.oauth_signing_keys k order by k.created_at desc
$$;

-- New key is always sealed; older keys are retired in the same transaction.
create or replace function public.rout_oauth_signing_key_rotate(p_kid text, p_public jsonb, p_sealed text, p_iv text,
  p_fingerprint text, p_alg text)
returns timestamptz language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_created timestamptz;
begin
  if p_kid is null or p_public is null or p_sealed is null or p_iv is null or p_alg is distinct from 'ES256'
     or p_public ? 'd' then
    raise exception 'invalid_signing_key' using errcode = '22023';
  end if;
  insert into public.oauth_signing_keys (kid, private_jwk, public_jwk, private_jwk_sealed, private_jwk_iv, kek_fingerprint, alg)
  values (p_kid, null, p_public, p_sealed, p_iv, p_fingerprint, p_alg)
  returning created_at into v_created;
  update public.oauth_signing_keys k set retired_at = now()
   where k.retired_at is null and k.kid <> p_kid and k.created_at <= v_created;
  return v_created;
end $$;

-- Only retired or revoked keys can lose their private parts.
create or replace function public.rout_oauth_signing_keys_wipe(p_kids text[])
returns integer language plpgsql volatile security definer set search_path = pg_catalog as $$
declare n integer;
begin
  update public.oauth_signing_keys k set private_jwk = null, private_jwk_sealed = null, private_jwk_iv = null
   where k.kid = any (p_kids) and (k.retired_at is not null or k.revoked_at is not null);
  get diagnostics n = row_count;
  return n;
end $$;

create or replace function public.rout_oauth_signing_key_retire_legacy(p_kid text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  update public.oauth_signing_keys k set private_jwk = null, retired_at = coalesce(k.retired_at, now())
   where k.kid = p_kid and k.private_jwk is not null;
  return found;
end $$;

-- ------------------------------------------------------------------ consents
-- Granted by the signed-in member, for an active app; scopes are merged while active.
create or replace function public.rout_oauth_consent_grant(p_client text, p_scopes text[])
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_user uuid := public.rout_current_user_id();
begin
  if v_user is null then raise exception 'forbidden' using errcode = '42501'; end if;
  if not exists (select 1 from public.oauth_clients c where c.client_id = p_client and c.status = 'active') then
    return false;
  end if;
  insert into public.oauth_consents (user_id, client_id, scopes)
  values (v_user, p_client, coalesce(p_scopes, '{}'))
  on conflict (user_id, client_id) do update set
    scopes = case when public.oauth_consents.revoked_at is null
      then array(select distinct x from unnest(public.oauth_consents.scopes || excluded.scopes) as x order by x)
      else excluded.scopes end,
    granted_at = now(), revoked_at = null;
  return true;
end $$;

-- Picture proxy / server checks: does this member have an active consent for this (active) app?
create or replace function public.rout_oauth_consent_active(p_user uuid, p_client text, p_scope text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from public.oauth_consents g join public.oauth_clients c on c.client_id = g.client_id
                  where g.user_id = p_user and g.client_id = p_client and g.revoked_at is null and c.status = 'active'
                    and (p_scope is null or p_scope = any (g.scopes)))
$$;

create or replace function public.rout_oauth_client_consent_count(p_client text)
returns integer language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  return (select count(*)::int from public.oauth_consents g where g.client_id = p_client);
end $$;

-- ------------------------------------------------------------------ tokens (no-user endpoints)
create or replace function public.rout_oauth_access_token_check(p_hash text, p_subject text, p_client text)
returns uuid language sql stable security definer set search_path = pg_catalog as $$
  select t.user_id from public.oauth_access_tokens t
    join public.oauth_clients c on c.client_id = t.client_id
    join public.users u on u.id = t.user_id
    join public.oauth_consents g on g.user_id = t.user_id and g.client_id = t.client_id
   where t.token_hash = p_hash and t.revoked_at is null and t.expires_at > now()
     and t.subject = p_subject and t.client_id = p_client
     and c.status = 'active' and not u.is_disabled and u.account_status = 'active' and g.revoked_at is null
     and (t.family_id is null or not exists (select 1 from public.oauth_refresh_tokens r
                                              where r.family_id = t.family_id and r.revoked_at is not null))
   limit 1
$$;

create or replace function public.rout_oauth_access_token_introspect(p_hash text, p_client text)
returns table (expires_at timestamptz, created_at timestamptz, scopes text[], subject text)
language sql stable security definer set search_path = pg_catalog as $$
  select t.expires_at, t.created_at, t.scopes, t.subject from public.oauth_access_tokens t
    join public.oauth_clients c on c.client_id = t.client_id
    join public.users u on u.id = t.user_id
    join public.oauth_consents g on g.client_id = t.client_id and g.user_id = t.user_id
   where t.token_hash = p_hash and t.client_id = p_client and t.revoked_at is null and t.expires_at > now()
     and c.status = 'active' and not u.is_disabled and u.account_status = 'active' and g.revoked_at is null
     and (t.family_id is null or not exists (select 1 from public.oauth_refresh_tokens f
                                              where f.family_id = t.family_id and f.revoked_at is not null))
   limit 1
$$;

create or replace function public.rout_oauth_refresh_token_introspect(p_hash text, p_client text)
returns table (user_id uuid, scopes text[], expires_at timestamptz)
language sql stable security definer set search_path = pg_catalog as $$
  select r.user_id, r.scopes, r.expires_at from public.oauth_refresh_tokens r
    join public.oauth_clients c on c.client_id = r.client_id
    join public.users u on u.id = r.user_id
    join public.oauth_consents g on g.client_id = r.client_id and g.user_id = r.user_id
   where r.token_hash = p_hash and r.client_id = p_client and r.used_at is null and r.revoked_at is null
     and r.expires_at > now() and c.status = 'active' and not u.is_disabled and u.account_status = 'active'
     and g.revoked_at is null
     and not exists (select 1 from public.oauth_refresh_tokens f where f.family_id = r.family_id and f.revoked_at is not null)
   limit 1
$$;

-- RFC 7009: the (authenticated) client revokes one of its own tokens and its family.
create or replace function public.rout_oauth_token_revoke(p_hash text, p_client text)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  update public.oauth_access_tokens t set revoked_at = coalesce(t.revoked_at, now())
   where t.token_hash = p_hash and t.client_id = p_client;
  update public.oauth_refresh_tokens r set revoked_at = coalesce(r.revoked_at, now())
   where r.client_id = p_client and r.family_id in (select f.family_id from public.oauth_refresh_tokens f
                                                    where f.token_hash = p_hash and f.client_id = p_client);
  update public.oauth_access_tokens t set revoked_at = coalesce(t.revoked_at, now())
   where t.client_id = p_client and t.family_id in (select f.family_id from public.oauth_refresh_tokens f
                                                    where f.token_hash = p_hash and f.client_id = p_client);
end $$;

-- Refresh rotation runs at the token endpoint without a member context, so it
-- must see the owner-scoped token tables itself. Body unchanged from 0115.
create or replace function public.rotate_oauth_refresh(old_hash text, target_client text, new_hash text)
returns table(result text,user_id uuid,subject text,scopes text[],family_id uuid,auth_time timestamptz,acr text)
language plpgsql security definer set search_path = pg_catalog as $$
declare old public.oauth_refresh_tokens%rowtype;
begin
  select * into old from public.oauth_refresh_tokens t where t.token_hash=old_hash and t.client_id=target_client for update;
  if not found then return query select 'invalid'::text,null::uuid,null::text,null::text[],null::uuid,null::timestamptz,null::text; return; end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(old.family_id::text,0));
  if old.used_at is not null then
    update public.oauth_refresh_tokens t set revoked_at=coalesce(t.revoked_at,now()) where t.family_id=old.family_id;
    update public.oauth_access_tokens t set revoked_at=coalesce(t.revoked_at,now()) where t.family_id=old.family_id;
    return query select 'reuse'::text,null::uuid,null::text,null::text[],old.family_id,null::timestamptz,null::text; return;
  end if;
  if old.revoked_at is not null or old.expires_at<=now()
    or exists(select 1 from public.oauth_refresh_tokens t where t.family_id=old.family_id and t.revoked_at is not null)
    or not exists(select 1 from public.oauth_consents c where c.user_id=old.user_id and c.client_id=target_client and c.revoked_at is null and 'offline_access'=any(c.scopes))
    or not exists(select 1 from public.users u where u.id=old.user_id and not u.is_disabled and u.account_status='active')
    or not exists(select 1 from public.oauth_clients c where c.client_id=target_client and c.status='active') then
    return query select 'invalid'::text,null::uuid,null::text,null::text[],old.family_id,null::timestamptz,null::text; return;
  end if;
  update public.oauth_refresh_tokens t set used_at=now() where t.id=old.id;
  insert into public.oauth_refresh_tokens(family_id,token_hash,client_id,user_id,scopes,expires_at,subject,auth_time,acr)
  values(old.family_id,new_hash,target_client,old.user_id,old.scopes,old.expires_at,old.subject,old.auth_time,old.acr);
  return query select 'ok'::text,old.user_id,old.subject,old.scopes,old.family_id,old.auth_time,old.acr;
end $$;

-- ------------------------------------------------------------------ test users
create or replace function public.rout_oauth_test_users_list(p_client text)
returns setof text language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  return query select t.identifier from public.oauth_client_test_users t where t.client_id = p_client order by t.created_at;
end $$;

create or replace function public.rout_oauth_test_user_add(p_client text, p_identifier text, p_max integer)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_id text := pg_catalog.lower(pg_catalog.btrim(p_identifier));
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  if v_id is null or pg_catalog.length(v_id) not between 1 and 320 then return 'invalid'; end if;
  perform 1 from public.oauth_clients c where c.client_id = p_client for update;
  if (select count(*) from public.oauth_client_test_users t where t.client_id = p_client)
     >= least(greatest(coalesce(p_max, 10), 1), 100) then
    return 'limit';
  end if;
  insert into public.oauth_client_test_users (client_id, identifier) values (p_client, v_id) on conflict do nothing;
  return 'ok';
end $$;

create or replace function public.rout_oauth_test_user_remove(p_client text, p_identifier text)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  delete from public.oauth_client_test_users t where t.client_id = p_client and t.identifier = pg_catalog.lower(pg_catalog.btrim(p_identifier));
end $$;

-- ------------------------------------------------------------------ verification requests
create or replace function public.rout_oauth_client_verified(p_client text)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select exists (select 1 from public.oauth_client_verification_requests v where v.client_id = p_client and v.status = 'verified')
$$;

create or replace function public.rout_oauth_verification_latest(p_client text)
returns table (status text, created_at timestamptz, reviewed_at timestamptz)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  return query select v.status, v.created_at, v.reviewed_at from public.oauth_client_verification_requests v
    where v.client_id = p_client order by v.created_at desc limit 1;
end $$;

create or replace function public.rout_oauth_verification_request(p_client text, p_note text)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  perform 1 from public.oauth_clients c where c.client_id = p_client for update;
  if exists (select 1 from public.oauth_client_verification_requests v
              where v.client_id = p_client and v.status in ('pending', 'verified')) then
    return 'exists';
  end if;
  insert into public.oauth_client_verification_requests (client_id, requested_by, note)
  values (p_client, public.rout_current_user_id(), nullif(left(p_note, 2000), ''));
  return 'ok';
end $$;

create or replace function public.rout_oauth_verification_pending()
returns table (id uuid, client_id text, note text, created_at timestamptz, name text, homepage_url text,
  privacy_url text, support_email text, legal_owner text)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_caller_has_admin_permission('review_apps') then raise exception 'forbidden' using errcode = '42501'; end if;
  return query select r.id, r.client_id, r.note, r.created_at, c.name, c.homepage_url, c.privacy_url, c.support_email, c.legal_owner
    from public.oauth_client_verification_requests r join public.oauth_clients c on c.client_id = r.client_id
   where r.status = 'pending' order by r.created_at;
end $$;

-- Returns the app name and owner for the review e-mail (empty when nothing was pending).
create or replace function public.rout_oauth_verification_review(p_request uuid, p_approve boolean)
returns table (name text, owner_user_id uuid)
language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not public.rout_caller_has_admin_permission('review_apps') then raise exception 'forbidden' using errcode = '42501'; end if;
  return query
    with done as (
      update public.oauth_client_verification_requests v
         set status = case when p_approve then 'verified' else 'rejected' end,
             reviewed_by = public.rout_current_user_id(), reviewed_at = now()
       where v.id = p_request and v.status = 'pending'
      returning v.client_id)
    select c.name, c.owner_user_id from done join public.oauth_clients c on c.client_id = done.client_id;
end $$;

-- Admin app list (all apps, latest review status, owner handle).
create or replace function public.rout_oauth_admin_apps()
returns table (id uuid, client_id text, name text, redirect_uris text[], status text, created_at timestamptz,
  owner_user_id uuid, owner_handle text, review_status text)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_caller_has_admin_permission('review_apps') then raise exception 'forbidden' using errcode = '42501'; end if;
  return query select c.id, c.client_id, c.name, c.redirect_uris, c.status, c.created_at, c.owner_user_id,
      p.username::text,
      (select v.status from public.oauth_client_verification_requests v where v.client_id = c.client_id
        order by v.created_at desc limit 1)
    from public.oauth_clients c left join public.profiles p on p.id = c.owner_user_id
   order by c.created_at desc limit 500;
end $$;

-- Admin decision on an app: approve/reject its review, or block/unblock it
-- (blocking also burns its open authorization codes). Returns client_id and name.
create or replace function public.rout_oauth_admin_app_decide(p_id uuid, p_action text)
returns table (client_id text, name text)
language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_client text; v_name text; v_actor uuid := public.rout_current_user_id();
begin
  if not public.rout_caller_has_admin_permission('review_apps') then raise exception 'forbidden' using errcode = '42501'; end if;
  if p_action not in ('approve', 'reject', 'block', 'unblock') then raise exception 'invalid_action' using errcode = '22023'; end if;
  select c.client_id, c.name into v_client, v_name from public.oauth_clients c where c.id = p_id for update;
  if not found then return; end if;
  if p_action in ('approve', 'reject') then
    update public.oauth_client_verification_requests v
       set status = case when p_action = 'approve' then 'verified' else 'rejected' end,
           reviewed_by = v_actor, reviewed_at = now()
     where v.client_id = v_client and v.status = 'pending';
    if not found then
      insert into public.oauth_client_verification_requests (client_id, requested_by, note, status, reviewed_by, reviewed_at)
      values (v_client, v_actor, 'Beslissing door admin', case when p_action = 'approve' then 'verified' else 'rejected' end, v_actor, now());
    end if;
  else
    update public.oauth_clients c set status = case when p_action = 'block' then 'disabled' else 'active' end where c.id = p_id;
    if p_action = 'block' then
      update public.oauth_auth_codes a set consumed_at = now() where a.client_id = v_client and a.consumed_at is null;
    end if;
  end if;
  return query select v_client, v_name;
end $$;

-- ------------------------------------------------------------------ debug events
-- Append-only developer log; values are bounded and old rows are trimmed here.
create or replace function public.rout_oauth_debug_log(p_client text, p_endpoint text, p_outcome text,
  p_error text, p_detail jsonb)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if p_endpoint not in ('authorize', 'token', 'userinfo') or p_outcome not in ('success', 'error')
     or p_client is null or pg_catalog.length(p_client) > 100
     or pg_catalog.octet_length(coalesce(p_detail, '{}'::jsonb)::text) > 4000
     or not exists (select 1 from public.oauth_clients c where c.client_id = p_client) then
    return;
  end if;
  insert into public.oauth_debug_events (client_id, endpoint, outcome, error_code, detail)
  values (p_client, p_endpoint, p_outcome, left(p_error, 100), coalesce(p_detail, '{}'::jsonb));
  if pg_catalog.random() < 0.02 then
    delete from public.oauth_debug_events e where e.created_at < now() - interval '7 days';
  end if;
end $$;

create or replace function public.rout_oauth_debug_list(p_client text, p_errors_only boolean)
returns table (id uuid, client_id text, endpoint text, outcome text, error_code text, detail jsonb, created_at timestamptz)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  if not public.rout_oauth_can_manage(p_client) then raise exception 'forbidden' using errcode = '42501'; end if;
  return query select e.id, e.client_id, e.endpoint, e.outcome, e.error_code, e.detail, e.created_at
    from public.oauth_debug_events e
   where e.client_id = p_client and (not coalesce(p_errors_only, false) or e.outcome = 'error')
     and e.created_at > now() - interval '7 days'
   order by e.created_at desc limit 100;
end $$;

-- Several apps at once: silently limited to the apps the caller may manage.
create or replace function public.rout_oauth_debug_activity(p_clients text[])
returns table (id uuid, client_id text, endpoint text, outcome text, error_code text, detail jsonb, created_at timestamptz)
language sql stable security definer set search_path = pg_catalog as $$
  select e.id, e.client_id, e.endpoint, e.outcome, e.error_code, e.detail, e.created_at
    from public.oauth_debug_events e
   where e.client_id = any (p_clients) and public.rout_oauth_can_manage(e.client_id)
     and e.created_at > now() - interval '7 days'
   order by e.created_at desc, e.id desc limit 50
$$;

-- ------------------------------------------------------------------ strict policies (next to rout_server until 0230)
do $$
begin
  drop policy if exists rout_owner on public.oauth_consents;
  create policy rout_owner on public.oauth_consents for select to rout_app
    using (user_id = public.rout_current_user_id() or public.rout_purge_due(user_id));
  drop policy if exists rout_owner_revoke on public.oauth_consents;
  create policy rout_owner_revoke on public.oauth_consents for update to rout_app
    using (user_id = public.rout_current_user_id()) with check (user_id = public.rout_current_user_id());
  drop policy if exists rout_owner_purge on public.oauth_consents;
  create policy rout_owner_purge on public.oauth_consents for delete to rout_app
    using (public.rout_purge_due(user_id));
  -- A DELETE ... WHERE user_id = $1 must also see the rows, so the purge gets a
  -- matching read policy (only user_id is granted after 0230).
  drop policy if exists rout_owner_purge_read on public.oauth_auth_codes;
  create policy rout_owner_purge_read on public.oauth_auth_codes for select to rout_app
    using (public.rout_purge_due(user_id));
  drop policy if exists rout_owner_purge on public.oauth_auth_codes;
  create policy rout_owner_purge on public.oauth_auth_codes for delete to rout_app
    using (public.rout_purge_due(user_id));
end $$;

-- ------------------------------------------------------------------ repair: account purge after 0227
-- A DELETE ... WHERE col = $1 also needs to read col. After 0227 the purge could
-- not read admin_bootstrap_tokens.consumed_by (permission denied, so the whole
-- purge transaction failed) nor see user_roles / admin_permissions rows. Grant
-- exactly that read, only while that member's deletion is due.
do $$
begin
  grant select (consumed_by) on table public.admin_bootstrap_tokens to rout_app;
  drop policy if exists rout_owner_purge_read on public.admin_bootstrap_tokens;
  create policy rout_owner_purge_read on public.admin_bootstrap_tokens for select to rout_app
    using (public.rout_purge_due(consumed_by));
  drop policy if exists rout_owner_purge_read on public.user_roles;
  create policy rout_owner_purge_read on public.user_roles for select to rout_app
    using (public.rout_purge_due(user_id));
  drop policy if exists rout_owner_purge_read on public.admin_permissions;
  create policy rout_owner_purge_read on public.admin_permissions for select to rout_app
    using (public.rout_purge_due(user_id));
end $$;

-- ------------------------------------------------------------------ privileges
do $$
declare f text;
begin
  foreach f in array array[
    'rout_oauth_can_manage(text)', 'rout_oauth_client_get(text)', 'rout_oauth_client_secret_hash(text)',
    'rout_oauth_user_may_use(text)', 'rout_oauth_email_webhook_targets(text[])',
    'rout_oauth_code_issue(text, text, text, text[], text, text, text, boolean, integer)',
    'rout_oauth_code_consume(text, text, text, text)', 'rout_oauth_client_code_stats(text)',
    'rout_oauth_signing_keys_list()', 'rout_oauth_signing_key_rotate(text, jsonb, text, text, text, text)',
    'rout_oauth_signing_keys_wipe(text[])', 'rout_oauth_signing_key_retire_legacy(text)',
    'rout_oauth_consent_grant(text, text[])', 'rout_oauth_consent_active(uuid, text, text)',
    'rout_oauth_client_consent_count(text)', 'rout_oauth_access_token_check(text, text, text)',
    'rout_oauth_access_token_introspect(text, text)', 'rout_oauth_refresh_token_introspect(text, text)',
    'rout_oauth_token_revoke(text, text)', 'rotate_oauth_refresh(text, text, text)',
    'rout_oauth_test_users_list(text)', 'rout_oauth_test_user_add(text, text, integer)',
    'rout_oauth_test_user_remove(text, text)', 'rout_oauth_client_verified(text)',
    'rout_oauth_verification_latest(text)', 'rout_oauth_verification_request(text, text)',
    'rout_oauth_verification_pending()', 'rout_oauth_verification_review(uuid, boolean)',
    'rout_oauth_admin_apps()', 'rout_oauth_admin_app_decide(uuid, text)',
    'rout_oauth_debug_log(text, text, text, text, jsonb)', 'rout_oauth_debug_list(text, boolean)',
    'rout_oauth_debug_activity(text[])'] loop
    execute format('revoke all on function public.%s from public', f);
    execute format('grant execute on function public.%s to rout_app', f);
  end loop;
end $$;
