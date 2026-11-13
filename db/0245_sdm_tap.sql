-- 0245 (EXPAND): ROUT Card taps, NXP NTAG 424 DNA SUN/SDM, unlinkable by design.
--
-- The card's tap URL carries ONLY the encrypted PICCData and the truncated
-- AES-CMAC (https://rout.be/t?p=<32 hex>&m=<16 hex>); no card id, no batch id.
-- PICCData changes on every tap, so two taps of the same card cannot be linked
-- without the fleet-wide K_SDMMetaRead.
--
--   fleet key   K_SDMMetaRead + a UID-index key (sdm_ envelope, server vault)
--   batch       batch master for AN10922 diversification (sdm_ envelope)
--   card        uid_hash = HMAC(UID-index key, UID); K_SDMFileRead is derived
--               per tap from the batch master and never stored
--
-- The server decrypts PICCData with the fleet key, looks the card up by
-- uid_hash, derives the card key and checks the CMAC; this schema enforces
-- everything around that: lockout, one attempt per tap, a 60 s window and a
-- strictly increasing counter (atomic, so a replayed URL never works twice).
-- A verified tap mints a single-use tap_ grant (120 s) for exactly one purpose.
-- rout_app has no table rights; only the functions below are executable.
-- The 0224 recovery-card path is left unchanged.

create table vault_enclave.sdm_fleet_keys (
  fleet_id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references public.users(id) on delete restrict,
  sdm_ref text not null unique references vault_enclave.opaque_tokens(token_ref) on delete restrict,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  retired_at timestamptz,
  constraint sdm_fleet_ref_kind check (left(sdm_ref, 4) = 'sdm_')
);

create table vault_enclave.sdm_batches (
  batch_id uuid primary key default gen_random_uuid(),
  fleet_id uuid not null references vault_enclave.sdm_fleet_keys(fleet_id) on delete restrict,
  owner_user_id uuid not null references public.users(id) on delete restrict,
  sdm_ref text not null unique references vault_enclave.opaque_tokens(token_ref) on delete restrict,
  label text not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  exported_at timestamptz,
  retired_at timestamptz,
  constraint sdm_batches_ref_kind check (left(sdm_ref, 4) = 'sdm_'),
  constraint sdm_batches_label check (char_length(label) between 1 and 80)
);

create table vault_enclave.sdm_batch_cards (
  card_id uuid primary key default gen_random_uuid(),
  batch_id uuid not null references vault_enclave.sdm_batches(batch_id) on delete restrict,
  uid_hash bytea not null unique,
  activation_hash bytea,
  owner_user_id uuid references public.users(id) on delete set null,
  last_counter integer,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  activated_at timestamptz,
  revoked_at timestamptz,
  constraint sdm_batch_cards_uid_hash_len check (octet_length(uid_hash) = 32),
  constraint sdm_batch_cards_activation_len check (activation_hash is null or octet_length(activation_hash) = 32),
  constraint sdm_batch_cards_counter_range check (last_counter is null or last_counter between 0 and 16777214)
);
create index sdm_batch_cards_batch_idx on vault_enclave.sdm_batch_cards (batch_id);
create index sdm_batch_cards_owner_idx on vault_enclave.sdm_batch_cards (owner_user_id);

create table vault_enclave.sdm_tap_attempts (
  attempt_id uuid primary key default gen_random_uuid(),
  card_id uuid not null references vault_enclave.sdm_batch_cards(card_id) on delete cascade,
  tap_digest bytea not null,
  started_at timestamptz not null,
  outcome text not null default 'pending',
  closed_at timestamptz,
  read_counter integer,
  constraint sdm_tap_attempts_outcome check (outcome in ('pending', 'verified', 'failed')),
  constraint sdm_tap_attempts_digest_len check (octet_length(tap_digest) = 32)
);
create index sdm_tap_attempts_card_idx on vault_enclave.sdm_tap_attempts (card_id, started_at);

-- Only the SHA-256 of a grant is stored: a database read never yields a usable grant.
create table vault_enclave.sdm_tap_grants (
  grant_digest bytea primary key,
  card_id uuid not null references vault_enclave.sdm_batch_cards(card_id) on delete cascade,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  consumed_for text,
  constraint sdm_tap_grants_digest_len check (octet_length(grant_digest) = 32),
  constraint sdm_tap_grants_purpose check (consumed_for is null or consumed_for in ('public_proof', 'step_up'))
);
create index sdm_tap_grants_card_idx on vault_enclave.sdm_tap_grants (card_id, created_at);

revoke all on table vault_enclave.sdm_fleet_keys from public, rout_app;
revoke all on table vault_enclave.sdm_batches from public, rout_app;
revoke all on table vault_enclave.sdm_batch_cards from public, rout_app;
revoke all on table vault_enclave.sdm_tap_attempts from public, rout_app;
revoke all on table vault_enclave.sdm_tap_grants from public, rout_app;
alter table vault_enclave.sdm_fleet_keys enable row level security;
alter table vault_enclave.sdm_batches enable row level security;
alter table vault_enclave.sdm_batch_cards enable row level security;
alter table vault_enclave.sdm_tap_attempts enable row level security;
alter table vault_enclave.sdm_tap_grants enable row level security;

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume'));

-- An sdm_ envelope may back exactly one card, fleet key or batch.
create function vault_enclave.sdm_ref_free(p_ref text)
returns boolean language sql stable set search_path = pg_catalog as $$
  select not exists (select 1 from vault_enclave.sdm_cards c where c.sdm_ref = p_ref)
     and not exists (select 1 from vault_enclave.sdm_fleet_keys f where f.sdm_ref = p_ref)
     and not exists (select 1 from vault_enclave.sdm_batches b where b.sdm_ref = p_ref)
$$;

-- ---------------------------------------------------------------- admin RPCs

create function vault_enclave.register_sdm_fleet_key(p_sdm_ref text)
returns uuid language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_ref text := case when p_sdm_ref ~ '^sdm_[0-9a-f]{64}$' then p_sdm_ref end;
  v_id uuid;
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_fleet_register', 'denied', 'not_admin', v_ref); return null;
  end if;
  if v_ref is null or not exists (
       select 1 from vault_enclave.opaque_tokens t where t.token_ref = v_ref and t.owner_user_id = v_caller and t.token_type = 'sdm')
     or not vault_enclave.sdm_ref_free(v_ref) then
    perform vault_enclave.append_audit(v_caller, 'sdm_fleet_register', 'denied', 'ref_unusable', v_ref); return null;
  end if;
  insert into vault_enclave.sdm_fleet_keys (owner_user_id, sdm_ref) values (v_caller, v_ref) returning fleet_id into v_id;
  perform vault_enclave.append_audit(v_caller, 'sdm_fleet_register', 'granted', 'ok', v_ref);
  return v_id;
end $$;

create function vault_enclave.register_sdm_batch(p_fleet_id uuid, p_sdm_ref text, p_label text)
returns uuid language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_ref text := case when p_sdm_ref ~ '^sdm_[0-9a-f]{64}$' then p_sdm_ref end;
  v_label text := pg_catalog.btrim(coalesce(p_label, ''));
  v_id uuid;
begin
  if v_caller is null or not public.rout_is_admin_member(v_caller) then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_register', 'denied', 'not_admin', v_ref); return null;
  end if;
  if not exists (select 1 from vault_enclave.sdm_fleet_keys f where f.fleet_id = p_fleet_id and f.retired_at is null)
     or char_length(v_label) not between 1 and 80
     or v_ref is null or not exists (
       select 1 from vault_enclave.opaque_tokens t where t.token_ref = v_ref and t.owner_user_id = v_caller and t.token_type = 'sdm')
     or not vault_enclave.sdm_ref_free(v_ref) then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_register', 'denied', 'bad_request', v_ref); return null;
  end if;
  insert into vault_enclave.sdm_batches (fleet_id, owner_user_id, sdm_ref, label)
  values (p_fleet_id, v_caller, v_ref, v_label) returning batch_id into v_id;
  perform vault_enclave.append_audit(v_caller, 'sdm_batch_register', 'granted', 'ok', v_ref);
  return v_id;
end $$;

-- Manifest import: one uid_hash (and optional activation-code hash) per card.
-- Returns how many new cards were registered; known uid_hashes are skipped.
create function vault_enclave.register_sdm_batch_cards(p_batch_id uuid, p_uid_hashes bytea[], p_activation_hashes bytea[])
returns integer language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_batch vault_enclave.sdm_batches%rowtype;
  v_n int := coalesce(pg_catalog.array_length(p_uid_hashes, 1), 0);
  v_rows int;
begin
  select * into v_batch from vault_enclave.sdm_batches b where b.batch_id = p_batch_id for update;
  if v_caller is null or not public.rout_is_admin_member(v_caller) or not found
     or v_batch.owner_user_id <> v_caller or v_batch.retired_at is not null then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_cards_register', 'denied', 'not_batch_owner', v_batch.sdm_ref); return null;
  end if;
  if v_n not between 1 and 5000
     or (p_activation_hashes is not null and coalesce(pg_catalog.array_length(p_activation_hashes, 1), 0) <> v_n)
     or exists (select 1 from pg_catalog.unnest(p_uid_hashes) h where h is null or octet_length(h) <> 32)
     or exists (select 1 from pg_catalog.unnest(p_activation_hashes) h where h is not null and octet_length(h) <> 32) then
    perform vault_enclave.append_audit(v_caller, 'sdm_batch_cards_register', 'denied', 'bad_manifest', v_batch.sdm_ref); return null;
  end if;
  insert into vault_enclave.sdm_batch_cards (batch_id, uid_hash, activation_hash)
  select v_batch.batch_id, u.h, a.h
    from pg_catalog.unnest(p_uid_hashes) with ordinality u(h, i)
    left join pg_catalog.unnest(p_activation_hashes) with ordinality a(h, i) on a.i = u.i
  on conflict (uid_hash) do nothing;
  get diagnostics v_rows = row_count;
  perform vault_enclave.append_audit(v_caller, 'sdm_batch_cards_register', 'granted', 'imported_' || v_rows, v_batch.sdm_ref);
  return v_rows;
end $$;

-- ---------------------------------------------------------------- tap RPCs (no session needed)

-- The active fleet keys, sealed: openable only with the server vault key.
create function vault_enclave.sdm_tap_fleet_keys()
returns table (fleet_id uuid, owner_user_id uuid, encrypted_payload bytea)
language sql stable security definer set search_path = pg_catalog as $$
  select f.fleet_id, f.owner_user_id, t.encrypted_payload
    from vault_enclave.sdm_fleet_keys f
    join vault_enclave.opaque_tokens t on t.token_ref = f.sdm_ref and t.owner_user_id = f.owner_user_id and t.token_type = 'sdm'
   where f.retired_at is null
   order by f.created_at desc
   limit 4
$$;

create function vault_enclave.begin_sdm_tap(p_fleet_id uuid, p_uid_hash bytea, p_picc_data bytea, p_cmac bytea)
returns table (granted boolean, attempt_id uuid, batch_id uuid, batch_owner uuid, encrypted_payload bytea, last_counter integer)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_card vault_enclave.sdm_batch_cards%rowtype;
  v_batch vault_enclave.sdm_batches%rowtype;
  v_failures int;
  v_attempt uuid;
  v_payload bytea;
begin
  if p_uid_hash is null or octet_length(p_uid_hash) <> 32
     or p_picc_data is null or octet_length(p_picc_data) <> 16 or p_cmac is null or octet_length(p_cmac) <> 8 then
    perform vault_enclave.append_audit(null, 'sdm_tap_begin', 'denied', 'malformed_tap', null);
    return query select false, null::uuid, null::uuid, null::uuid, null::bytea, null::integer; return;
  end if;
  select c.* into v_card from vault_enclave.sdm_batch_cards c
    join vault_enclave.sdm_batches b on b.batch_id = c.batch_id
   where c.uid_hash = p_uid_hash and b.fleet_id = p_fleet_id
   for update of c;
  if not found or v_card.revoked_at is not null then
    perform vault_enclave.append_audit(null, 'sdm_tap_begin', 'denied', case when found then 'card_revoked' else 'unknown_card' end, null);
    return query select false, null::uuid, null::uuid, null::uuid, null::bytea, null::integer; return;
  end if;
  select * into v_batch from vault_enclave.sdm_batches b where b.batch_id = v_card.batch_id;
  if v_batch.retired_at is not null then
    perform vault_enclave.append_audit(null, 'sdm_tap_begin', 'denied', 'batch_retired', v_batch.sdm_ref);
    return query select false, null::uuid, null::uuid, null::uuid, null::bytea, null::integer; return;
  end if;
  -- Serialise taps of one card so parallel requests cannot all pass the lockout.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_card.card_id::text, 7421003245));
  delete from vault_enclave.sdm_tap_attempts a where a.card_id = v_card.card_id and a.started_at < v_now - interval '1 day';
  delete from vault_enclave.sdm_tap_grants g where g.card_id = v_card.card_id and g.expires_at < v_now - interval '1 day';
  select count(*)::int into v_failures from vault_enclave.sdm_tap_attempts a
   where a.card_id = v_card.card_id and a.outcome <> 'verified' and a.started_at > v_now - interval '10 minutes';
  if v_failures >= 5 then
    perform vault_enclave.append_audit(v_card.owner_user_id, 'sdm_tap_begin', 'denied', 'card_locked', v_batch.sdm_ref);
    return query select false, null::uuid, null::uuid, null::uuid, null::bytea, null::integer; return;
  end if;
  select t.encrypted_payload into v_payload from vault_enclave.opaque_tokens t
   where t.token_ref = v_batch.sdm_ref and t.owner_user_id = v_batch.owner_user_id and t.token_type = 'sdm';
  if not found then
    perform vault_enclave.append_audit(v_card.owner_user_id, 'sdm_tap_begin', 'denied', 'envelope_missing', v_batch.sdm_ref);
    return query select false, null::uuid, null::uuid, null::uuid, null::bytea, null::integer; return;
  end if;
  insert into vault_enclave.sdm_tap_attempts (card_id, tap_digest, started_at)
  values (v_card.card_id, pg_catalog.sha256(p_picc_data || p_cmac), v_now)
  returning sdm_tap_attempts.attempt_id into v_attempt;
  perform vault_enclave.append_audit(v_card.owner_user_id, 'sdm_tap_begin', 'granted', 'pending', v_batch.sdm_ref);
  return query select true, v_attempt, v_batch.batch_id, v_batch.owner_user_id, v_payload, v_card.last_counter;
end $$;

-- Closes the attempt; returns a fresh tap_ grant only for a verified tap with a
-- strictly higher counter, for the same tap bytes, within 60 s.
create function vault_enclave.confirm_sdm_tap(
  p_attempt_id uuid, p_picc_data bytea, p_cmac bytea, p_verified boolean, p_read_counter integer)
returns text language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_attempt vault_enclave.sdm_tap_attempts%rowtype;
  v_owner uuid;
  v_rows int;
  v_grant text;
begin
  select * into v_attempt from vault_enclave.sdm_tap_attempts a where a.attempt_id = p_attempt_id for update;
  if not found or v_attempt.outcome <> 'pending' then
    perform vault_enclave.append_audit(null, 'sdm_tap_confirm', 'denied', 'attempt_not_pending', null);
    return null;
  end if;
  select c.owner_user_id into v_owner from vault_enclave.sdm_batch_cards c where c.card_id = v_attempt.card_id;
  if p_verified is distinct from true
     or v_now - v_attempt.started_at > interval '60 seconds'
     or p_picc_data is null or p_cmac is null
     or pg_catalog.sha256(p_picc_data || p_cmac) <> v_attempt.tap_digest
     or p_read_counter is null or p_read_counter not between 0 and 16777214 then
    update vault_enclave.sdm_tap_attempts set outcome = 'failed', closed_at = v_now where attempt_id = v_attempt.attempt_id;
    perform vault_enclave.append_audit(v_owner, 'sdm_tap_confirm', 'denied',
      case when p_verified is distinct from true then 'cmac_invalid'
           when v_now - v_attempt.started_at > interval '60 seconds' then 'attempt_expired'
           when p_read_counter is null or p_read_counter not between 0 and 16777214 then 'bad_counter'
           else 'tap_mismatch' end, null);
    return null;
  end if;
  update vault_enclave.sdm_batch_cards c set last_counter = p_read_counter
   where c.card_id = v_attempt.card_id and c.revoked_at is null
     and (c.last_counter is null or c.last_counter < p_read_counter);
  get diagnostics v_rows = row_count;
  if v_rows = 0 then
    update vault_enclave.sdm_tap_attempts set outcome = 'failed', closed_at = v_now where attempt_id = v_attempt.attempt_id;
    perform vault_enclave.append_audit(v_owner, 'sdm_tap_confirm', 'denied', 'replayed', null);
    return null;
  end if;
  update vault_enclave.sdm_tap_attempts set outcome = 'verified', closed_at = v_now, read_counter = p_read_counter
   where attempt_id = v_attempt.attempt_id;
  v_grant := 'tap_' || pg_catalog.encode(public.gen_random_bytes(32), 'hex');
  insert into vault_enclave.sdm_tap_grants (grant_digest, card_id, created_at, expires_at)
  values (pg_catalog.sha256(pg_catalog.convert_to(v_grant, 'UTF8')), v_attempt.card_id, v_now, v_now + interval '120 seconds');
  perform vault_enclave.append_audit(v_owner, 'sdm_tap_confirm', 'granted', 'ok', null);
  return v_grant;
end $$;

-- Spends a tap_ grant once, for one purpose. public_proof needs no session and
-- reveals only whether the card is activated; step_up only works for the
-- card's own owner (the caller from the transaction context).
create function vault_enclave.consume_sdm_tap(p_tap_ref text, p_purpose text)
returns table (granted boolean, card_state text)
language plpgsql security definer set search_path = pg_catalog as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_caller uuid := vault_enclave.caller_user_id();
  v_grant vault_enclave.sdm_tap_grants%rowtype;
  v_card vault_enclave.sdm_batch_cards%rowtype;
begin
  if p_tap_ref is null or p_tap_ref !~ '^tap_[0-9a-f]{64}$' or p_purpose not in ('public_proof', 'step_up') then
    perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'denied', 'bad_request', null);
    return query select false, null::text; return;
  end if;
  select * into v_grant from vault_enclave.sdm_tap_grants g
   where g.grant_digest = pg_catalog.sha256(pg_catalog.convert_to(p_tap_ref, 'UTF8')) for update;
  if not found or v_grant.consumed_at is not null or v_grant.expires_at < v_now then
    perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'denied',
      case when not found then 'unknown_grant' when v_grant.consumed_at is not null then 'grant_spent' else 'grant_expired' end, null);
    return query select false, null::text; return;
  end if;
  select * into v_card from vault_enclave.sdm_batch_cards c where c.card_id = v_grant.card_id;
  if v_card.revoked_at is not null or (p_purpose = 'step_up' and (v_caller is null or v_card.owner_user_id is distinct from v_caller)) then
    update vault_enclave.sdm_tap_grants set consumed_at = v_now, consumed_for = p_purpose where grant_digest = v_grant.grant_digest;
    perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'denied',
      case when v_card.revoked_at is not null then 'card_revoked' else 'not_card_owner' end, null);
    return query select false, null::text; return;
  end if;
  update vault_enclave.sdm_tap_grants set consumed_at = v_now, consumed_for = p_purpose where grant_digest = v_grant.grant_digest;
  perform vault_enclave.append_audit(v_caller, 'sdm_tap_consume', 'granted', p_purpose, null);
  return query select true, case when v_card.owner_user_id is null then 'unactivated' else 'active' end;
end $$;

revoke all on function vault_enclave.sdm_ref_free(text) from public, rout_app;
revoke all on function vault_enclave.register_sdm_fleet_key(text) from public, rout_app;
revoke all on function vault_enclave.register_sdm_batch(uuid, text, text) from public, rout_app;
revoke all on function vault_enclave.register_sdm_batch_cards(uuid, bytea[], bytea[]) from public, rout_app;
revoke all on function vault_enclave.sdm_tap_fleet_keys() from public, rout_app;
revoke all on function vault_enclave.begin_sdm_tap(uuid, bytea, bytea, bytea) from public, rout_app;
revoke all on function vault_enclave.confirm_sdm_tap(uuid, bytea, bytea, boolean, integer) from public, rout_app;
revoke all on function vault_enclave.consume_sdm_tap(text, text) from public, rout_app;
grant execute on function vault_enclave.register_sdm_fleet_key(text) to rout_app;
grant execute on function vault_enclave.register_sdm_batch(uuid, text, text) to rout_app;
grant execute on function vault_enclave.register_sdm_batch_cards(uuid, bytea[], bytea[]) to rout_app;
grant execute on function vault_enclave.sdm_tap_fleet_keys() to rout_app;
grant execute on function vault_enclave.begin_sdm_tap(uuid, bytea, bytea, bytea) to rout_app;
grant execute on function vault_enclave.confirm_sdm_tap(uuid, bytea, bytea, boolean, integer) to rout_app;
grant execute on function vault_enclave.consume_sdm_tap(text, text) to rout_app;
