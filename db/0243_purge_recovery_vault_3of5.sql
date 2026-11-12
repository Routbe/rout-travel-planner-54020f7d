-- 0243: purge the 3-of-5 recovery vault (0209/0210). Owner's decision: every
-- existing 3-of-5 setup is invalidated and deleted, with no fallback. The only
-- recovery left is the 2-of-3 ceremony of 0242.
--
-- Removed: recovery_vaults, recovery_sealed_shards, recovery_attempts, their
-- functions and shard-ceiling trigger, and their account-merge guards.
-- Kept: pairwise_subjects and rout_pairwise_register (0209, unrelated).

-- 1. Account merge: drop the two guards first, or the merge would fail on a
--    table that no longer exists.
do $own$ begin execute format('grant rout_merge_executor to %I with inherit true, set true', current_user); end $own$;
grant create on schema public to rout_merge_executor;

do $m$
declare
  v_def text;
  v_new text;
begin
  select pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) into v_def;
  v_new := regexp_replace(v_def, E'[^\\n]*''merge_blocked:recovery_(vaults|attempts)''[^\\n]*\\n', '', 'g');
  if position('merge_blocked:recovery_vaults''' in v_new) > 0 or position('merge_blocked:recovery_attempts''' in v_new) > 0 then
    raise exception 'execute_account_merge: legacy recovery guards still present';
  end if;
  if v_new <> v_def then execute v_new; end if;
end $m$;

revoke create on schema public from rout_merge_executor;
do $own$ begin execute format('revoke rout_merge_executor from %I', current_user); end $own$;

-- 2. Functions (they reference the tables, so they go first).
drop function if exists public.rout_recovery_vault_put(uuid, text, text, jsonb);
drop function if exists public.rout_recovery_vault_get(uuid);
drop function if exists public.rout_recovery_vault_delete(uuid);
drop function if exists public.rout_recovery_shard_put(uuid, text, smallint, text, text);
drop function if exists public.rout_recovery_shards_get(uuid);
drop function if exists public.rout_recovery_attempt(uuid, text);
drop function if exists public.rout_recovery_attempts_list(uuid);

-- 3. Tables with all their rows (shards before vaults; the trigger goes with its table).
drop table if exists public.recovery_sealed_shards;
drop function if exists public.rout_recovery_shard_ceiling();
drop table if exists public.recovery_vaults;
drop table if exists public.recovery_attempts;
