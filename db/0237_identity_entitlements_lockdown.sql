-- 0237: CONTRACT step of 0236. Removes the free "rout_server" access from the
-- identity, credential and entitlement tables. Apply only after every
-- deployment runs the code that uses the 0236 functions.
--
-- After this file rout_app has, on these tables:
--   badges, reserved_handles     read (public catalogue policy)
--   api_keys                     the signed-in owner's own rows (policies)
--   everything else              nothing (functions only, or unused)
do $$
declare t text;
begin
  foreach t in array array['credential_issue_requests', 'credential_issuer_blocks', 'identity_labels', 'account_merge_tickets',
                           'api_keys', 'reserved_handles', 'badges', 'entitlement_overrides', 'referrals', 'didit_monthly_usage'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
  end loop;
  grant select on table public.badges, public.reserved_handles to rout_app;
  grant select, insert, delete, update (name, revoked_at, updated_at) on table public.api_keys to rout_app;
end $$;
