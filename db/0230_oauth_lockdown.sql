-- 0230: CONTRACT step of 0228. Removes the free "rout_server" access from the
-- ROUT ID tables. Apply only after every deployment runs the code that uses
-- the 0228 functions (hold back with migrate-gateway --only until then).
--
-- After this file rout_app has, on these tables:
--   oauth_auth_codes                    read user_id + delete, both only during a due account purge
--   oauth_consents                      select/update(revoke) own rows, delete during a due purge
--   oauth_signing_keys                  nothing (functions only)
--   oauth_client_test_users             nothing (functions only)
--   oauth_client_verification_requests  nothing (functions only)
--   oauth_debug_events                  nothing (functions only)
do $$
declare t text;
begin
  foreach t in array array['oauth_auth_codes', 'oauth_consents', 'oauth_signing_keys', 'oauth_client_test_users',
                           'oauth_client_verification_requests', 'oauth_debug_events'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
  end loop;
  grant select, update (revoked_at), delete on table public.oauth_consents to rout_app;
  grant select (user_id), delete on table public.oauth_auth_codes to rout_app;
end $$;
