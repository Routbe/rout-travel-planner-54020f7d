-- 0233: CONTRACT step of 0232. Removes the free "rout_server" access from the
-- anti-abuse stores and the session-less sign-in tables. Apply only after every
-- deployment runs the code that uses the 0232 functions.
--
-- After this file rout_app has no table rights on any of these eight tables;
-- upload_rate_limits is unused by the code and simply closes.
do $$
declare t text;
begin
  foreach t in array array['altcha_used', 'signin_throttle', 'rate_limits', 'upload_rate_limits', 'login_codes',
                           'fediverse_email_otp', 'telegram_verify_sessions', 'mastodon_app_registrations'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
  end loop;
end $$;
