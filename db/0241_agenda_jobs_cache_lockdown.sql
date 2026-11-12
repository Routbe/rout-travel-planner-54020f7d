-- 0241: CONTRACT step of 0240 — the last tables with the free "rout_server"
-- access. Apply only after every deployment runs the code that uses the 0240
-- functions.
--
-- After this file rout_app has, on these tables:
--   booking_requests                read, the host's own requests
--   platform_integration_switches   read provider + mode only
--   everything else                 nothing (functions only)
do $$
declare t text;
begin
  foreach t in array array['availability_jobs', 'booking_requests', 'alias_sync_jobs', 'forwarding_confirmation_sends',
                           'ambient_weather_cache', 'platform_integration_switches'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
  end loop;
  grant select on table public.booking_requests to rout_app;
  grant select (provider, mode) on table public.platform_integration_switches to rout_app;
end $$;
