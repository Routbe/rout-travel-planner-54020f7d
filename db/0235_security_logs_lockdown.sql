-- 0235: CONTRACT step of 0234. Removes the free "rout_server" access from the
-- security logs, webhook bookkeeping and the SEPA review queue. Apply only
-- after every deployment runs the code that uses the 0234 functions.
--
-- After this file rout_app has, on these tables:
--   security_events, webhook_deliveries   nothing (functions only)
--   webhook_events        admins read (session-bound policy)
--   sepa_review_queue     admins read and decide; a due purge deletes the member's rows
--   security_audit_logs   a due purge deletes the member's rows; nothing else
do $$
declare t text;
begin
  foreach t in array array['security_audit_logs', 'security_events', 'webhook_events', 'webhook_deliveries', 'sepa_review_queue'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
  end loop;
  grant select on table public.webhook_events to rout_app;
  grant select, update (status, decided_by, decided_at, notes), delete on table public.sepa_review_queue to rout_app;
  grant select (user_id, created_at), delete on table public.security_audit_logs to rout_app;
end $$;
