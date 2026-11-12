-- 0239: CONTRACT step of 0238. Removes the free "rout_server" access from the
-- public profile, statistics and visitor-form tables. Apply only after every
-- deployment runs the code that uses the 0238 functions.
--
-- After this file rout_app has, on these tables:
--   links, qr_scans                 read + delete, within the owner/colleague/admin policies
--   profile_link_clicks             read, the owner's own clicks
--   showcase_profiles               read (public catalogue)
--   lead_captures                   read, the profile owner's own messages
--   contact_submissions             read, admins only
--   poll_votes, onboarding_drafts   nothing (functions only)
do $$
declare t text;
begin
  foreach t in array array['links', 'profile_link_clicks', 'qr_scans', 'poll_votes', 'showcase_profiles',
                           'lead_captures', 'contact_submissions', 'onboarding_drafts'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
  end loop;
  grant select, delete on table public.links, public.qr_scans to rout_app;
  grant select on table public.profile_link_clicks, public.showcase_profiles, public.lead_captures,
                        public.contact_submissions to rout_app;
end $$;
