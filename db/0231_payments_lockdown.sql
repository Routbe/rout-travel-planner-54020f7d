-- 0231: CONTRACT step of 0229. Removes the free "rout_server" access from the
-- payment, gift-card, promo-code and pricing tables. Apply only after every
-- deployment runs the code that uses the 0229 functions.
--
-- After this file rout_app has, on these tables:
--   gift_cards, promo_codes, promo_code_events, pricing_settings   nothing (functions only)
--   psp_credentials        read the non-secret columns of own rows; delete during a due purge
--   verification_payments  read own rows; admins read all and update status/provider_ref
do $$
declare t text;
begin
  foreach t in array array['gift_cards', 'promo_codes', 'promo_code_events', 'pricing_settings',
                           'psp_credentials', 'verification_payments'] loop
    execute format('drop policy if exists rout_server on public.%I', t);
    execute format('revoke all on table public.%I from rout_app', t);
  end loop;
  grant select (user_id, provider, last4, mode, verified_at, publishable_key), delete on table public.psp_credentials to rout_app;
  grant select, update (status, provider_ref, updated_at) on table public.verification_payments to rout_app;
end $$;
