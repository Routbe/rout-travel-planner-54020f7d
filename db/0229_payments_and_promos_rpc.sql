-- 0229: payments, gift cards, promo codes and pricing through database
-- functions (0223 phase 4, batch "betalingen"). EXPAND step: only adds
-- functions and strict policies next to the legacy "rout_server" policies, so
-- the deployed code keeps working. db-pending/0231 removes the free access once
-- every deployment runs the code that uses these functions.
--
-- Who calls what:
--   * members (caller = rout_current_user_id()): open/reprice/attach/fail their
--     own verification payment, save/delete their own payment-provider keys,
--     buy a gift card, list the gift cards they bought;
--   * signed webhooks and cron (no member context; the route verified the
--     provider signature or cron secret before calling): one payment by id or
--     reference, the fixed status transitions, the atomic "paid" claim, gift
--     card activation, the transfer-window scan;
--   * admins (rout_has_role(caller, 'admin')): pricing, promo-code management,
--     gift shipments; their payment screens read/update through the
--     session-bound admin policies below.
--
-- Double spending: gift activation locks the gift row (FOR UPDATE) and creates
-- its promo code in the same function; a promo redemption is one UPDATE whose
-- WHERE re-checks active/expiry/cap under the row lock, so two concurrent
-- claims can never both pass the cap.

-- ------------------------------------------------------------------ helpers
create or replace function public.rout_caller_is_admin()
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_has_role(public.rout_current_user_id(), 'admin')
$$;

create or replace function public.rout_require_member()
returns uuid language plpgsql stable security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_current_user_id();
begin
  if v is null then raise exception 'member context required' using errcode = '42501'; end if;
  return v;
end $$;

create or replace function public.rout_require_admin()
returns uuid language plpgsql stable security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_current_user_id();
begin
  if v is null or not public.rout_has_role(v, 'admin') then
    raise exception 'admin required' using errcode = '42501';
  end if;
  return v;
end $$;

-- ============================================================ pricing
create or replace function public.rout_pricing_get()
returns jsonb language sql stable security definer set search_path = pg_catalog as $$
  select pg_catalog.jsonb_build_object(
           'verification_base_cents', s.verification_base_cents, 'fee_card_cents', s.fee_card_cents,
           'fee_bunq_cents', s.fee_bunq_cents, 'fee_sepa_cents', s.fee_sepa_cents,
           'min_donation_cents', s.min_donation_cents)
    from public.pricing_settings s where s.id = 1
$$;

create or replace function public.rout_pricing_set(p_base int, p_card int, p_bunq int, p_sepa int, p_min_donation int)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_admin uuid := public.rout_require_admin();
begin
  if least(p_base, p_card, p_bunq, p_sepa, p_min_donation) < 0
     or greatest(p_base, p_card, p_bunq, p_sepa, p_min_donation) > 100000 then
    raise exception 'pricing out of range' using errcode = '22023';
  end if;
  insert into public.pricing_settings
    (id, verification_base_cents, fee_card_cents, fee_bunq_cents, fee_sepa_cents, min_donation_cents, updated_at, updated_by)
  values (1, p_base, p_card, p_bunq, p_sepa, p_min_donation, pg_catalog.now(), v_admin)
  on conflict (id) do update set
    verification_base_cents = excluded.verification_base_cents, fee_card_cents = excluded.fee_card_cents,
    fee_bunq_cents = excluded.fee_bunq_cents, fee_sepa_cents = excluded.fee_sepa_cents,
    min_donation_cents = excluded.min_donation_cents, updated_at = pg_catalog.now(), updated_by = v_admin;
end $$;

-- ============================================================ promo codes
-- One exact code, only while redeemable. No listing, no counts.
create or replace function public.rout_promo_lookup(p_code text)
returns table (percent_off int, amount_off_cents int, label text, max_discount_cents int)
language sql stable security definer set search_path = pg_catalog as $$
  select c.percent_off, c.amount_off_cents, c.label, c.max_discount_cents
    from public.promo_codes c
   where c.code = p_code and c.active
     and (c.expires_at is null or c.expires_at > pg_catalog.now())
     and (c.max_redemptions is null or c.redeemed_count < c.max_redemptions)
   limit 1
$$;

-- Atomic claim: the cap is re-checked under the row lock of this UPDATE.
-- Returns no row when the code is used up, expired or unknown. Writes the audit trail itself.
create or replace function public.rout_promo_redeem(p_code text)
returns table (redeemed_count int, max_redemptions int)
language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_count int; v_max int;
begin
  update public.promo_codes c
     set redeemed_count = c.redeemed_count + 1,
         last_redeemed_at = pg_catalog.now(),
         active = case when c.max_redemptions is not null and c.redeemed_count + 1 >= c.max_redemptions
                       then false else c.active end,
         updated_at = pg_catalog.now()
   where c.code = p_code and c.active
     and (c.expires_at is null or c.expires_at > pg_catalog.now())
     and (c.max_redemptions is null or c.redeemed_count < c.max_redemptions)
  returning c.redeemed_count, c.max_redemptions into v_count, v_max;
  if v_count is null then
    insert into public.promo_code_events (code, event, detail) values (p_code, 'exhausted', 'claim geweigerd: niet meer geldig');
    return;
  end if;
  insert into public.promo_code_events (code, event, detail) values (p_code, 'redeemed', 'gebruik #' || v_count);
  if v_max is not null and v_count >= v_max then
    insert into public.promo_code_events (code, event, detail) values (p_code, 'exhausted', 'maximum bereikt');
  end if;
  redeemed_count := v_count; max_redemptions := v_max;
  return next;
end $$;

-- Admin audit notes (created / sent by mail or SMS). Redemptions log themselves.
create or replace function public.rout_promo_event(p_code text, p_event text, p_detail text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  if not public.rout_caller_is_admin() or p_event not in ('created', 'sent_email', 'sent_sms') then return false; end if;
  insert into public.promo_code_events (code, event, detail) values (p_code, p_event, pg_catalog.left(p_detail, 500));
  return true;
end $$;

create or replace function public.rout_promo_admin_save(
  p_code text, p_label text, p_percent int, p_amount int, p_max_discount int,
  p_max_redemptions int, p_expires_at timestamptz, p_overwrite boolean)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  perform public.rout_require_admin();
  if p_code !~ '^[^[:space:]]{1,64}$' or coalesce(p_percent, 0) not between 0 and 100 or coalesce(p_amount, 0) < 0
     or (p_max_redemptions is not null and p_max_redemptions not between 1 and 100000) then
    raise exception 'invalid promo code' using errcode = '22023';
  end if;
  if p_overwrite then
    insert into public.promo_codes (code, label, percent_off, amount_off_cents, max_discount_cents, max_redemptions, expires_at, active)
    values (p_code, p_label, coalesce(p_percent, 0), coalesce(p_amount, 0), p_max_discount, p_max_redemptions, p_expires_at, true)
    on conflict (code) do update set label = excluded.label, percent_off = excluded.percent_off,
      amount_off_cents = excluded.amount_off_cents, max_discount_cents = excluded.max_discount_cents,
      max_redemptions = excluded.max_redemptions, expires_at = excluded.expires_at, active = true, updated_at = pg_catalog.now();
    return true;
  end if;
  insert into public.promo_codes (code, label, percent_off, amount_off_cents, max_discount_cents, max_redemptions, expires_at, active)
  values (p_code, p_label, coalesce(p_percent, 0), coalesce(p_amount, 0), p_max_discount, p_max_redemptions, p_expires_at, true)
  on conflict (code) do nothing;
  return found;
end $$;

create or replace function public.rout_promo_admin_list(p_limit int)
returns setof jsonb language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  perform public.rout_require_admin();
  return query select pg_catalog.jsonb_build_object('code', c.code, 'label', c.label, 'percent_off', c.percent_off,
      'amount_off_cents', c.amount_off_cents, 'max_redemptions', c.max_redemptions, 'redeemed_count', c.redeemed_count,
      'active', c.active, 'expires_at', c.expires_at, 'created_at', c.created_at)
    from public.promo_codes c order by c.created_at desc limit least(greatest(coalesce(p_limit, 50), 1), 500);
end $$;

create or replace function public.rout_promo_admin_terms(p_code text)
returns table (max_redemptions int, expires_at timestamptz)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  perform public.rout_require_admin();
  return query select c.max_redemptions, c.expires_at from public.promo_codes c where c.code = p_code limit 1;
end $$;

-- ============================================================ gift cards
-- Purchase (anonymous or member). Returns null when the code is already taken.
create or replace function public.rout_gift_card_create(
  p_code text, p_amount int, p_purchaser_user_id uuid, p_purchaser_email text, p_purchaser_name text,
  p_recipient_email text, p_recipient_name text, p_message text, p_design text, p_physical boolean,
  p_ship_name text, p_ship_line1 text, p_ship_postal_code text, p_ship_city text, p_ship_country text)
returns uuid language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_id uuid;
begin
  if p_purchaser_user_id is not null and p_purchaser_user_id is distinct from public.rout_current_user_id() then
    raise exception 'purchaser must be the caller' using errcode = '42501';
  end if;
  if p_amount not between 500 and 50000 or pg_catalog.length(coalesce(p_purchaser_email, '')) not between 3 and 320 then
    raise exception 'invalid gift order' using errcode = '22023';
  end if;
  insert into public.gift_cards (code, amount_cents, purchaser_user_id, purchaser_email, purchaser_name,
      recipient_email, recipient_name, message, design, physical_delivery,
      ship_name, ship_line1, ship_postal_code, ship_city, ship_country)
  values (p_code, p_amount, p_purchaser_user_id, p_purchaser_email, p_purchaser_name,
      p_recipient_email, p_recipient_name, pg_catalog.left(p_message, 1000), coalesce(p_design, 'classic'), coalesce(p_physical, false),
      p_ship_name, p_ship_line1, p_ship_postal_code, p_ship_city, p_ship_country)
  on conflict (code) do nothing
  returning id into v_id;
  return v_id;
end $$;

-- Payment confirmed (signed Stripe webhook or an admin gift). Locks the row,
-- flips pending -> paid and creates the one promo code in the same transaction;
-- a second delivery finds nothing to do. p_paid_cents, when given, must equal the card value.
create or replace function public.rout_gift_card_activate(
  p_gift uuid, p_reference text, p_max_redemptions int, p_expires_at timestamptz, p_paid_cents int)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog as $$
declare g public.gift_cards;
begin
  select * into g from public.gift_cards where id = p_gift for update;
  if not found then return pg_catalog.jsonb_build_object('outcome', 'not_found'); end if;
  if p_paid_cents is not null and p_paid_cents <> g.amount_cents then
    return pg_catalog.jsonb_build_object('outcome', 'amount_mismatch');
  end if;
  if coalesce(p_max_redemptions, 1) not between 1 and 10000 then
    raise exception 'invalid redemption cap' using errcode = '22023';
  end if;
  if not (g.status = 'pending'
          or (g.status = 'paid' and not exists (select 1 from public.promo_codes c where c.code = g.code))) then
    return pg_catalog.jsonb_build_object('outcome', 'duplicate');
  end if;
  update public.gift_cards
     set status = 'paid', paid_at = pg_catalog.now(),
         fulfilment_status = case when physical_delivery then 'pending_print' else fulfilment_status end,
         stripe_reference = coalesce(p_reference, stripe_reference), updated_at = pg_catalog.now()
   where id = p_gift
  returning * into g;
  insert into public.promo_codes (code, label, percent_off, amount_off_cents, max_redemptions, expires_at, active)
  values (g.code, 'Cadeaubon', 0, g.amount_cents, coalesce(p_max_redemptions, 1), p_expires_at, true)
  on conflict (code) do nothing;
  return pg_catalog.jsonb_build_object('outcome', 'activated', 'card', pg_catalog.to_jsonb(g));
end $$;

create or replace function public.rout_gift_card_mark_delivered(p_gift uuid, p_invoice text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  update public.gift_cards set status = 'delivered', delivered_at = pg_catalog.now(), invoice_number = p_invoice,
         updated_at = pg_catalog.now()
   where id = p_gift and status = 'paid';
  return found;
end $$;

-- Public card view: paid/delivered cards only, never e-mail or address.
create or replace function public.rout_gift_card_public(p_code text)
returns jsonb language sql stable security definer set search_path = pg_catalog as $$
  select pg_catalog.jsonb_build_object('code', g.code, 'amount_cents', g.amount_cents, 'currency', g.currency,
           'design', g.design, 'recipient_name', g.recipient_name, 'purchaser_name', g.purchaser_name,
           'message', g.message, 'status', g.status, 'fulfilment_status', g.fulfilment_status,
           'tracking_code', g.tracking_code, 'created_at', g.created_at,
           'redeemed', coalesce((select c.redeemed_count > 0 from public.promo_codes c where c.code = g.code), false))
    from public.gift_cards g where g.code = p_code and g.status in ('paid', 'delivered') limit 1
$$;

create or replace function public.rout_gift_card_mine()
returns setof jsonb language plpgsql stable security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member();
begin
  return query select pg_catalog.jsonb_build_object('code', g.code, 'amount_cents', g.amount_cents, 'currency', g.currency,
           'design', g.design, 'recipient_name', g.recipient_name, 'purchaser_name', g.purchaser_name,
           'message', g.message, 'status', g.status, 'fulfilment_status', g.fulfilment_status,
           'tracking_code', g.tracking_code, 'created_at', g.created_at,
           'redeemed', coalesce((select c.redeemed_count > 0 from public.promo_codes c where c.code = g.code), false))
    from public.gift_cards g where g.purchaser_user_id = v order by g.created_at desc limit 50;
end $$;

create or replace function public.rout_gift_card_recipient(p_code text)
returns table (recipient_email text, recipient_name text, message text)
language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  perform public.rout_require_admin();
  return query select g.recipient_email, g.recipient_name, g.message from public.gift_cards g where g.code = p_code limit 1;
end $$;

create or replace function public.rout_gift_shipments(p_open_only boolean)
returns setof jsonb language plpgsql stable security definer set search_path = pg_catalog as $$
begin
  perform public.rout_require_admin();
  return query select pg_catalog.jsonb_build_object('id', g.id, 'code', g.code, 'amount_cents', g.amount_cents,
      'design', g.design, 'status', g.status, 'fulfilment_status', g.fulfilment_status, 'tracking_code', g.tracking_code,
      'purchaser_email', g.purchaser_email, 'recipient_name', g.recipient_name, 'ship_name', g.ship_name,
      'ship_line1', g.ship_line1, 'ship_postal_code', g.ship_postal_code, 'ship_city', g.ship_city,
      'ship_country', g.ship_country, 'created_at', g.created_at, 'shipped_at', g.shipped_at)
    from public.gift_cards g
   where g.physical_delivery and g.status in ('paid', 'delivered')
     and (not p_open_only or g.fulfilment_status <> 'shipped')
   order by g.created_at asc limit 200;
end $$;

create or replace function public.rout_gift_shipment_update(p_gift uuid, p_status text, p_tracking text)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_code text;
begin
  perform public.rout_require_admin();
  update public.gift_cards
     set fulfilment_status = p_status, tracking_code = coalesce(p_tracking, tracking_code),
         packaged_at = case when p_status = 'packaged' then pg_catalog.now() else packaged_at end,
         shipped_at = case when p_status = 'shipped' then pg_catalog.now() else shipped_at end,
         updated_at = pg_catalog.now()
   where id = p_gift and physical_delivery
  returning code into v_code;
  return v_code;
end $$;

-- ============================================================ creator payment keys
-- Owner writes (sealed secret only; the plaintext never reaches the database).
create or replace function public.rout_psp_save(p_provider text, p_ciphertext text, p_iv text, p_last4 text, p_mode text, p_publishable_key text)
returns void language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member();
begin
  insert into public.psp_credentials (user_id, provider, ciphertext, iv, last4, mode, publishable_key, verified_at)
  values (v, p_provider, p_ciphertext, p_iv, pg_catalog.right(p_last4, 4), p_mode, p_publishable_key, pg_catalog.now())
  on conflict (user_id, provider) do update set ciphertext = excluded.ciphertext, iv = excluded.iv,
    last4 = excluded.last4, mode = excluded.mode, publishable_key = excluded.publishable_key, verified_at = pg_catalog.now();
end $$;

create or replace function public.rout_psp_delete(p_provider text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member();
begin
  delete from public.psp_credentials where user_id = v and provider = p_provider;
  return found;
end $$;

-- Who has an active public tip page with payment keys. Shared gate for the two public functions.
create or replace function public.rout_psp_public_owner(p_user uuid)
returns boolean language sql stable security definer set search_path = pg_catalog as $$
  select exists (
    select 1 from public.profiles p join public.tip_settings t on t.user_id = p.id
     where p.id = p_user and p.verified is true and p.username is not null
       and not coalesce(p.is_banned, false) and not coalesce(p.is_suspended, false)
       and coalesce(p.status, 'active') = 'active'
       and coalesce((pg_catalog.to_jsonb(p) ->> 'is_business')::boolean, false)
       and t.enabled)
$$;


-- Public tip page: which providers are linked (no key material).
create or replace function public.rout_psp_public_providers(p_user uuid)
returns setof text language sql stable security definer set search_path = pg_catalog as $$
  select c.provider from public.psp_credentials c
   where c.user_id = p_user and public.rout_psp_public_owner(p_user) order by c.provider
$$;

-- startPspTip only: the sealed key of one creator with an active public tip page.
-- Useless without PSP_ENCRYPTION_KEY, which lives only in the server environment.
create or replace function public.rout_psp_tip_credential(p_user uuid, p_provider text)
returns table (ciphertext text, iv text, publishable_key text)
language sql stable security definer set search_path = pg_catalog as $$
  select c.ciphertext, c.iv, c.publishable_key from public.psp_credentials c
   where c.user_id = p_user and c.provider = p_provider and public.rout_psp_public_owner(p_user) limit 1
$$;

-- ============================================================ verification payments
create or replace function public.rout_vp_json(v public.verification_payments)
returns jsonb language sql immutable set search_path = pg_catalog as $$
  select pg_catalog.jsonb_build_object('id', v.id, 'user_id', v.user_id, 'tier', v.tier, 'amount_cents', v.amount_cents,
    'currency', v.currency, 'donation_cents', v.donation_cents, 'donation_plan', v.donation_plan, 'provider', v.provider,
    'provider_ref', v.provider_ref, 'reference_code', v.reference_code, 'status', v.status,
    'created_at', v.created_at, 'updated_at', v.updated_at, 'expires_at', v.expires_at)
$$;


-- Member: open a new verification payment for themselves (always pending).
create or replace function public.rout_vp_open(p_provider text, p_amount int, p_donation int, p_plan text, p_reference text)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member(); r public.verification_payments;
begin
  if p_provider not in ('stripe', 'sepa', 'bunq') or p_amount not between 0 and 100000
     or coalesce(p_donation, 0) not between 0 and 100000 or p_plan not in ('none', 'one_time', 'monthly', 'yearly')
     or p_reference !~ '^ROUT-[0-9]{4}$' then
    raise exception 'invalid payment' using errcode = '22023';
  end if;
  insert into public.verification_payments (user_id, tier, amount_cents, donation_cents, donation_plan, provider, reference_code, status)
  values (v, 'early_believer', p_amount, coalesce(p_donation, 0), p_plan, p_provider, p_reference, 'pending')
  returning * into r;
  return public.rout_vp_json(r);
end $$;

-- Member: store the provider reference of their own open payment.
create or replace function public.rout_vp_attach_ref(p_id uuid, p_provider_ref text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member();
begin
  update public.verification_payments set provider_ref = p_provider_ref, updated_at = pg_catalog.now()
   where id = p_id and user_id = v and status in ('pending', 'incomplete')
     and (p_provider_ref ~ '^pi_[A-Za-z0-9_]+$' or p_provider_ref ~ '^bunqme:[0-9]+:[0-9]+$');
  return found;
end $$;

-- Member: new price on their own reused, still-open Stripe intent.
create or replace function public.rout_vp_reprice(p_id uuid, p_amount int, p_donation int, p_plan text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member();
begin
  if p_amount not between 0 and 100000 or coalesce(p_donation, 0) not between 0 and 100000
     or p_plan not in ('none', 'one_time', 'monthly', 'yearly') then
    raise exception 'invalid payment' using errcode = '22023';
  end if;
  update public.verification_payments
     set amount_cents = p_amount, donation_cents = coalesce(p_donation, 0), donation_plan = p_plan, updated_at = pg_catalog.now()
   where id = p_id and user_id = v and provider = 'stripe' and status in ('pending', 'incomplete');
  return found;
end $$;

-- Member: quietly close their own abandoned Stripe attempts (never processing/paid).
create or replace function public.rout_vp_expire_own_open_stripe()
returns int language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member(); n int;
begin
  update public.verification_payments set status = 'expired', updated_at = pg_catalog.now()
   where user_id = v and provider = 'stripe' and status in ('pending', 'incomplete');
  get diagnostics n = row_count;
  return n;
end $$;

-- Member: their own checkout could not start.
create or replace function public.rout_vp_fail_own(p_id uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v uuid := public.rout_require_member();
begin
  update public.verification_payments set status = 'failed', updated_at = pg_catalog.now()
   where id = p_id and user_id = v and status = 'pending';
  return found;
end $$;

-- Service (signed webhooks, cron, server flows): one payment by id.
create or replace function public.rout_vp_get(p_id uuid)
returns jsonb language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_vp_json(v) from public.verification_payments v where v.id = p_id
$$;

-- Service: newest payment for one bank reference code or one provider reference.
create or replace function public.rout_vp_find(p_reference text, p_provider_ref text)
returns jsonb language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_vp_json(v) from public.verification_payments v
   where (p_reference is not null and v.reference_code = p_reference)
      or (p_provider_ref is not null and v.provider_ref = p_provider_ref)
   order by v.created_at desc limit 1
$$;

-- Service: the one atomic "paid" transition. True only for the call that flipped the row,
-- so duplicate webhooks never activate, invoice or mail twice.
create or replace function public.rout_vp_claim_paid(p_id uuid, p_provider_ref text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  update public.verification_payments set status = 'paid', provider_ref = p_provider_ref, updated_at = pg_catalog.now()
   where id = p_id and status not in ('paid', 'refunded');
  return found;
end $$;

-- Service: non-final outcomes. Never sets "paid"; a paid row only moves to "refunded".
create or replace function public.rout_vp_mark(p_id uuid, p_status text, p_provider_ref text)
returns text language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_status text;
begin
  if p_status not in ('processing', 'failed', 'expired', 'refunded', 'incomplete', 'pending', 'cancelled') then
    raise exception 'invalid payment status' using errcode = '22023';
  end if;
  select status into v_status from public.verification_payments where id = p_id for update;
  if not found then return 'not_found'; end if;
  if v_status = 'paid' and p_status <> 'refunded' then return 'paid'; end if;
  update public.verification_payments set status = p_status, provider_ref = coalesce(p_provider_ref, provider_ref),
         updated_at = pg_catalog.now()
   where id = p_id;
  return 'updated';
end $$;

-- Service: a recurring donation stopped (the verification itself stays).
create or replace function public.rout_vp_end_donation(p_id uuid)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog as $$
begin
  update public.verification_payments set donation_plan = 'none', donation_cents = 0, updated_at = pg_catalog.now()
   where id = p_id;
  return found;
end $$;

-- Service: SEPA level 2 — open transfers whose expected total equals the received amount.
create or replace function public.rout_vp_sepa_candidates(p_amount int)
returns setof jsonb language sql stable security definer set search_path = pg_catalog as $$
  select public.rout_vp_json(v) from (
    select * from public.verification_payments
     where provider = 'sepa' and status <> 'paid' order by created_at desc limit 50) v
   where v.amount_cents + coalesce(v.donation_cents, 0) = p_amount
$$;

-- Service: invoice numbering (count of paid payments up to a moment), never the rows.
create or replace function public.rout_vp_paid_sequence(p_at timestamptz)
returns int language sql stable security definer set search_path = pg_catalog as $$
  select pg_catalog.count(*)::int from public.verification_payments where status = 'paid' and created_at <= p_at
$$;

-- Cron: one transfer-window round (7-day window, then expired).
create or replace function public.rout_vp_transfer_scan()
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog as $$
declare v_open int; v_expired int;
begin
  update public.verification_payments set expires_at = created_at + interval '7 days'
   where expires_at is null and status in ('pending', 'awaiting_transfer');
  update public.verification_payments set last_scanned_at = pg_catalog.now()
   where status in ('pending', 'awaiting_transfer');
  get diagnostics v_open = row_count;
  update public.verification_payments set status = 'expired', updated_at = pg_catalog.now()
   where status in ('pending', 'awaiting_transfer') and expires_at is not null and expires_at < pg_catalog.now();
  get diagnostics v_expired = row_count;
  return pg_catalog.jsonb_build_object('scanned', v_open, 'expired', v_expired);
end $$;

-- ------------------------------------------------------------------ strict policies
-- Added next to "rout_server"; they become the only table access once 0231 drops it.
drop policy if exists vp_owner_read on public.verification_payments;
create policy vp_owner_read on public.verification_payments for select to rout_app
  using (user_id = public.rout_current_user_id());
drop policy if exists vp_admin_read on public.verification_payments;
create policy vp_admin_read on public.verification_payments for select to rout_app
  using (public.rout_caller_is_admin());
drop policy if exists vp_admin_update on public.verification_payments;
create policy vp_admin_update on public.verification_payments for update to rout_app
  using (public.rout_caller_is_admin()) with check (public.rout_caller_is_admin());

drop policy if exists psp_owner_read on public.psp_credentials;
create policy psp_owner_read on public.psp_credentials for select to rout_app
  using (user_id = public.rout_current_user_id());
drop policy if exists psp_purge on public.psp_credentials;
create policy psp_purge on public.psp_credentials for delete to rout_app
  using (public.rout_purge_due(user_id));
drop policy if exists psp_purge_read on public.psp_credentials;
create policy psp_purge_read on public.psp_credentials for select to rout_app
  using (public.rout_purge_due(user_id));

-- ------------------------------------------------------------------ execute rights
-- Only the app role may call these functions; the two internal helpers are
-- reachable solely from inside the functions above.
do $$
declare f regprocedure;
begin
  for f in
    select p.oid::regprocedure from pg_catalog.pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and p.proname = any (array[
         'rout_caller_is_admin', 'rout_require_member', 'rout_require_admin',
         'rout_pricing_get', 'rout_pricing_set',
         'rout_promo_lookup', 'rout_promo_redeem', 'rout_promo_event', 'rout_promo_admin_save',
         'rout_promo_admin_list', 'rout_promo_admin_terms',
         'rout_gift_card_create', 'rout_gift_card_activate', 'rout_gift_card_mark_delivered',
         'rout_gift_card_public', 'rout_gift_card_mine', 'rout_gift_card_recipient',
         'rout_gift_shipments', 'rout_gift_shipment_update',
         'rout_psp_save', 'rout_psp_delete', 'rout_psp_public_owner', 'rout_psp_public_providers',
         'rout_psp_tip_credential',
         'rout_vp_json', 'rout_vp_open', 'rout_vp_attach_ref', 'rout_vp_reprice',
         'rout_vp_expire_own_open_stripe', 'rout_vp_fail_own', 'rout_vp_get', 'rout_vp_find',
         'rout_vp_claim_paid', 'rout_vp_mark', 'rout_vp_end_donation', 'rout_vp_sepa_candidates',
         'rout_vp_paid_sequence', 'rout_vp_transfer_scan'])
  loop
    execute pg_catalog.format('revoke all on function %s from public', f);
    if f::text not like 'rout_vp_json(%' and f::text not like 'rout_psp_public_owner(%' then
      execute pg_catalog.format('grant execute on function %s to rout_app', f);
    end if;
  end loop;
end $$;
