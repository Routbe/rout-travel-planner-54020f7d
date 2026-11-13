# Roadmap

## ROUT Card tap (NTAG 424 DNA) — Batch 1
- [ ] db/0245_sdm_tap.sql (EXPAND): fleet MetaRead key, batches, cards by uid_hash, tap attempts, tap grants, RPCs for rout_app only
- [ ] sdm-verifier.ts: AN10922 diversification, PICCData decrypt, uid index, constant-time compares + NXP vectors
- [ ] sdm-tap.server.ts + vault port methods; PGlite tests as rout_app
- [ ] /t public tap page (PICCData only, no card id), "Authentic ROUT Card" badge, replaceState clears query
- [ ] schema level 0245, snapshot + db types
## ROUT Card tap — later batches
- [ ] step_up purpose (card_tap method for card_reveal / card_lifecycle)
- [ ] Admin batch screen: create, one-time station config export, manifest import; member activation

## Workspace Studio
- [ ] New profile photo does not save in Workspace Studio (e.g. maximilien-6yak, private account switched to workspace)
- [ ] "ROUT OS v2.5 Alle systemen operationeel" overlaps bottom preview buttons on phone; check similar overlaps
