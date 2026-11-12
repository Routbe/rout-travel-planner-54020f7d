# Roadmap

- [x] Import GitHub repo 1:1 and verify pages
- [x] Owner Neon connection (agent only) + DATABASE_URL (rout_app)
- [x] Step 1: rout.be health reports schema 0241
- [x] Checksums of 0238–0241 match schema_migrations (older drift reported: 0209, 91)
- [x] Step 2a: db/schema.snapshot.json regenerated from replay (0241)
- [x] Step 2b: full test suite (448 files) green; flaky ledger plaintext check fixed
- [x] Runtime secrets for sign-in copied from Vercel
- [x] Step 4: ROUT ID provider no longer depends on a self discovery fetch
- [ ] Live grant drift: rout_app has broader table grants live than migrations intend (11 tables + 2 views; RLS contains them) — tidy-up migration needs owner review (waiting on user)
- [x] Step 3: 2-of-3 recovery ceremony (passkey + paper + ROUT) in the existing crypto worker, settings wizard, db/0242 applied live
- [x] Purge 3-of-5 vault from code and live database (db/0243 applied live, 0 setups existed)
- [ ] Copy ROUT_RECOVERY_FACTOR_SECRET to Vercel and deploy, so rout.be runs the new recovery (waiting on user)
- [x] Sign-in by recovery at /recovery (2 of 3, worker signs a one-time challenge, pieces wiped)
- [ ] Apply db/0244 to the live database (waiting on user approval; the wizard's save needs it)
- [ ] Try the wizard with a real passkey in the preview (needs the user's own sign-in and passkey)
