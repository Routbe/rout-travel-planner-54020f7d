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
- [ ] Step 3: 2-of-3 recovery ceremony — factor choice, storage and worker placement (waiting on user decisions)
