# Roadmap

- [x] Import GitHub repo 1:1 and verify pages
- [x] Owner Neon connection (agent only) + DATABASE_URL (rout_app)
- [x] Step 1: rout.be health reports schema 0241
- [ ] Verify recorded checksums of 0238–0241 in schema_migrations
- [ ] Step 2a: regenerate db/schema.snapshot.json (replay) and check against live
- [ ] Step 2b: run full test suite, fix failures
- [ ] Runtime secrets for sign-in (BETTER_AUTH_SECRET, PUBLIC_ORIGIN, vault/KEK keys matching production)
- [ ] Step 4: Better Auth "oidc" provider skipped warning without OIDC_* vars
- [ ] Step 3: recovery ceremony — use real master key from crypto enclave, setup wizard UI, recovery flow
