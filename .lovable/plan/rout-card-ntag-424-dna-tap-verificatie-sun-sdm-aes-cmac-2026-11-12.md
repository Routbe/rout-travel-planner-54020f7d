# ROUT Card: NTAG 424 DNA tap-verificatie (SUN/SDM, AES-CMAC)

## Uitgangspunt (wat er al is)
- `crypto-enclave/sdm-verifier.ts`: AES-128-CBC ontsleuteling van PICCData (K_SDMMetaRead), SV2-sessiesleutel en afgekapte AES-CMAC (oneven bytes) met K_SDMFileRead, getest tegen de officiële NXP-testvector (AN12196).
- `vault_enclave.sdm_cards` + `register_sdm_card`, `retrieve_sdm_for_recovery`, `confirm_sdm_recovery` (db/0224): per-kaart sleutels als `sdm_`-envelop (RVE1, server-sleutel gewikkeld onder `ROUT_VAULT_KEK`), teller strikt oplopend en atomair bijgewerkt, pogingen gebonden aan `SHA256(picc||cmac)`, 60 s geldig, lockout na 3 fouten.
- Ontbreekt: een tap-URL en -pagina, een algemeen tap-doel (nu alleen herstel), sleutelafleiding per kaart, een personalisatieflow, en `/v/$cardId` controleert niets cryptografisch.

## Doel
Elke tap op een ROUT Card levert een eenmalig, servergecontroleerd bewijs van fysiek bezit op. `rout_app` krijgt geen tabelrechten; alles loopt via smalle SECURITY DEFINER-functies in `vault_enclave`.

## Tap-flow

```text
Kaart (NDEF, SDM aan)
  https://rout.be/t?p=<PICCData 32 hex>&m=<CMAC 16 hex>
        |
        v
/t (publieke pagina) -> server function verifyCardTap
  1. vorm + rate limit (IP en kaart), fail-closed
  2. PICCData ontsleutelen met K_SDMMetaRead (vloot-/batchsleutel)
       -> UID (7 B) + SDMReadCtr (3 B)
  3. vault_enclave.begin_sdm_tap(uid_hash, picc, cmac)
       -> attempt_id, sdm_ref, envelop, last_counter
  4. envelop openen in de vault-adapter, K_SDMFileRead afleiden
       SV2 -> KSesSDMFileReadMAC -> CMAC vergelijken (constant-time)
  5. vault_enclave.confirm_sdm_tap(attempt_id, picc, cmac, ok, ctr)
       -> teller > last_counter atomair, anders weigering
       -> tap_-ref (eenmalig, 60 s) gebonden aan kaart + eigenaar
  6. sleutelbytes en sessiesleutels wissen in finally
        |
        v
Doel verbruikt de tap_-ref: publiek "echte kaart"-bewijs, step-up of herstel
```

## Waarom deze URL-indeling
- Geen vast kaart-ID in de URL: PICCData verandert bij elke tap, dus een tap is niet koppelbaar zonder de MetaRead-sleutel. Het kaart-ID volgt uit `HMAC(uid)` na ontsleuteling.
- MAC over lege invoer (SDMMACInputOffset = SDMMACOffset): dit sluit aan op de bestaande verifier en vereist geen SV1 of versleuteld bestandsdeel.
- De teller is de replay-bescherming. Daarom weigert de database elke teller die niet hoger is, ook als de MAC klopt.

## Sleutelbeheer
- Per batch: een batch-master (AN10922 diversificatie) en een K_SDMMetaRead, beide als `sdm_`-envelop in `vault_enclave`, nooit als omgevingsvariabele.
- Per kaart: K_SDMFileRead = AN10922(batch-master, UID || batch-id). Er wordt niets per kaart opgeslagen behalve uid_hash, de teller, de status en de eigenaar.
- AppMasterKey (sleutel 0) wordt in de fabriek gewijzigd en afgeleid van een aparte batch-master. Die is alleen nodig voor herconfiguratie en verlaat het personalisatiestation nooit.
- `IVaultPort` krijgt `verifySdmTap`. De Postgres-adapter opent de envelop server-side zoals nu. Een latere externe enclave of HSM kan de CMAC uitvoeren zonder dat sleutels de app bereiken.

## Database (EXPAND, dan CONTRACT)
- EXPAND `0245_sdm_tap.sql`:
  - `vault_enclave.sdm_batches` (batch_id, meta_ref, master_ref, status)
  - `sdm_cards` uitbreiden met batch_id en uid_hash (uniek)
  - `begin_sdm_tap`, `confirm_sdm_tap`, `consume_card_tap(tap_ref, purpose)` en een audit-rij per tap in de bestaande hash-keten
  - alleen EXECUTE voor `rout_app`; PUBLIC ingetrokken; de aanroeper komt uit de transactiecontext
- De herstelfuncties uit 0224 gaan intern over op dezelfde kern. Hun signatuur blijft gelijk.
- CONTRACT (in `db-pending/`) verwijdert de oude herstelspecifieke paden pas wanneer productie het EXPAND-niveau meldt.

## Doelen van een tap (`purpose`)
1. `public_proof`: de `/v/<kaart>`-pagina toont "echte, actieve kaart, net getapt". Geen persoonsgegevens.
2. `step_up`: nieuwe step-up-methode `card_tap` voor bestaande acties zoals `card_lifecycle` en `card_reveal`.
3. `recovery`: bestaand pad, nu via de gedeelde kern. Het hoort niet bij de huidige 2-van-3 ceremonie, tenzij je dat later expliciet kiest.

## Personalisatie (admin)
- Admin-scherm "Kaartbatch": batch aanmaken (sleutels in de vault gegenereerd), een configuratiebestand voor het personalisatiestation exporteren (NDEF-sjabloon, SDM-offsets, sleutelnummers) en een manifest importeren (UID-hash per kaart, ondertekend).
- Activeren bij het lid gaat via de bestaande koppelflow (activatiecode). De eerste geldige tap legt de startteller vast.

## Tests
- NXP-vectoren AN12196: SV2, MAC, oneven bytes; AN10922-diversificatievector.
- PGlite als `rout_app`: replay (gelijke en lagere teller), verlopen poging, verkeerde binding, ingetrokken kaart, lockout, en geen tabeltoegang.
- Route: foute vorm, rate limit, een uniforme weigering die niets lekt.
- Een echte tap met een testkaart als laatste stap (handmatig).

## Open beslissingen
- Vloot-brede K_SDMMetaRead per batch (onkoppelbaar, voorgesteld) of een vast kaart-ID in de URL (eenvoudiger, maar wel volgbaar).
- Welke doelen eerst: publiek bewijs, step-up of beide.
- Wie personaliseert: een eigen station (configuratiebestand van ROUT) of de kaartleverancier (manifest-import).

## Technische details
- Bestanden: `src/routes/t.tsx`, `src/lib/wallet/card-tap.functions.ts`, `src/lib/vault/sdm-tap.server.ts`, `src/lib/crypto-enclave/sdm-verifier.ts` (AN10922 toevoegen), `vault-port.server.ts` (`verifySdmTap`), admin-batchscherm, `db/0245_sdm_tap.sql`, en `schema-version.ts` op 0245.
- Byte-vergelijking constant-time, `@noble/ciphers` blijft de enige AES/CMAC-bron, en geen logging van PICCData, CMAC of UID (alleen hashes).
- Antwoorden zijn `no-store`. De tap-pagina wist de query uit de adresbalk (`history.replaceState`), zodat een gedeelde link niets herbruikbaars bevat.
