/**
 * The newest database migration (db/) this code relies on. The public health
 * probe reports it, so anyone can see whether a deployment already runs the
 * code that matches a held-back CONTRACT migration in db-pending/.
 * Kept equal to the highest migration number by schema-version.test.ts.
 */
export const CODE_SCHEMA_LEVEL = "0241";
