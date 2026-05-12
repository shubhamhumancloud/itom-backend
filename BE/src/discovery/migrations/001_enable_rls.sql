-- Row-Level Security for every disc_* table.
--
-- This is the second lock on tenant isolation: even if a developer forgets
-- to add `WHERE tenantId=?` in a TypeORM query, Postgres itself will
-- refuse to return rows from another tenant.
--
-- ------------------------------------------------------------
-- Activation: NOT auto-applied by TypeORM `synchronize: true`.
-- ------------------------------------------------------------
-- Why: enabling RLS without also wiring middleware that sets
-- `app.tenant_id` on every connection check-out would make every query
-- return zero rows (the policy below filters out rows whose tenant_id
-- doesn't match the GUC, and an unset GUC fails the comparison).
--
-- To activate:
--   1. Run this file manually:  psql -d itom -f 001_enable_rls.sql
--   2. Land the per-request middleware that runs:
--        SET LOCAL app.tenant_id = '<tenant uuid>';
--      inside a transaction or with a request-scoped QueryRunner.
--   3. Smoke test:
--        SET app.tenant_id = '<tenantA-uuid>';
--        SELECT count(*) FROM disc_observation;   -- only tenantA rows
--        RESET app.tenant_id;
--        SELECT count(*) FROM disc_observation;   -- 0 rows
--
-- Until step 2 is done, leave this file unapplied. The current
-- service-layer tenant filtering is the only lock.

-- Helper: produce a tenant policy with one statement so we don't repeat
-- ourselves across tables. Postgres has no CREATE POLICY shortcut so a
-- DO block is the readable way.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'disc_scan_job',
    'disc_discovery_session',
    'disc_observation',
    'disc_credential',
    'disc_audit_log',
    'disc_collector'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'DROP POLICY IF EXISTS %I ON %I',
      t || '_tenant_isolation', t
    );
    -- `current_setting('app.tenant_id', true)` returns NULL if unset, which
    -- makes the comparison NULL (not TRUE), so no rows leak when the
    -- middleware forgets to SET. Fail-closed.
    EXECUTE format(
      'CREATE POLICY %I ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)::uuid)',
      t || '_tenant_isolation', t
    );
  END LOOP;
END $$;
