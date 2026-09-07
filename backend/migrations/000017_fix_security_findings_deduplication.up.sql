-- Migration: 000017_fix_security_findings_deduplication.up.sql
-- Subsystem: Sentinel Security Hub Finding Lifecycle & Deduplication

DELETE FROM security_findings a USING security_findings b
WHERE a.id < b.id
  AND a.organization_id = b.organization_id
  AND a.server_id IS NOT DISTINCT FROM b.server_id
  AND a.fingerprint = b.fingerprint;

DROP INDEX IF EXISTS idx_security_findings_fingerprint;

CREATE UNIQUE INDEX IF NOT EXISTS idx_security_findings_unique_fingerprint
ON security_findings(organization_id, server_id, fingerprint) NULLS NOT DISTINCT;
