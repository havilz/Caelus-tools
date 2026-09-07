-- Migration: 000017_fix_security_findings_deduplication.down.sql
-- Rollback to partial index

DROP INDEX IF EXISTS idx_security_findings_unique_fingerprint;

CREATE UNIQUE INDEX IF NOT EXISTS idx_security_findings_fingerprint
ON security_findings(organization_id, server_id, fingerprint) WHERE status != 'resolved';
