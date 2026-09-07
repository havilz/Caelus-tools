-- Migration: 000018_add_ssh_hardened_to_servers.up.sql
-- Subsystem: Server Telemetry Security Posture

ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_hardened BOOLEAN NOT NULL DEFAULT FALSE;
