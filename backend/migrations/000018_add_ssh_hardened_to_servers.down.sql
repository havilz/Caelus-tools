-- Migration: 000018_add_ssh_hardened_to_servers.down.sql

ALTER TABLE servers DROP COLUMN IF EXISTS ssh_hardened;
