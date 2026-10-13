-- 000016_add_server_id_to_firewall_rules.down.sql

DROP INDEX IF EXISTS idx_firewall_rules_server_id;

ALTER TABLE firewall_rules
    DROP COLUMN IF EXISTS server_id;
