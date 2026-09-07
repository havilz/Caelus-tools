-- 000016_add_server_id_to_firewall_rules.up.sql

ALTER TABLE firewall_rules
    ADD COLUMN IF NOT EXISTS server_id UUID REFERENCES servers(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_firewall_rules_server_id ON firewall_rules(server_id);
