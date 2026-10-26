-- Team policies enforced by clients on hosts that live in team vaults:
--   auth               'any' | 'keys_only'  – forbid password / keyboard-interactive auth
--   jump_host_required                      – hosts must be reached through a jump host
--   export             'allow' | 'deny'     – no local export/backup of team vault data
--   forward_ports      allowlist of remote ports (n or a-b) for port forwarding; empty = any
ALTER TABLE team_policies
    ADD COLUMN auth text NOT NULL DEFAULT 'any',
    ADD COLUMN jump_host_required boolean NOT NULL DEFAULT false,
    ADD COLUMN export text NOT NULL DEFAULT 'allow',
    ADD COLUMN forward_ports text[] NOT NULL DEFAULT '{}';
