-- Scheduled snippet runs. The server only knows opaque entity ids and the
-- schedule; devices holding the vault key (bridge, opted-in desktops) claim
-- due runs, execute the snippet on the hosts and report results.
CREATE TABLE team_automations (
    id             uuid PRIMARY KEY,
    team_id        uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    vault_id       uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    snippet_id     uuid NOT NULL,
    name           text NOT NULL,
    host_ids       uuid[] NOT NULL DEFAULT '{}',
    group_id       uuid,
    schedule       text NOT NULL,
    timezone       text NOT NULL DEFAULT 'UTC',
    enabled        boolean NOT NULL DEFAULT true,
    timeout_secs   integer NOT NULL DEFAULT 300,
    alert_on       text NOT NULL DEFAULT 'failure' CHECK (alert_on IN ('never', 'failure', 'always')),
    alert_emails   text[] NOT NULL DEFAULT '{}',
    alert_admins   boolean NOT NULL DEFAULT true,
    last_run_at    timestamptz,
    last_status    text,
    next_run_at    timestamptz,
    created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX team_automations_team_idx ON team_automations (team_id);
CREATE INDEX team_automations_due_idx ON team_automations (next_run_at) WHERE enabled;

CREATE TABLE team_automation_runs (
    id                 uuid PRIMARY KEY,
    automation_id      uuid NOT NULL REFERENCES team_automations(id) ON DELETE CASCADE,
    team_id            uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    status             text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'running', 'done', 'failed', 'missed', 'cancelled')),
    scheduled_for      timestamptz NOT NULL,
    manual             boolean NOT NULL DEFAULT false,
    claimed_by_device  uuid REFERENCES devices(id) ON DELETE SET NULL,
    claimed_at         timestamptz,
    finished_at        timestamptz,
    hosts_total        integer NOT NULL DEFAULT 0,
    hosts_failed       integer NOT NULL DEFAULT 0,
    results            jsonb NOT NULL DEFAULT '[]'::jsonb,
    error              text,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX team_automation_runs_automation_idx ON team_automation_runs (automation_id, created_at DESC);
CREATE INDEX team_automation_runs_open_idx ON team_automation_runs (team_id, status) WHERE status IN ('pending', 'running');
