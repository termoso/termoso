-- Tamper-evident audit log.
--
-- Every team_audit_events row carries hash = sha256(canonical fields || prev_hash)
-- where prev_hash is the hash of the team's previous event; the trigger below
-- serialises inserts per team so the chain never forks. Retention anchors the
-- newest deleted row in audit_checkpoints before removing it, and periodic
-- signed checkpoints (server Ed25519 key) let an auditor prove the head of the
-- chain existed at a point in time. GET /teams/{id}/audit/verify walks the chain.

ALTER TABLE team_audit_events
    ADD COLUMN prev_hash bytea,
    ADD COLUMN hash bytea;

CREATE OR REPLACE FUNCTION audit_event_hash(
    prev bytea, id bigint, team_id uuid, actor_id uuid, device_id uuid,
    action text, vault_id uuid, target_user uuid, details jsonb, created_at timestamptz
) RETURNS bytea
LANGUAGE sql IMMUTABLE AS $$
    SELECT sha256(convert_to(
        'termoso-audit-v1' || '|' || id::text || '|' || team_id::text
        || '|' || coalesce(actor_id::text, '') || '|' || coalesce(device_id::text, '')
        || '|' || action || '|' || coalesce(vault_id::text, '') || '|' || coalesce(target_user::text, '')
        || '|' || details::text
        || '|' || to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        || '|' || coalesce(encode(prev, 'hex'), ''),
        'UTF8'))
$$;

CREATE OR REPLACE FUNCTION audit_event_chain() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('audit:' || NEW.team_id::text));
    SELECT e.hash INTO NEW.prev_hash FROM team_audit_events e
     WHERE e.team_id = NEW.team_id ORDER BY e.id DESC LIMIT 1;
    NEW.hash := audit_event_hash(NEW.prev_hash, NEW.id, NEW.team_id, NEW.actor_id, NEW.device_id,
                                 NEW.action, NEW.vault_id, NEW.target_user, NEW.details, NEW.created_at);
    RETURN NEW;
END
$$;

CREATE TRIGGER team_audit_events_chain
    BEFORE INSERT ON team_audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_event_chain();

-- Anchors (kind = 'retention', unsigned: the hash of the newest row retention
-- removed) and signed checkpoints (kind = 'checkpoint', signature = OpenSSH
-- sshsig PEM over `termoso-audit-checkpoint-v1|team|last_id|hex hash`, namespace
-- `termoso-audit`, verifiable with `ssh-keygen -Y verify`).
CREATE TABLE audit_checkpoints (
    id          bigserial PRIMARY KEY,
    team_id     uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('retention', 'checkpoint')),
    last_id     bigint NOT NULL,
    hash        bytea NOT NULL,
    signature   text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_checkpoints_team_idx ON audit_checkpoints (team_id, id DESC);

-- Server-wide sealed keys (purpose → sealed OpenSSH private key).
CREATE TABLE server_keys (
    purpose         text PRIMARY KEY,
    public_key      text NOT NULL,
    private_key_enc bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
