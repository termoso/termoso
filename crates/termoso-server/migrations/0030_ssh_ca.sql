-- Team SSH certificate authority: the server signs short-lived user
-- certificates for members' device keys; hosts trust one `TrustedUserCAKeys`.
CREATE TABLE team_ssh_cas (
    team_id             uuid PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
    key_type            text NOT NULL,
    public_key          text NOT NULL,
    -- OpenSSH private key PEM, AEAD-sealed with the server master key
    -- (purpose `team_ssh_ca:<team_id>`).
    private_key_enc     bytea NOT NULL,
    principals          text[] NOT NULL DEFAULT '{}',
    ttl_hours           integer NOT NULL DEFAULT 8,
    extensions          text[] NOT NULL DEFAULT '{permit-pty,permit-port-forwarding,permit-user-rc}',
    enabled             boolean NOT NULL DEFAULT true,
    -- Previous key after a rotation, trusted by hosts until `retired_until`.
    retired_public_key  text,
    retired_until       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    rotated_at          timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE team_ssh_certs (
    id               uuid PRIMARY KEY,
    team_id          uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id        uuid REFERENCES devices(id) ON DELETE SET NULL,
    serial           bigint NOT NULL,
    key_type         text NOT NULL,
    key_fingerprint  text NOT NULL,
    key_id           text NOT NULL,
    principals       text[] NOT NULL,
    valid_after      timestamptz NOT NULL,
    valid_before     timestamptz NOT NULL,
    revoked_at       timestamptz,
    revoked_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (team_id, serial)
);
CREATE INDEX team_ssh_certs_team_idx ON team_ssh_certs (team_id, created_at DESC);
CREATE INDEX team_ssh_certs_device_idx ON team_ssh_certs (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX team_ssh_certs_live_idx ON team_ssh_certs (team_id, valid_before) WHERE revoked_at IS NULL;

-- Per-team serial counter (certificate serials must be unique per CA).
CREATE SEQUENCE team_ssh_cert_serial_seq;
