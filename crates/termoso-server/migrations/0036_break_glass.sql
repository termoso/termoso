-- Break-glass: an owner designates one member and a one-time secret kept
-- offline (safe, printed envelope). When the owner is unreachable the member
-- redeems the secret and becomes an admin of the team for a bounded time;
-- everyone is told, everything is audited, the role reverts automatically.
CREATE TABLE team_break_glass (
    team_id          uuid PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_hash      text NOT NULL,
    duration_hours   int NOT NULL,
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    attempts         int NOT NULL DEFAULT 0,
    locked_until     timestamptz,
    used_at          timestamptz,
    expires_at       timestamptz,
    ended_at         timestamptz,
    prev_role        text,
    prev_role_id     uuid,
    prev_role_source text
);
CREATE INDEX team_break_glass_active_idx ON team_break_glass (expires_at) WHERE used_at IS NOT NULL AND ended_at IS NULL;
