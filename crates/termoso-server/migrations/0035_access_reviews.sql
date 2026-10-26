-- Periodic access reviews: a snapshot of who is in the team and who can open
-- which team vault, each line confirmed ("keep") or revoked ("remove") by an
-- admin; completing the review applies the removals. Opened by hand or by the
-- scheduler every `access_review_days` (0 = off).
ALTER TABLE team_policies
    ADD COLUMN access_review_days int NOT NULL DEFAULT 0;

CREATE TABLE team_access_reviews (
    id           uuid PRIMARY KEY,
    team_id      uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'completed', 'cancelled')),
    opened_by    uuid REFERENCES users(id) ON DELETE SET NULL,   -- NULL = scheduler
    opened_at    timestamptz NOT NULL DEFAULT now(),
    due_at       timestamptz NOT NULL,
    closed_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    closed_at    timestamptz,
    kept         int NOT NULL DEFAULT 0,
    removed      int NOT NULL DEFAULT 0
);
CREATE INDEX team_access_reviews_team_idx ON team_access_reviews (team_id, opened_at DESC);
CREATE UNIQUE INDEX team_access_reviews_open_idx ON team_access_reviews (team_id) WHERE status = 'open';

CREATE TABLE team_access_review_items (
    id           uuid PRIMARY KEY,
    review_id    uuid NOT NULL REFERENCES team_access_reviews(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('member', 'vault_access')),
    user_id      uuid NOT NULL,
    vault_id     uuid,
    role         text NOT NULL,
    last_seen_at timestamptz,
    decision     text CHECK (decision IN ('keep', 'remove')),
    decided_by   uuid,
    decided_at   timestamptz,
    note         text,
    UNIQUE (review_id, kind, user_id, vault_id)
);
CREATE INDEX team_access_review_items_review_idx ON team_access_review_items (review_id);
