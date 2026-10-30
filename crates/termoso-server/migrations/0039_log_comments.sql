-- Threaded comments on session recordings: who said what, when, and
-- optionally at which point of the recording. Plain text like the shared
-- note; the recording itself stays client-encrypted.
CREATE TABLE session_log_comments (
    id          uuid PRIMARY KEY,
    log_id      uuid NOT NULL REFERENCES session_logs(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body        text NOT NULL,
    offset_ms   bigint,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_log_comments_log_idx ON session_log_comments (log_id, created_at);
