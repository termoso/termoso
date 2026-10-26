-- SAML Single Logout: remember which IdP session a Termoso session came from,
-- so a LogoutRequest from the IdP can find and revoke it.
ALTER TABLE sessions
    ADD COLUMN sso_provider text,
    ADD COLUMN sso_subject text,
    ADD COLUMN sso_session_index text;
CREATE INDEX sessions_sso_idx ON sessions (sso_provider, sso_subject)
    WHERE sso_provider IS NOT NULL AND revoked_at IS NULL;
