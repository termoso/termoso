-- Device posture: facts a client reports about itself at sign-in / refresh
-- (os_version, disk_encryption, screen_lock, secure_key_storage), and the team
-- policies that require them before a member of the team may sign in.
ALTER TABLE devices
    ADD COLUMN posture jsonb,
    ADD COLUMN posture_at timestamptz;

ALTER TABLE team_policies
    ADD COLUMN posture_disk_encryption boolean NOT NULL DEFAULT false,
    ADD COLUMN posture_screen_lock boolean NOT NULL DEFAULT false,
    ADD COLUMN posture_secure_key boolean NOT NULL DEFAULT false;
