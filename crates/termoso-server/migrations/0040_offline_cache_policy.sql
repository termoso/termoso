-- Team policy for offline copies of files read from team hosts (SFTP cache):
--   offline_cache      'allow' | 'deny'     – deny hides the per-host setting and purges copies
ALTER TABLE team_policies
    ADD COLUMN offline_cache text NOT NULL DEFAULT 'allow';
