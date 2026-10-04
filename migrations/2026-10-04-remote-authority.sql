-- Existing remote bearers are invalidated: reconnect after this migration.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'endpt' AND table_name = 'remote_sessions'
           AND column_name = 'owner_access_token_version'
    ) THEN
        ALTER TABLE endpt.remote_sessions
            ADD COLUMN owner_access_token_version INTEGER NOT NULL DEFAULT 0;
        UPDATE endpt.remote_sessions
           SET status = 'closed', ended_at = now(), vnc_token = NULL
         WHERE status = 'active';
    END IF;
END;
$$;
