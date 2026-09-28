BEGIN;

ALTER TABLE endpt.windows_users
    ADD COLUMN IF NOT EXISTS sid TEXT,
    ADD COLUMN IF NOT EXISTS principal_name TEXT,
    ADD COLUMN IF NOT EXISTS account_type TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS domain_name TEXT,
    ADD COLUMN IF NOT EXISTS present BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ NOT NULL DEFAULT now();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='windows_users_account_type_check'
          AND conrelid='endpt.windows_users'::regclass
    ) THEN
        ALTER TABLE endpt.windows_users
            ADD CONSTRAINT windows_users_account_type_check
            CHECK (account_type IN ('local','domain','entra','microsoft','unknown'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_windows_users_sid
    ON endpt.windows_users(sid) WHERE sid IS NOT NULL;

CREATE OR REPLACE FUNCTION endpt.replace_windows_users(p_endpoint_id UUID, p_users JSONB)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=endpt,public
AS $$
DECLARE v_count INTEGER;
BEGIN
    IF p_users IS NULL OR jsonb_typeof(p_users) IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_users) > 512 THEN
        RAISE EXCEPTION 'invalid user inventory';
    END IF;

    UPDATE endpt.windows_users SET present=FALSE
    WHERE endpoint_id=p_endpoint_id;

    INSERT INTO endpt.windows_users (
        endpoint_id, username, display_name, sid, principal_name,
        account_type, domain_name, is_admin, is_enabled, present, last_synced
    )
    SELECT
        p_endpoint_id,
        item->>'username',
        NULLIF(item->>'display_name', ''),
        NULLIF(item->>'sid', ''),
        NULLIF(item->>'principal_name', ''),
        CASE WHEN item->>'account_type' IN ('local','domain','entra','microsoft','unknown')
             THEN item->>'account_type' ELSE 'unknown' END,
        NULLIF(item->>'domain_name', ''),
        COALESCE((item->>'is_admin')::BOOLEAN, FALSE),
        COALESCE((item->>'is_enabled')::BOOLEAN, TRUE),
        TRUE,
        now()
    FROM jsonb_array_elements(p_users) item
    WHERE NULLIF(item->>'username', '') IS NOT NULL
    ON CONFLICT (endpoint_id, username) DO UPDATE SET
        display_name=EXCLUDED.display_name,
        sid=EXCLUDED.sid,
        principal_name=EXCLUDED.principal_name,
        account_type=EXCLUDED.account_type,
        domain_name=EXCLUDED.domain_name,
        is_admin=EXCLUDED.is_admin,
        is_enabled=EXCLUDED.is_enabled,
        present=TRUE,
        last_synced=now();

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION endpt.replace_windows_users(UUID, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.replace_windows_users(UUID, JSONB) TO service_role;

NOTIFY pgrst, 'reload schema';
COMMIT;
