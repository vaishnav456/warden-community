-- BitLocker recovery metadata. The numerical recovery password is always
-- application-layer AES-256-GCM ciphertext under the tenant DEK.
CREATE TABLE IF NOT EXISTS endpt.endpoint_recovery_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    volume_mount text NOT NULL,
    protector_id text NOT NULL,
    recovery_password_encrypted text NOT NULL,
    volume_status text,
    protection_status text,
    encryption_percentage numeric(5,2),
    is_current boolean NOT NULL DEFAULT true,
    escrowed_at timestamptz NOT NULL DEFAULT now(),
    last_reported_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(endpoint_id, volume_mount, protector_id)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_recovery_keys_current
    ON endpt.endpoint_recovery_keys(company_id, endpoint_id, is_current, escrowed_at DESC);

CREATE OR REPLACE FUNCTION endpt.upsert_endpoint_recovery_key(
    p_company_id uuid, p_endpoint_id uuid, p_volume_mount text,
    p_protector_id text, p_recovery_password_encrypted text,
    p_volume_status text, p_protection_status text, p_encryption_percentage numeric
)
RETURNS SETOF endpt.endpoint_recovery_keys
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
DECLARE v_row endpt.endpoint_recovery_keys;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM endpt.endpoints
        WHERE id = p_endpoint_id AND company_id = p_company_id AND is_active = true
    ) THEN
        RAISE EXCEPTION 'endpoint does not belong to active company';
    END IF;
    -- Serialize escrow/rotation for this endpoint volume. Demotion and upsert
    -- then commit together, so a failed write never loses the previous key.
    PERFORM pg_advisory_xact_lock(hashtextextended(p_endpoint_id::text || ':' || p_volume_mount, 0));
    UPDATE endpt.endpoint_recovery_keys
       SET is_current = false
     WHERE endpoint_id = p_endpoint_id AND volume_mount = p_volume_mount
       AND protector_id <> p_protector_id AND is_current = true;
    INSERT INTO endpt.endpoint_recovery_keys (
        company_id, endpoint_id, volume_mount, protector_id,
        recovery_password_encrypted, volume_status, protection_status,
        encryption_percentage, is_current, last_reported_at
    ) VALUES (
        p_company_id, p_endpoint_id, p_volume_mount, p_protector_id,
        p_recovery_password_encrypted, p_volume_status, p_protection_status,
        p_encryption_percentage, true, now()
    )
    ON CONFLICT (endpoint_id, volume_mount, protector_id) DO UPDATE SET
        recovery_password_encrypted = EXCLUDED.recovery_password_encrypted,
        volume_status = EXCLUDED.volume_status,
        protection_status = EXCLUDED.protection_status,
        encryption_percentage = EXCLUDED.encryption_percentage,
        is_current = true,
        last_reported_at = now()
    RETURNING * INTO v_row;
    RETURN NEXT v_row;
END;
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.endpoint_recovery_keys TO service_role;
REVOKE ALL ON FUNCTION endpt.upsert_endpoint_recovery_key(uuid,uuid,text,text,text,text,text,numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.upsert_endpoint_recovery_key(uuid,uuid,text,text,text,text,text,numeric) TO service_role;
NOTIFY pgrst, 'reload schema';
