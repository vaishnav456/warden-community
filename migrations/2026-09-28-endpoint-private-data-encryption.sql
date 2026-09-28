-- Tenant-envelope encryption support for endpoint identifying data.
-- Existing plaintext is migrated by tools/encrypt_endpoint_private_data.py
-- after this additive migration and compatible server code are deployed.
ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS hardware_id_hash TEXT,
    ADD COLUMN IF NOT EXISTS installation_id_hash TEXT,
    ADD COLUMN IF NOT EXISTS topology_telemetry_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS capability_details_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS tags_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS asset_metadata_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS device_identity_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS private_data_encryption_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE endpt.alerts
    ADD COLUMN IF NOT EXISTS detail_encrypted TEXT;
ALTER TABLE endpt.audit_log
    ADD COLUMN IF NOT EXISTS detail_encrypted TEXT;
ALTER TABLE endpt.endpoint_events
    ADD COLUMN IF NOT EXISTS detail_encrypted TEXT;

CREATE INDEX IF NOT EXISTS idx_endpoints_installation_hash
    ON endpt.endpoints(company_id, installation_id_hash)
    WHERE installation_id_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_endpoints_hardware_hash
    ON endpt.endpoints(company_id, hardware_id_hash)
    WHERE hardware_id_hash IS NOT NULL;

-- Temporary, tenant-bound bridge for migrating append-only audit rows. This
-- function cannot change identities/actions/timestamps and is removed by the
-- finalize migration after the hash chain is rebuilt.
CREATE OR REPLACE FUNCTION endpt.migrate_audit_detail_encryption(
    p_audit_id UUID, p_company_id UUID, p_detail_encrypted TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, pg_temp AS $$
BEGIN
    UPDATE endpt.audit_log
       SET detail = '{}'::jsonb,
           detail_encrypted = p_detail_encrypted
     WHERE id = p_audit_id
       AND company_id = p_company_id
       AND detail_encrypted IS NULL
       AND p_detail_encrypted LIKE 'v2:%';
    RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION endpt.migrate_audit_detail_encryption(UUID, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.migrate_audit_detail_encryption(UUID, UUID, TEXT) TO service_role;

CREATE OR REPLACE FUNCTION endpt.set_audit_log_hash()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, pg_temp
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('endpt.audit_log.hash_chain'));
    SELECT row_hash INTO NEW.prev_hash
      FROM endpt.audit_log ORDER BY created_at DESC, id DESC LIMIT 1;
    NEW.row_hash := encode(public.digest(convert_to(concat_ws('|',
        coalesce(NEW.prev_hash, ''), NEW.id::text,
        coalesce(NEW.company_id::text, ''), coalesce(NEW.branch_id::text, ''),
        coalesce(NEW.endpoint_id::text, ''), coalesce(NEW.actor_id::text, ''),
        coalesce(NEW.escalation_id::text, ''), NEW.action,
        CASE WHEN NEW.detail_encrypted IS NULL
             THEN NEW.detail::text ELSE NEW.detail_encrypted END,
        NEW.created_at::text
    ), 'UTF8'), 'sha256'), 'hex');
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.verify_audit_chain()
RETURNS JSONB
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = endpt, pg_temp AS $$
WITH ordered AS (
    SELECT audit_log.*,
           lag(row_hash) OVER (ORDER BY created_at, id) AS expected_prev
      FROM endpt.audit_log
), checked AS (
    SELECT *,
        encode(public.digest(convert_to(concat_ws('|',
            coalesce(expected_prev, ''), id::text,
            coalesce(company_id::text, ''), coalesce(branch_id::text, ''),
            coalesce(endpoint_id::text, ''), coalesce(actor_id::text, ''),
            coalesce(escalation_id::text, ''), action,
            CASE WHEN detail_encrypted IS NULL
                 THEN detail::text ELSE detail_encrypted END,
            created_at::text
        ), 'UTF8'), 'sha256'), 'hex') AS expected_hash
      FROM ordered
)
SELECT jsonb_build_object(
    'rows', count(*),
    'broken', count(*) FILTER (
        WHERE prev_hash IS DISTINCT FROM expected_prev
           OR row_hash IS DISTINCT FROM expected_hash),
    'valid', count(*) FILTER (
        WHERE prev_hash IS DISTINCT FROM expected_prev
           OR row_hash IS DISTINCT FROM expected_hash) = 0,
    'verified_at', now()
) FROM checked;
$$;
REVOKE ALL ON FUNCTION endpt.verify_audit_chain() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.verify_audit_chain() TO service_role;

NOTIFY pgrst, 'reload schema';
