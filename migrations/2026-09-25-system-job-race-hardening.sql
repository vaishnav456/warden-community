-- Serialize scheduled/automatic job creation per endpoint and operation.
-- This remains correct with multiple scheduler processes or overlapping
-- service restarts and leaves deliberate admin-created jobs unrestricted.
CREATE OR REPLACE FUNCTION endpt.create_system_job_once(
    p_company_id UUID, p_branch_id UUID, p_endpoint_id UUID,
    p_type TEXT, p_encrypted_payload TEXT
) RETURNS SETOF endpt.jobs
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_endpoint_id::text || ':' || p_type, 0));
    IF EXISTS (
        SELECT 1 FROM endpt.jobs
         WHERE endpoint_id=p_endpoint_id AND type=p_type
           AND status IN ('pending','approved','running')
    ) THEN
        RETURN;
    END IF;
    RETURN QUERY
    INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
    VALUES(p_company_id,p_branch_id,p_endpoint_id,p_type,p_encrypted_payload,'pending',NULL)
    RETURNING *;
END;
$$;
REVOKE ALL ON FUNCTION endpt.create_system_job_once(UUID,UUID,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_system_job_once(UUID,UUID,UUID,TEXT,TEXT) TO service_role;

NOTIFY pgrst, 'reload schema';
