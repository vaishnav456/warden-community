-- Privileged requests must identify their administrative requester so the
-- requester can never satisfy an approval step on their own request.
ALTER TABLE endpt.escalation_requests
    ADD COLUMN IF NOT EXISTS requested_by UUID
        REFERENCES endpt.admin_users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_escalation_requests_requester
    ON endpt.escalation_requests(requested_by, status);

CREATE OR REPLACE FUNCTION endpt.approve_escalation_request(
    p_request_id UUID,
    p_admin_id UUID,
    p_expected_status TEXT,
    p_is_secondary BOOLEAN,
    p_token_hash TEXT,
    p_token_expires_at TIMESTAMPTZ
) RETURNS SETOF endpt.escalation_requests
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, pg_temp
AS $$
DECLARE
    current_request endpt.escalation_requests%ROWTYPE;
BEGIN
    SELECT * INTO current_request
      FROM endpt.escalation_requests
     WHERE id = p_request_id
     FOR UPDATE;

    IF NOT FOUND OR current_request.status <> p_expected_status THEN
        RETURN;
    END IF;
    IF current_request.requested_by IS NOT NULL
       AND current_request.requested_by = p_admin_id THEN
        RAISE EXCEPTION 'requester cannot approve own escalation'
            USING ERRCODE = '42501';
    END IF;
    IF p_is_secondary AND current_request.reviewed_by = p_admin_id THEN
        RAISE EXCEPTION 'same administrator cannot provide both approvals'
            USING ERRCODE = '42501';
    END IF;

    IF p_is_secondary THEN
        UPDATE endpt.escalation_requests
           SET secondary_reviewed_by = p_admin_id,
               secondary_reviewed_at = now(),
               status = 'approved',
               escalation_token = p_token_hash,
               token_expires_at = p_token_expires_at
         WHERE id = p_request_id
         RETURNING * INTO current_request;
    ELSE
        UPDATE endpt.escalation_requests
           SET reviewed_by = p_admin_id,
               reviewed_at = now(),
               status = CASE WHEN requires_dual_approval
                             THEN 'pending_secondary' ELSE 'approved' END,
               escalation_token = p_token_hash,
               token_expires_at = p_token_expires_at
         WHERE id = p_request_id
         RETURNING * INTO current_request;
    END IF;

    RETURN NEXT current_request;
END;
$$;

REVOKE ALL ON FUNCTION endpt.approve_escalation_request(UUID, UUID, TEXT, BOOLEAN, TEXT, TIMESTAMPTZ) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.approve_escalation_request(UUID, UUID, TEXT, BOOLEAN, TEXT, TIMESTAMPTZ) TO service_role;
