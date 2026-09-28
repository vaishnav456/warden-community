ALTER TABLE endpt.build_requests ADD COLUMN IF NOT EXISTS claim_token UUID;
ALTER TABLE endpt.build_requests ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_build_requests_expired_claim
    ON endpt.build_requests(lease_expires_at) WHERE status = 'building';

CREATE OR REPLACE FUNCTION endpt.claim_next_build(p_lease_seconds INTEGER DEFAULT 900)
RETURNS SETOF endpt.build_requests AS $$
DECLARE v_id UUID;
BEGIN
    SELECT id INTO v_id FROM endpt.build_requests
    WHERE status = 'pending'
       OR (status = 'building' AND (lease_expires_at IS NULL OR lease_expires_at < now()))
    ORDER BY created_at ASC FOR UPDATE SKIP LOCKED LIMIT 1;
    IF v_id IS NULL THEN RETURN; END IF;
    RETURN QUERY UPDATE endpt.build_requests
       SET status='building', claim_token=gen_random_uuid(),
           lease_expires_at=now()+make_interval(secs => GREATEST(p_lease_seconds, 60)),
           updated_at=now()
     WHERE id=v_id RETURNING *;
END;
$$ LANGUAGE plpgsql;
CREATE OR REPLACE FUNCTION endpt.renew_build_claim(
    p_build_id UUID, p_claim_token UUID, p_lease_seconds INTEGER DEFAULT 900
) RETURNS BOOLEAN AS $$
DECLARE v_count INTEGER;
BEGIN
    UPDATE endpt.build_requests
       SET lease_expires_at=now()+make_interval(secs => GREATEST(p_lease_seconds, 60)), updated_at=now()
     WHERE id=p_build_id AND status='building' AND claim_token=p_claim_token;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END;
$$ LANGUAGE plpgsql;
