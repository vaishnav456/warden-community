CREATE OR REPLACE FUNCTION endpt.claim_remote_support_link(p_token_hash text)
RETURNS SETOF endpt.remote_support_links
LANGUAGE sql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
    UPDATE endpt.remote_support_links
       SET use_count = use_count + 1
     WHERE token_hash = p_token_hash
       AND revoked_at IS NULL
       AND expires_at > now()
       AND use_count < max_uses
    RETURNING *;
$$;
REVOKE ALL ON FUNCTION endpt.claim_remote_support_link(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_remote_support_link(text) TO service_role;
