-- Short-lived WebRTC rendezvous metadata for Warden Home direct-only P2P.
-- SDP contains connection candidates but never file content or storage keys.
ALTER TABLE endpt.home_storage_nodes
    DROP CONSTRAINT IF EXISTS home_storage_nodes_deployment_mode_check;
ALTER TABLE endpt.home_storage_nodes
    ADD CONSTRAINT home_storage_nodes_deployment_mode_check
    CHECK (deployment_mode IN ('local','public','hybrid','p2p'));
ALTER TABLE endpt.home_storage_nodes
    DROP CONSTRAINT IF EXISTS home_storage_nodes_url_required_check;
ALTER TABLE endpt.home_storage_nodes
    ADD CONSTRAINT home_storage_nodes_url_required_check
    CHECK (deployment_mode = 'p2p' OR local_url IS NOT NULL OR public_url IS NOT NULL);

CREATE TABLE IF NOT EXISTS endpt.home_p2p_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    node_id uuid NOT NULL REFERENCES endpt.home_storage_nodes(id) ON DELETE CASCADE,
    offer_sdp text NOT NULL CHECK (length(offer_sdp) BETWEEN 32 AND 131072),
    answer_sdp text CHECK (answer_sdp IS NULL OR length(answer_sdp) BETWEEN 32 AND 131072),
    status text NOT NULL DEFAULT 'offered' CHECK (status IN ('offered','answered','expired','failed')),
    error_message text,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '2 minutes'),
    created_at timestamptz NOT NULL DEFAULT now(),
    answered_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_home_p2p_node_pending
    ON endpt.home_p2p_sessions(node_id, created_at)
    WHERE status = 'offered';
CREATE INDEX IF NOT EXISTS idx_home_p2p_endpoint
    ON endpt.home_p2p_sessions(endpoint_id, created_at DESC);

GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.home_p2p_sessions TO service_role;
NOTIFY pgrst, 'reload schema';
