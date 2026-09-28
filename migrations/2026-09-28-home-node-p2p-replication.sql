-- Permit a Home Node replica to initiate a direct-only WebRTC session to a
-- writer. Exactly one authenticated initiator owns every rendezvous row.
ALTER TABLE endpt.home_p2p_sessions
    ADD COLUMN IF NOT EXISTS initiator_node_id uuid
    REFERENCES endpt.home_storage_nodes(id) ON DELETE CASCADE;

ALTER TABLE endpt.home_p2p_sessions
    ALTER COLUMN endpoint_id DROP NOT NULL;

ALTER TABLE endpt.home_p2p_sessions
    DROP CONSTRAINT IF EXISTS home_p2p_sessions_single_initiator_check;
ALTER TABLE endpt.home_p2p_sessions
    ADD CONSTRAINT home_p2p_sessions_single_initiator_check
    CHECK ((endpoint_id IS NOT NULL) <> (initiator_node_id IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_home_p2p_initiator_node
    ON endpt.home_p2p_sessions(initiator_node_id, created_at DESC)
    WHERE initiator_node_id IS NOT NULL;

NOTIFY pgrst, 'reload schema';
