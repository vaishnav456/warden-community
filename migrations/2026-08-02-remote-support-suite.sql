ALTER TABLE endpt.remote_sessions
    ADD COLUMN IF NOT EXISTS consent_status text NOT NULL DEFAULT 'not_required'
        CHECK (consent_status IN ('not_required','pending','approved','denied','expired')),
    ADD COLUMN IF NOT EXISTS recording_status text NOT NULL DEFAULT 'none'
        CHECK (recording_status IN ('none','recording','completed','failed')),
    ADD COLUMN IF NOT EXISTS reconnect_until timestamptz;

CREATE TABLE IF NOT EXISTS endpt.remote_session_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id uuid NOT NULL REFERENCES endpt.remote_sessions(id) ON DELETE CASCADE,
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    admin_id uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    event_type text NOT NULL CHECK (event_type IN
        ('note','chat_admin','chat_endpoint','consent','recording','system')),
    body text NOT NULL CHECK (length(body) BETWEEN 1 AND 4000),
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remote_session_events_session
    ON endpt.remote_session_events(session_id, created_at);

CREATE TABLE IF NOT EXISTS endpt.remote_support_links (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    max_uses integer NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 20),
    use_count integer NOT NULL DEFAULT 0,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remote_support_links_endpoint
    ON endpt.remote_support_links(endpoint_id, created_at DESC);

GRANT ALL PRIVILEGES ON endpt.remote_session_events, endpt.remote_support_links TO service_role;

