CREATE ROLE service_role;
CREATE ROLE operational_anon;
CREATE SCHEMA endpt;
CREATE TABLE endpt.mail_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours',
    processed boolean NOT NULL DEFAULT false,
    claim_token uuid, lease_until timestamptz
);
GRANT USAGE ON SCHEMA endpt TO service_role, operational_anon;
GRANT SELECT, UPDATE ON endpt.mail_events TO service_role;
CREATE TABLE endpt.mail_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours',
    available_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending',
    payload_encrypted text, result_code text,
    claim_token uuid, lease_until timestamptz
);
GRANT SELECT, UPDATE ON endpt.mail_outbox TO service_role;
