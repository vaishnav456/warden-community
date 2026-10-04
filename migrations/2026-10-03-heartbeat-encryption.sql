BEGIN;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS heartbeat_encrypted text;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS heartbeat_encryption_required boolean NOT NULL DEFAULT false;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS heartbeat_device_proof_required boolean NOT NULL DEFAULT false;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS previous_client_cert_fingerprint text;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS previous_client_cert_expires_at timestamptz;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS agent_integrity_encrypted text;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS agent_integrity_baseline_encrypted text;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS agent_integrity jsonb NOT NULL DEFAULT '{}';
ALTER TABLE endpt.endpoint_metrics ADD COLUMN IF NOT EXISTS metrics_encrypted text;
CREATE TABLE IF NOT EXISTS endpt.heartbeat_nonces (
 endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
 nonce text NOT NULL CHECK (nonce ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(endpoint_id,nonce)
);
CREATE INDEX IF NOT EXISTS heartbeat_nonces_age ON endpt.heartbeat_nonces(created_at);
ALTER TABLE endpt.heartbeat_nonces ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON endpt.heartbeat_nonces FROM PUBLIC;
DO $$ DECLARE role_name text; BEGIN
 FOR role_name IN SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated') LOOP
  EXECUTE format('REVOKE ALL ON endpt.heartbeat_nonces FROM %I',role_name);
 END LOOP;
END $$;
GRANT ALL ON endpt.heartbeat_nonces TO service_role;
CREATE OR REPLACE FUNCTION endpt.claim_heartbeat_nonce(p_endpoint uuid,p_nonce text)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,endpt AS $$
DECLARE inserted integer;
BEGIN
 IF p_nonce IS NULL OR p_nonce !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
 -- Retain longer than the 5-minute message acceptance window, across restarts.
 DELETE FROM endpt.heartbeat_nonces WHERE (endpoint_id,nonce) IN (
  SELECT endpoint_id,nonce FROM endpt.heartbeat_nonces
  WHERE created_at < now()-interval '15 minutes' ORDER BY created_at LIMIT 100);
 INSERT INTO endpt.heartbeat_nonces(endpoint_id,nonce) VALUES(p_endpoint,p_nonce)
 ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS inserted=ROW_COUNT;
 RETURN inserted=1;
END $$;
REVOKE ALL ON FUNCTION endpt.claim_heartbeat_nonce(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_heartbeat_nonce(uuid,text) TO service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
