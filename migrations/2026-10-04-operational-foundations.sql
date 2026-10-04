-- Requires the existing mail/password-recovery migration. No device jobs.
ALTER TABLE endpt.mail_events ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0;
ALTER TABLE endpt.mail_events ADD COLUMN IF NOT EXISTS available_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE endpt.mail_events ADD COLUMN IF NOT EXISTS dead_lettered_at timestamptz;
ALTER TABLE endpt.mail_events ADD COLUMN IF NOT EXISTS result_code text;
CREATE INDEX IF NOT EXISTS mail_events_retry_due ON endpt.mail_events(available_at, created_at)
    WHERE NOT processed AND dead_lettered_at IS NULL;

CREATE OR REPLACE FUNCTION endpt.claim_mail_event(p_claim uuid)
RETURNS SETOF endpt.mail_events LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
BEGIN
    -- A worker killed during its sixth attempt must not leave a poison event
    -- eligible for unbounded reclamation. Preserve it for operator review.
    UPDATE endpt.mail_events SET dead_lettered_at=now(),result_code='retry_exhausted',
        claim_token=NULL,lease_until=NULL
    WHERE NOT processed AND attempts>=6 AND dead_lettered_at IS NULL
        AND (lease_until IS NULL OR lease_until<now());
    RETURN QUERY UPDATE endpt.mail_events
        SET claim_token=p_claim,lease_until=now()+interval '5 minutes',attempts=attempts+1
    WHERE id=(SELECT id FROM endpt.mail_events
        WHERE NOT processed AND dead_lettered_at IS NULL AND attempts<6
        AND available_at<=now() AND expires_at>now()
        AND (lease_until IS NULL OR lease_until<now())
        ORDER BY available_at,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
    RETURNING *;
END $$;
REVOKE ALL ON FUNCTION endpt.claim_mail_event(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_mail_event(uuid) TO service_role;

CREATE OR REPLACE FUNCTION endpt.claim_mail_message(p_claim uuid)
RETURNS SETOF endpt.mail_outbox LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
BEGIN
    UPDATE endpt.mail_outbox SET status='skipped',payload_encrypted=NULL,result_code='expired',
        claim_token=NULL,lease_until=NULL
    WHERE status IN ('pending','sending') AND expires_at<=now()
        AND (lease_until IS NULL OR lease_until<now());
    UPDATE endpt.mail_outbox SET status='failed',payload_encrypted=NULL,result_code='retry_exhausted',
        claim_token=NULL,lease_until=NULL
    WHERE status IN ('pending','sending') AND attempts>=6
        AND (lease_until IS NULL OR lease_until<now());
    RETURN QUERY UPDATE endpt.mail_outbox SET status='sending',claim_token=p_claim,
        lease_until=now()+interval '5 minutes',attempts=attempts+1
    WHERE id=(SELECT id FROM endpt.mail_outbox
        WHERE status IN ('pending','sending') AND attempts<6 AND available_at<=now()
        AND expires_at>now() AND (lease_until IS NULL OR lease_until<now())
        ORDER BY available_at,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED)
    RETURNING *;
END $$;
REVOKE ALL ON FUNCTION endpt.claim_mail_message(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_mail_message(uuid) TO service_role;
