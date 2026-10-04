INSERT INTO endpt.mail_events(id,attempts,available_at,lease_until) VALUES
('11111111-1111-1111-1111-111111111111',5,now()-interval '1 hour',NULL),
('22222222-2222-2222-2222-222222222222',6,now()-interval '2 hours',now()-interval '1 second'),
('33333333-3333-3333-3333-333333333333',6,now()-interval '3 hours',now()+interval '1 hour'),
('44444444-4444-4444-4444-444444444444',0,now()+interval '1 hour',NULL),
('55555555-5555-5555-5555-555555555555',0,now(),NULL);
SET ROLE service_role;
DO $$
DECLARE claimed endpt.mail_events;
BEGIN
    SELECT * INTO claimed FROM endpt.claim_mail_event('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    IF claimed.id IS DISTINCT FROM '11111111-1111-1111-1111-111111111111'::uuid
        OR claimed.attempts<>6 OR claimed.lease_until<=now() THEN
        RAISE EXCEPTION 'Claim did not atomically increment attempt/lease';
    END IF;
    SELECT * INTO claimed FROM endpt.claim_mail_event('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
    IF claimed.id IS DISTINCT FROM '55555555-5555-5555-5555-555555555555'::uuid THEN
        RAISE EXCEPTION 'Poison/delayed/leased events blocked unrelated work';
    END IF;
    IF EXISTS(SELECT FROM endpt.mail_events WHERE id='22222222-2222-2222-2222-222222222222'
              AND dead_lettered_at IS NULL) THEN
        RAISE EXCEPTION 'Exhausted abandoned event not dead-lettered';
    END IF;
    IF EXISTS(SELECT FROM endpt.mail_events WHERE id='33333333-3333-3333-3333-333333333333'
              AND dead_lettered_at IS NOT NULL) THEN
        RAISE EXCEPTION 'Active final-attempt worker was invalidated';
    END IF;
END $$;
RESET ROLE;
UPDATE endpt.mail_events SET lease_until=now()-interval '1 second'
    WHERE id='11111111-1111-1111-1111-111111111111';
SET ROLE service_role;
DO $$
BEGIN
    PERFORM endpt.claim_mail_event('cccccccc-cccc-cccc-cccc-cccccccccccc');
    IF EXISTS(SELECT FROM endpt.mail_events WHERE id='11111111-1111-1111-1111-111111111111'
              AND dead_lettered_at IS NULL) THEN
        RAISE EXCEPTION 'Killed sixth attempt became eligible indefinitely';
    END IF;
END $$;
RESET ROLE;
DO $$
BEGIN
    IF has_function_privilege('operational_anon','endpt.claim_mail_event(uuid)','EXECUTE') THEN
        RAISE EXCEPTION 'Anonymous claim privilege';
    END IF;
END $$;
SELECT 'Retry bound, abandoned lease recovery, isolation from poison work and privileges passed' AS result;

INSERT INTO endpt.mail_outbox(id,attempts,status,payload_encrypted,lease_until) VALUES
('11111111-1111-1111-1111-111111111111',6,'sending','encrypted',now()-interval '1 second'),
('22222222-2222-2222-2222-222222222222',5,'pending','encrypted',NULL);
SET ROLE service_role;
DO $$
DECLARE claimed endpt.mail_outbox;
BEGIN
    SELECT * INTO claimed FROM endpt.claim_mail_message('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    IF claimed.id IS DISTINCT FROM '22222222-2222-2222-2222-222222222222'::uuid OR claimed.attempts<>6 THEN
        RAISE EXCEPTION 'Outbox retry bound failed';
    END IF;
    IF EXISTS(SELECT FROM endpt.mail_outbox WHERE id='11111111-1111-1111-1111-111111111111'
              AND (status<>'failed' OR payload_encrypted IS NOT NULL)) THEN
        RAISE EXCEPTION 'Abandoned terminal delivery was not redacted and failed';
    END IF;
END $$;
RESET ROLE;
SELECT 'Outbox crash retry bound and terminal payload redaction passed' AS result;
