\set ON_ERROR_STOP on
BEGIN;
DO $$ DECLARE ep endpt.endpoints; ad endpt.admin_users; t uuid:=gen_random_uuid(); m uuid:=gen_random_uuid(); r jsonb; total integer;
BEGIN
 SELECT * INTO ep FROM endpt.endpoints LIMIT 1;
 SELECT * INTO ad FROM endpt.admin_users WHERE company_id=ep.company_id AND role='company_admin' AND is_active LIMIT 1;
 IF ep.id IS NULL OR ad.id IS NULL THEN RAISE EXCEPTION 'Development fixture unavailable'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'create',NULL,repeat('a',64),'encrypted fixture');
 IF r->>'id'<>t::text THEN RAISE EXCEPTION 'Creation failed: %',r; END IF;
 PERFORM endpt.support_ticket_action(ep.company_id,ep.id,t,'create',NULL,repeat('a',64),'retry fixture');
 SELECT count(*) INTO total FROM endpt.support_requests WHERE id=t;
 IF total<>1 THEN RAISE EXCEPTION 'Duplicate creation'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'reply',NULL,repeat('b',64),'cipher',m);
 IF r->>'error'<>'forbidden' THEN RAISE EXCEPTION 'Other user reply accepted'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'reply',NULL,repeat('a',64),'cipher',m);
 IF r ? 'error' THEN RAISE EXCEPTION 'Reply rejected: %',r; END IF;
 PERFORM endpt.support_ticket_action(ep.company_id,ep.id,t,'reply',NULL,repeat('a',64),'cipher',m);
 SELECT count(*) INTO total FROM endpt.support_messages WHERE id=m;
 IF total<>1 THEN RAISE EXCEPTION 'Duplicate reply'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'claim',ad.id);
 IF r->>'status'<>'claimed' THEN RAISE EXCEPTION 'Claim failed'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'claim',ad.id);
 IF r->>'error'<>'conflict' THEN RAISE EXCEPTION 'Double claim accepted'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'resolve',ad.id);
 IF r->>'status'<>'resolved' THEN RAISE EXCEPTION 'Resolve failed'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'reply',ad.id,NULL,'cipher',gen_random_uuid());
 IF r->>'error'<>'resolved' THEN RAISE EXCEPTION 'Resolved reply accepted'; END IF;
 r:=endpt.support_ticket_action(ep.company_id,ep.id,t,'reopen',NULL,repeat('a',64),'cipher');
 IF r->>'status'<>'open' THEN RAISE EXCEPTION 'User reopen failed'; END IF;
 IF has_function_privilege('public','endpt.support_ticket_action(uuid,uuid,uuid,text,uuid,text,text,uuid,timestamptz)','EXECUTE')
 THEN RAISE EXCEPTION 'RPC exposed to PUBLIC'; END IF;
END $$;
ROLLBACK;
