-- Run AFTER the mail migration, in an isolated transaction; never commit fixtures.
DO $$
DECLARE cid uuid:=gen_random_uuid(); aid uuid:=gen_random_uuid(); bid uuid:=gen_random_uuid();
        token text:=repeat('a',64); version integer; result uuid; claim uuid:=gen_random_uuid(); mid uuid:=gen_random_uuid();
BEGIN
 INSERT INTO endpt.companies(id,slug,name,vpn_subnet) VALUES(cid,'mail-test-'||cid,'Mail transaction fixture','10.255.254.0/24');
 INSERT INTO endpt.mail_settings(scope_key,config_encrypted) VALUES('platform','fixture ciphertext');
 INSERT INTO endpt.branches(id,company_id,name) VALUES(bid,cid,'Fixture branch');
 INSERT INTO endpt.admin_users(id,email,password_hash,full_name,role,company_id,mfa_enabled)
 VALUES(aid,'mail-'||aid||'@example.invalid','$2b$12$oldfixture','Mail fixture','company_admin',cid,true);
 SELECT coalesce(access_token_version,0) INTO version FROM endpt.admin_users WHERE id=aid;
 IF NOT EXISTS(SELECT 1 FROM endpt.mail_events WHERE admin_id=aid AND kind='account_created') THEN
   RAISE EXCEPTION 'welcome event missing'; END IF;
 IF endpt.request_admin_password_reset(aid,token,repeat('b',64),version) THEN
   RAISE EXCEPTION 'wrong email hash accepted'; END IF;
 IF NOT endpt.request_admin_password_reset(aid,token,encode(public.digest('mail-'||aid||'@example.invalid','sha256'),'hex'),version) THEN
   RAISE EXCEPTION 'reset request rejected'; END IF;
 INSERT INTO endpt.refresh_tokens(admin_id,token_hash,expires_at,absolute_expires_at)
 VALUES(aid,'fixture-'||aid,now()+interval '1 day',now()+interval '1 day');
 result:=endpt.complete_admin_password_reset(token,'$2b$12$newfixture');
 IF result IS DISTINCT FROM aid THEN RAISE EXCEPTION 'reset failed'; END IF;
 IF endpt.complete_admin_password_reset(token,'$2b$12$anotherfixture') IS NOT NULL THEN
   RAISE EXCEPTION 'reset token reuse allowed'; END IF;
 IF endpt.request_admin_password_reset(aid,repeat('b',64),encode(public.digest('mail-'||aid||'@example.invalid','sha256'),'hex'),version+1) THEN
   RAISE EXCEPTION 'account reset cooldown ignored'; END IF;
 IF NOT EXISTS(SELECT 1 FROM endpt.admin_users WHERE id=aid AND access_token_version=version+1 AND mfa_enabled) THEN
   RAISE EXCEPTION 'session generation or MFA changed incorrectly'; END IF;
 IF EXISTS(SELECT 1 FROM endpt.refresh_tokens WHERE admin_id=aid AND NOT revoked) THEN
   RAISE EXCEPTION 'session not revoked'; END IF;
 UPDATE endpt.admin_password_reset_tokens SET created_at=now()-interval '2 minutes' WHERE admin_id=aid;
 IF NOT endpt.request_admin_password_reset(aid,repeat('b',64),encode(public.digest('mail-'||aid||'@example.invalid','sha256'),'hex'),version+1) THEN
   RAISE EXCEPTION 'new reset after cooldown rejected'; END IF;
 UPDATE endpt.admin_password_reset_tokens SET expires_at=now()-interval '1 minute',created_at=now()-interval '2 minutes' WHERE admin_id=aid;
 IF endpt.complete_admin_password_reset(repeat('b',64),'$2b$12$fixture') IS NOT NULL THEN
   RAISE EXCEPTION 'expired token accepted'; END IF;
 PERFORM endpt.request_admin_password_reset(aid,repeat('c',64),encode(public.digest('mail-'||aid||'@example.invalid','sha256'),'hex'),version+1);
 UPDATE endpt.admin_users SET email='changed-'||aid||'@example.invalid' WHERE id=aid;
 IF endpt.complete_admin_password_reset(repeat('c',64),'$2b$12$fixture') IS NOT NULL THEN
   RAISE EXCEPTION 'token for old email accepted'; END IF;
 INSERT INTO endpt.alerts(company_id,branch_id,type,severity,title) VALUES(cid,bid,'fixture','critical','Fixture');
 IF NOT EXISTS(SELECT 1 FROM endpt.mail_events WHERE company_id=cid AND category='alerts_critical') THEN
   RAISE EXCEPTION 'default critical notification missing'; END IF;
 UPDATE endpt.admin_users SET notification_prefs='{"email_categories":{"alerts_critical":false}}' WHERE id=aid;
 DELETE FROM endpt.mail_events WHERE company_id=cid AND category='alerts_critical';
 INSERT INTO endpt.alerts(company_id,branch_id,type,severity,title) VALUES(cid,bid,'fixture','critical','Fixture opt-out');
 IF EXISTS(SELECT 1 FROM endpt.mail_events WHERE company_id=cid AND category='alerts_critical') THEN
   RAISE EXCEPTION 'explicit opt-out ignored'; END IF;
 INSERT INTO endpt.mail_outbox(id,event_key,company_id,admin_id,category,payload_encrypted)
 VALUES(mid,mid::text,cid,aid,'security','fixture ciphertext');
 IF NOT EXISTS(SELECT 1 FROM endpt.claim_mail_message(claim) WHERE id=mid AND attempts=1 AND status='sending') THEN
   RAISE EXCEPTION 'message claim failed'; END IF;
 IF EXISTS(SELECT 1 FROM endpt.claim_mail_message(gen_random_uuid())) THEN
   RAISE EXCEPTION 'leased message claimed twice'; END IF;
 UPDATE endpt.mail_outbox SET lease_until=now()-interval '1 minute',expires_at=now()-interval '1 minute' WHERE id=mid;
 PERFORM endpt.claim_mail_message(gen_random_uuid());
 IF NOT EXISTS(SELECT 1 FROM endpt.mail_outbox WHERE id=mid AND status='skipped' AND payload_encrypted IS NULL) THEN
   RAISE EXCEPTION 'expired body not cleared'; END IF;
 RAISE NOTICE 'Mail recovery, session, preference and lease assertions passed';
END $$;
