-- Run only after tools/encrypt_endpoint_private_data.py completes.
-- Rebuild the audit hash chain over ciphertext, then remove the temporary
-- append-only audit migration bridge.
DO $$
DECLARE
    audit_row RECORD;
    previous_hash TEXT := NULL;
    calculated_hash TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('endpt.audit_log.hash_chain'));
    FOR audit_row IN
        SELECT id, company_id, branch_id, endpoint_id, actor_id, escalation_id,
               action, detail, detail_encrypted, created_at
          FROM endpt.audit_log ORDER BY created_at, id
    LOOP
        calculated_hash := encode(public.digest(convert_to(concat_ws('|',
            coalesce(previous_hash, ''), audit_row.id::text,
            coalesce(audit_row.company_id::text, ''),
            coalesce(audit_row.branch_id::text, ''),
            coalesce(audit_row.endpoint_id::text, ''),
            coalesce(audit_row.actor_id::text, ''),
            coalesce(audit_row.escalation_id::text, ''),
            audit_row.action,
            CASE WHEN audit_row.detail_encrypted IS NULL
                 THEN audit_row.detail::text ELSE audit_row.detail_encrypted END,
            audit_row.created_at::text
        ), 'UTF8'), 'sha256'), 'hex');
        UPDATE endpt.audit_log
           SET prev_hash = previous_hash, row_hash = calculated_hash
         WHERE id = audit_row.id;
        previous_hash := calculated_hash;
    END LOOP;
END;
$$;

DROP FUNCTION IF EXISTS endpt.migrate_audit_detail_encryption(UUID, UUID, TEXT);
NOTIFY pgrst, 'reload schema';
