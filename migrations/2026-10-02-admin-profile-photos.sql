BEGIN;
ALTER TABLE endpt.admin_users
    ADD COLUMN IF NOT EXISTS profile_photo TEXT,
    ADD COLUMN IF NOT EXISTS profile_photo_mime TEXT
        CHECK (profile_photo_mime IS NULL OR profile_photo_mime = 'image/png');
-- Logical database row storage includes all administrator, identity and
-- endpoint photo copies. Community still has no hosted plan/quota limits.
CREATE OR REPLACE FUNCTION endpt.tenant_database_bytes(p_company_id uuid)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE r record; amount bigint; total bigint:=0;
BEGIN
    FOR r IN SELECT c.relname,
        bool_or(a.attname='company_id') AS direct,
        bool_or(a.attname='endpoint_id') AS endpoint_owned
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
        WHERE n.nspname='endpt' AND c.relkind='r' AND c.relname<>'tenant_storage_leases'
        GROUP BY c.relname LOOP
        IF r.direct THEN
            EXECUTE format('SELECT coalesce(sum(pg_column_size(t)),0) FROM endpt.%I t WHERE company_id=$1',r.relname)
                INTO amount USING p_company_id;
        ELSIF r.endpoint_owned THEN
            EXECUTE format('SELECT coalesce(sum(pg_column_size(t)),0) FROM endpt.%I t JOIN endpt.endpoints e ON e.id=t.endpoint_id WHERE e.company_id=$1',r.relname)
                INTO amount USING p_company_id;
        ELSE CONTINUE;
        END IF;
        total:=total+amount;
    END LOOP;
    RETURN total;
END $$;
REVOKE ALL ON FUNCTION endpt.tenant_database_bytes(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.tenant_database_bytes(uuid) TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
