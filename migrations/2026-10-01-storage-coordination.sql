-- Community: install/delete coordination only, no paid plans or storage caps.
CREATE TABLE IF NOT EXISTS endpt.tenant_storage_leases (
 company_id uuid PRIMARY KEY REFERENCES endpt.companies(id) ON DELETE CASCADE,
 token uuid NOT NULL,expires_at timestamptz NOT NULL
);
REVOKE ALL ON endpt.tenant_storage_leases FROM PUBLIC,service_role;
CREATE OR REPLACE FUNCTION endpt.claim_tenant_storage(p_company_id uuid,p_token uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE claimed uuid;
BEGIN
 INSERT INTO endpt.tenant_storage_leases VALUES(p_company_id,p_token,now()+interval '15 minutes')
 ON CONFLICT(company_id) DO UPDATE SET token=EXCLUDED.token,expires_at=EXCLUDED.expires_at
 WHERE tenant_storage_leases.expires_at<now() RETURNING token INTO claimed;
 RETURN claimed IS NOT NULL;
END; $$;
CREATE OR REPLACE FUNCTION endpt.release_tenant_storage(p_company_id uuid,p_token uuid)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
 DELETE FROM endpt.tenant_storage_leases WHERE company_id=p_company_id AND token=p_token;
$$;
REVOKE ALL ON FUNCTION endpt.claim_tenant_storage(uuid,uuid),endpt.release_tenant_storage(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_tenant_storage(uuid,uuid),endpt.release_tenant_storage(uuid,uuid) TO service_role;
ALTER TABLE endpt.app_library ADD COLUMN IF NOT EXISTS deletion_requested_at timestamptz;
NOTIFY pgrst,'reload schema';
