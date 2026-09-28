ALTER TABLE endpt.policy_deployments
    ADD COLUMN IF NOT EXISTS target_selector jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS rollout_percentage integer NOT NULL DEFAULT 100
        CHECK (rollout_percentage BETWEEN 1 AND 100),
    ADD COLUMN IF NOT EXISTS policy_version integer NOT NULL DEFAULT 1;

CREATE OR REPLACE FUNCTION endpt.create_targeted_policy_deployment(
    p_company_id uuid,
    p_branch_id uuid,
    p_template_id uuid,
    p_template_name text,
    p_encrypted_payload text,
    p_created_by uuid,
    p_endpoint_ids jsonb,
    p_target_selector jsonb DEFAULT '{}'::jsonb,
    p_rollout_percentage integer DEFAULT 100,
    p_reason text DEFAULT NULL,
    p_idempotency_key text DEFAULT NULL
) RETURNS TABLE(deployment_id uuid, targeted integer, queued integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE
    v_deployment_id uuid;
    v_endpoint record;
    v_job_id uuid;
    v_requested integer;
    v_targeted integer := 0;
    v_queued integer := 0;
BEGIN
    IF jsonb_typeof(p_endpoint_ids) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'endpoint ids must be an array';
    END IF;
    IF p_rollout_percentage NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'rollout percentage must be between 1 and 100';
    END IF;
    SELECT count(*) INTO v_requested FROM jsonb_array_elements_text(p_endpoint_ids);
    IF v_requested < 1 OR v_requested > 5000 THEN
        RAISE EXCEPTION 'target count must be between 1 and 5000';
    END IF;

    IF p_idempotency_key IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(p_company_id::text || ':' || p_idempotency_key, 0));
        SELECT id, targeted_count INTO v_deployment_id, v_targeted
          FROM endpt.policy_deployments
         WHERE company_id=p_company_id AND idempotency_key=p_idempotency_key;
        IF FOUND THEN
            SELECT count(*) INTO v_queued FROM endpt.policy_deployment_targets
             WHERE deployment_id=v_deployment_id;
            RETURN QUERY SELECT v_deployment_id,v_targeted,v_queued;
            RETURN;
        END IF;
    END IF;

    SELECT count(*) INTO v_targeted
      FROM endpt.endpoints e
      JOIN (SELECT DISTINCT value::uuid id FROM jsonb_array_elements_text(p_endpoint_ids)) requested
        ON requested.id=e.id
     WHERE e.company_id=p_company_id AND e.branch_id=p_branch_id AND e.is_active=true;
    IF v_targeted <> v_requested THEN
        RAISE EXCEPTION 'one or more targets are invalid or outside the requested scope';
    END IF;

    INSERT INTO endpt.policy_deployments(
        company_id,branch_id,template_id,template_name,reason,targeted_count,
        created_by,idempotency_key,target_selector,rollout_percentage,policy_version
    ) VALUES (
        p_company_id,p_branch_id,p_template_id,p_template_name,p_reason,v_targeted,
        p_created_by,p_idempotency_key,COALESCE(p_target_selector,'{}'::jsonb),
        p_rollout_percentage,1
    ) RETURNING id INTO v_deployment_id;

    FOR v_endpoint IN
        SELECT e.id,e.branch_id FROM endpt.endpoints e
        JOIN (SELECT DISTINCT value::uuid id FROM jsonb_array_elements_text(p_endpoint_ids)) requested
          ON requested.id=e.id
        ORDER BY e.hostname,e.id
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(p_company_id,v_endpoint.branch_id,v_endpoint.id,'PUSH_LOCAL_POLICY',
               p_encrypted_payload,'pending',p_created_by)
        RETURNING id INTO v_job_id;
        INSERT INTO endpt.policy_deployment_targets(deployment_id,endpoint_id,job_id)
        VALUES(v_deployment_id,v_endpoint.id,v_job_id);
        v_queued := v_queued+1;
    END LOOP;
    RETURN QUERY SELECT v_deployment_id,v_targeted,v_queued;
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_targeted_policy_deployment(uuid,uuid,uuid,text,text,uuid,jsonb,jsonb,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_targeted_policy_deployment(uuid,uuid,uuid,text,text,uuid,jsonb,jsonb,integer,text,text) TO service_role;
