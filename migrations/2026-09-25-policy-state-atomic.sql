-- Atomic, queryable endpoint policy state.
-- The legacy endpoints.policy_state document remains synchronized so older
-- servers/UI builds continue to work during a rolling deployment.

CREATE TABLE IF NOT EXISTS endpt.endpoint_policy_settings (
    endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    setting_key text NOT NULL,
    desired_value jsonb,
    effective_value jsonb,
    source text NOT NULL DEFAULT 'discovered'
        CHECK (source IN ('warden','discovered','readonly','local','domain_gpo','mdm','unknown')),
    status text NOT NULL DEFAULT 'discovered'
        CHECK (status IN ('pending','applied','in_sync','drifted','error','conflict','not_applicable','discovered','readonly')),
    policy_version text,
    applied_at timestamptz,
    checked_at timestamptz,
    last_error text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (endpoint_id, setting_key)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_policy_settings_status
    ON endpt.endpoint_policy_settings(endpoint_id, status);

-- Preserve the desired/effective state accumulated before this normalized
-- table existed.  Without this backfill, the first post-upgrade drift scan
-- would incorrectly reclassify every previously managed setting as merely
-- discovered.
INSERT INTO endpt.endpoint_policy_settings(
    endpoint_id, setting_key, desired_value, effective_value, source, status,
    applied_at, checked_at, updated_at
)
SELECT e.id, item.key,
       CASE WHEN item.value ? 'value' THEN item.value->'value' ELSE NULL END,
       CASE WHEN item.value ? 'current_value' THEN item.value->'current_value'
            WHEN item.value ? 'value' THEN item.value->'value' ELSE NULL END,
       CASE WHEN COALESCE((item.value->>'readonly')::boolean, false) THEN 'readonly'
            WHEN item.value ? 'value' THEN 'warden' ELSE 'discovered' END,
       CASE WHEN COALESCE((item.value->>'readonly')::boolean, false) THEN 'readonly'
            WHEN COALESCE((item.value->>'drift')::boolean, false) THEN 'drifted'
            WHEN item.value ? 'value' THEN 'in_sync' ELSE 'discovered' END,
       NULLIF(item.value->>'applied_at','')::timestamptz,
       NULLIF(item.value->>'checked_at','')::timestamptz,
       now()
  FROM endpt.endpoints e
 CROSS JOIN LATERAL jsonb_each(COALESCE(e.policy_state, '{}'::jsonb)) item
 WHERE jsonb_typeof(item.value) = 'object'
ON CONFLICT (endpoint_id, setting_key) DO NOTHING;

CREATE OR REPLACE FUNCTION endpt.apply_endpoint_policy_settings(
    p_endpoint_id uuid,
    p_settings jsonb,
    p_policy_version text DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, public AS $$
DECLARE
    item record;
    stamp timestamptz := now();
    legacy_patch jsonb := '{}'::jsonb;
BEGIN
    IF jsonb_typeof(p_settings) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'p_settings must be an object';
    END IF;

    FOR item IN SELECT key, value FROM jsonb_each(p_settings)
    LOOP
        INSERT INTO endpt.endpoint_policy_settings(
            endpoint_id, setting_key, desired_value, effective_value, source,
            status, policy_version, applied_at, checked_at, updated_at
        ) VALUES (
            p_endpoint_id, item.key, item.value, item.value, 'warden',
            'applied', p_policy_version, stamp, stamp, stamp
        )
        ON CONFLICT (endpoint_id, setting_key) DO UPDATE SET
            desired_value = EXCLUDED.desired_value,
            effective_value = EXCLUDED.effective_value,
            source = 'warden', status = 'applied',
            policy_version = COALESCE(EXCLUDED.policy_version, endpt.endpoint_policy_settings.policy_version),
            applied_at = stamp, checked_at = stamp, last_error = NULL,
            updated_at = stamp;

        legacy_patch := legacy_patch || jsonb_build_object(
            item.key, jsonb_build_object('value', item.value, 'current_value', item.value,
                                         'applied_at', stamp, 'checked_at', stamp,
                                         'drift', false, 'source', 'warden')
        );
    END LOOP;

    UPDATE endpt.endpoints
       SET policy_state = COALESCE(policy_state, '{}'::jsonb) || legacy_patch
     WHERE id = p_endpoint_id;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.record_endpoint_policy_observations(
    p_endpoint_id uuid,
    p_values jsonb,
    p_readonly_keys text[] DEFAULT ARRAY[]::text[]
) RETURNS text[]
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, public AS $$
DECLARE
    item record;
    current_row endpt.endpoint_policy_settings%ROWTYPE;
    stamp timestamptz := now();
    new_status text;
    new_source text;
    legacy_entry jsonb;
    legacy_patch jsonb := '{}'::jsonb;
    drifted text[] := ARRAY[]::text[];
BEGIN
    IF jsonb_typeof(p_values) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'p_values must be an object';
    END IF;

    FOR item IN SELECT key, value FROM jsonb_each(p_values)
    LOOP
        SELECT * INTO current_row
          FROM endpt.endpoint_policy_settings
         WHERE endpoint_id = p_endpoint_id AND setting_key = item.key
         FOR UPDATE;

        IF item.key = ANY(p_readonly_keys) THEN
            new_status := 'readonly'; new_source := 'readonly';
        ELSIF current_row.desired_value IS NULL THEN
            new_status := 'discovered'; new_source := 'discovered';
        ELSIF current_row.desired_value IS DISTINCT FROM item.value THEN
            new_status := 'drifted'; new_source := COALESCE(current_row.source, 'unknown');
            drifted := array_append(drifted, item.key);
        ELSE
            new_status := 'in_sync'; new_source := COALESCE(current_row.source, 'warden');
        END IF;

        INSERT INTO endpt.endpoint_policy_settings(
            endpoint_id, setting_key, effective_value, source, status,
            checked_at, updated_at
        ) VALUES (
            p_endpoint_id, item.key, item.value, new_source, new_status,
            stamp, stamp
        )
        ON CONFLICT (endpoint_id, setting_key) DO UPDATE SET
            effective_value = EXCLUDED.effective_value,
            source = CASE WHEN endpt.endpoint_policy_settings.desired_value IS NULL
                          THEN EXCLUDED.source ELSE endpt.endpoint_policy_settings.source END,
            status = EXCLUDED.status, checked_at = stamp, updated_at = stamp;

        legacy_entry := jsonb_build_object(
            'current_value', item.value, 'checked_at', stamp,
            'configured', item.value <> 'null'::jsonb,
            'source', new_source
        );
        IF current_row.desired_value IS NOT NULL THEN
            legacy_entry := legacy_entry || jsonb_build_object(
                'value', current_row.desired_value,
                'applied_at', current_row.applied_at,
                'drift', new_status = 'drifted'
            );
        ELSE
            legacy_entry := legacy_entry || jsonb_build_object(
                'discovered', new_status = 'discovered',
                'readonly', new_status = 'readonly'
            );
        END IF;
        legacy_patch := legacy_patch || jsonb_build_object(item.key, legacy_entry);
    END LOOP;

    UPDATE endpt.endpoints
       SET policy_state = COALESCE(policy_state, '{}'::jsonb) || legacy_patch
     WHERE id = p_endpoint_id;
    RETURN drifted;
END;
$$;

REVOKE ALL ON FUNCTION endpt.apply_endpoint_policy_settings(uuid,jsonb,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION endpt.record_endpoint_policy_observations(uuid,jsonb,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.apply_endpoint_policy_settings(uuid,jsonb,text) TO service_role;
GRANT EXECUTE ON FUNCTION endpt.record_endpoint_policy_observations(uuid,jsonb,text[]) TO service_role;
GRANT SELECT ON endpt.endpoint_policy_settings TO service_role;
