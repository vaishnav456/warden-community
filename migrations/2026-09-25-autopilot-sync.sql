-- Autopilot inventory identifies machines before Warden can know their SMBIOS
-- UUID, so pre-registration must also support serial and Entra device IDs.
ALTER TABLE endpt.enrollment_device_claims
    ALTER COLUMN hardware_id DROP NOT NULL;
ALTER TABLE endpt.enrollment_device_claims
    DROP CONSTRAINT IF EXISTS enrollment_device_claims_company_id_hardware_id_key;
ALTER TABLE endpt.enrollment_device_claims
    ADD COLUMN IF NOT EXISTS serial_number TEXT;
ALTER TABLE endpt.enrollment_device_claims
    ADD COLUMN IF NOT EXISTS entra_device_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_enrollment_claims_company_hardware
    ON endpt.enrollment_device_claims(company_id, lower(hardware_id))
    WHERE hardware_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrollment_claims_company_serial
    ON endpt.enrollment_device_claims(company_id, lower(serial_number))
    WHERE serial_number IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrollment_claims_company_provider
    ON endpt.enrollment_device_claims(company_id, provider_device_id)
    WHERE provider_device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_enrollment_claims_company_entra
    ON endpt.enrollment_device_claims(company_id, lower(entra_device_id))
    WHERE entra_device_id IS NOT NULL;

ALTER TABLE endpt.enrollment_device_claims
    DROP CONSTRAINT IF EXISTS enrollment_device_claims_has_identity;
ALTER TABLE endpt.enrollment_device_claims
    ADD CONSTRAINT enrollment_device_claims_has_identity CHECK (
        hardware_id IS NOT NULL OR serial_number IS NOT NULL
        OR entra_device_id IS NOT NULL OR provider_device_id IS NOT NULL
    );

CREATE OR REPLACE FUNCTION endpt.sync_autopilot_device_claims(
    p_company_id UUID, p_profile_id UUID, p_devices JSONB
) RETURNS JSONB AS $$
DECLARE
    v_device JSONB;
    v_existing UUID;
    v_provider TEXT;
    v_serial TEXT;
    v_entra TEXT;
    v_added INTEGER := 0;
    v_updated INTEGER := 0;
BEGIN
    IF jsonb_typeof(p_devices) <> 'array' OR jsonb_array_length(p_devices) > 10000 THEN
        RAISE EXCEPTION 'p_devices must be an array of at most 10000 devices';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM endpt.enrollment_profiles
         WHERE id=p_profile_id AND company_id=p_company_id AND is_active=true
    ) THEN
        RAISE EXCEPTION 'invalid enrollment profile';
    END IF;

    FOR v_device IN SELECT value FROM jsonb_array_elements(p_devices)
    LOOP
        v_provider := nullif(trim(v_device->>'provider_device_id'), '');
        v_serial := nullif(trim(v_device->>'serial_number'), '');
        v_entra := nullif(trim(v_device->>'entra_device_id'), '');
        IF v_provider IS NULL AND v_serial IS NULL AND v_entra IS NULL THEN
            CONTINUE;
        END IF;

        SELECT id INTO v_existing
          FROM endpt.enrollment_device_claims
         WHERE company_id=p_company_id AND (
             (v_provider IS NOT NULL AND provider_device_id=v_provider) OR
             (v_serial IS NOT NULL AND lower(serial_number)=lower(v_serial)) OR
             (v_entra IS NOT NULL AND lower(entra_device_id)=lower(v_entra))
         )
         ORDER BY created_at ASC LIMIT 1;

        IF v_existing IS NULL THEN
            INSERT INTO endpt.enrollment_device_claims
                (company_id, profile_id, provider_device_id, serial_number, entra_device_id)
            VALUES (p_company_id, p_profile_id, v_provider, v_serial, v_entra);
            v_added := v_added + 1;
        ELSE
            UPDATE endpt.enrollment_device_claims
               SET profile_id=p_profile_id,
                   provider_device_id=COALESCE(v_provider, provider_device_id),
                   serial_number=COALESCE(v_serial, serial_number),
                   entra_device_id=COALESCE(v_entra, entra_device_id),
                   status=CASE WHEN status='released' THEN 'pending' ELSE status END,
                   endpoint_id=CASE WHEN status='released' THEN NULL ELSE endpoint_id END,
                   enrolled_at=CASE WHEN status='released' THEN NULL ELSE enrolled_at END
             WHERE id=v_existing;
            v_updated := v_updated + 1;
        END IF;
        v_existing := NULL;
    END LOOP;
    RETURN jsonb_build_object('added', v_added, 'updated', v_updated);
END;
$$ LANGUAGE plpgsql;
GRANT EXECUTE ON FUNCTION endpt.sync_autopilot_device_claims(UUID, UUID, JSONB) TO service_role;

NOTIFY pgrst, 'reload schema';
