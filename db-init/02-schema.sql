-- ═══════════════════════════════════════════════════════════════════════════
-- Warden — endpt schema, full base DDL
-- Consolidated from the application model and historical migrations.
--
-- This is the authoritative schema for a FRESH database: every
-- table added by historical migrations (compliance_policies, compliance_results,
-- scheduled_jobs, alert_config/firewall_blocked_ips, the client-cert/
-- last-seen-ip/tenant-encryption columns) is already folded in below, with
-- corrected foreign keys targeting the real admin_users table.
-- The migration directory exists to upgrade older installations and should
-- not be replayed after this fresh-install schema unless release notes say so.
--
-- Target: self-hosted Postgres + PostgREST (replacing dropped Supabase
-- `endpt` schema — see db-init/01-roles.sql for the PostgREST roles this
-- schema's grants (03-grants.sql) depend on).
-- ═══════════════════════════════════════════════════════════════════════════

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- for gen_random_uuid()

CREATE SCHEMA IF NOT EXISTS endpt;

-- ─────────────────────────────────────────────────────────────────────────────
-- companies
-- vpn_subnet: legacy placeholder column, never shown/editable — app has no
-- VPN feature (see superadmin.py comment).
-- created_by FK added below, after admin_users exists (circular dependency).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE endpt.companies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    vpn_subnet      TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    encryption_mode TEXT NOT NULL DEFAULT 'managed'
                        CHECK (encryption_mode IN ('managed', 'byok')),
    wrapped_dek     TEXT,
    byok_salt       TEXT,
    -- Dual-approval-gated ops (UNINSTALL_AGENT, SHUTDOWN, REBOOT,
    -- DELETE_USER, etc. — see DUAL_APPROVAL_OPS in routes/endpoints.py)
    -- normally require two DIFFERENT admins to approve. A tenant with only
    -- one admin account can never satisfy that, so this is an explicit,
    -- disclosed opt-out a tenant can flip on for themselves (see
    -- settings/security.html) — defaults to TRUE (still required) since
    -- weakening it is a real security tradeoff, not a default.
    require_dual_approval BOOLEAN NOT NULL DEFAULT TRUE,
    -- Opt-in: when true, the background scheduler (services/scheduler.py)
    -- auto-dispatches an UPDATE_AGENT job to any online endpoint whose
    -- reported agent_version lags the latest completed build, without
    -- waiting for an admin to click "Update Agent" manually. Off by
    -- default — a bad build rolling out to the whole fleet unattended is
    -- a real risk a tenant should opt into deliberately, not inherit.
    auto_update_agents BOOLEAN NOT NULL DEFAULT FALSE,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE endpt.branches (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id  UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    city        TEXT,
    timezone    TEXT NOT NULL DEFAULT 'UTC',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_branches_company ON endpt.branches(company_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- admin_users
-- role: 'superadmin' | 'company_admin' | 'branch_admin' | 'technician'.
-- password_hash: bcrypt (60-char $2b$... string).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE endpt.admin_users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    full_name           TEXT NOT NULL,
    role                TEXT NOT NULL
                            CHECK (role IN ('superadmin', 'company_admin', 'branch_admin', 'technician')),
    company_id          UUID REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id           UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    created_by          UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    last_login_ip       TEXT,
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret          TEXT,
    mfa_backup_codes    JSONB,
    notification_prefs  JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_admin_users_company ON endpt.admin_users(company_id);
CREATE INDEX idx_admin_users_branch  ON endpt.admin_users(branch_id);

ALTER TABLE endpt.companies
    ADD CONSTRAINT fk_companies_created_by
    FOREIGN KEY (created_by) REFERENCES endpt.admin_users(id) ON DELETE SET NULL;

-- Tenant-owned third-party credentials. config_encrypted is encrypted with
-- the per-tenant DEK by server/db.py before storage; secrets never appear in
-- plaintext database columns or audit events.
CREATE TABLE endpt.tenant_integrations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL CHECK (provider IN ('microsoft_entra')),
    config_encrypted TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    status           TEXT NOT NULL DEFAULT 'not_tested'
                         CHECK (status IN ('not_tested', 'connected', 'error', 'disabled')),
    metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_tested_at   TIMESTAMPTZ,
    last_error       TEXT,
    created_by       UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, provider)
);
CREATE INDEX idx_tenant_integrations_company
    ON endpt.tenant_integrations(company_id, enabled);

CREATE TABLE endpt.refresh_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id     UUID NOT NULL REFERENCES endpt.admin_users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    ip_address   TEXT,
    user_agent   TEXT,
    expires_at   TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    family_id    UUID NOT NULL DEFAULT gen_random_uuid(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_refresh_tokens_admin ON endpt.refresh_tokens(admin_id);
CREATE INDEX idx_refresh_tokens_hash_active ON endpt.refresh_tokens(token_hash) WHERE revoked = FALSE;
CREATE INDEX idx_refresh_tokens_family ON endpt.refresh_tokens(family_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- endpoints
-- vpn_ip: TEXT not INET (app has no VPN feature, stores str(vpn_ip) if ever set).
-- is_active: required by get_endpoints' filter but nothing currently sets it
-- false — reserved for a future soft-delete path.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE endpt.endpoints (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id              UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id               UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    hostname                TEXT NOT NULL,
    api_key_hash            TEXT NOT NULL UNIQUE,
    hardware_id             TEXT,
    hardware_id_hash        TEXT,
    installation_id         TEXT,
    installation_id_hash    TEXT,
    enrollment_token_id     UUID,
    status                  TEXT NOT NULL DEFAULT 'offline'
                                CHECK (status IN ('online', 'offline')),
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    enrolled_at             TIMESTAMPTZ,
    vpn_ip                  TEXT,
    wg_pubkey               TEXT,
    last_seen               TIMESTAMPTZ,
    last_seen_ip            TEXT,
    local_ip                TEXT,
    device_type             TEXT NOT NULL DEFAULT 'unknown'
                                CHECK (device_type IN ('desktop', 'laptop', 'server', 'iot', 'unknown')),
    cpu_pct                 DOUBLE PRECISION,
    ram_used_pct            DOUBLE PRECISION,
    disk_free_gb            DOUBLE PRECISION,
    agent_version           TEXT,
    agent_memory_mb         DOUBLE PRECISION,
    agent_uptime_sec        INTEGER,
    net_sent_mbps           DOUBLE PRECISION,
    net_recv_mbps           DOUBLE PRECISION,
    topology_telemetry      JSONB NOT NULL DEFAULT '{}'::jsonb,
    topology_telemetry_encrypted TEXT,
    platform                TEXT NOT NULL DEFAULT 'windows'
                                CHECK (platform IN ('windows', 'linux', 'darwin', 'unknown')),
    capabilities            JSONB NOT NULL DEFAULT '[]'::jsonb,
    capability_details      JSONB NOT NULL DEFAULT '{}'::jsonb,
    capability_details_encrypted TEXT,
    os_name                 TEXT,
    os_version              TEXT,
    os_build                TEXT,
    os_edition              TEXT,
    arch                    TEXT,
    cpu_model               TEXT,
    ram_total_gb            DOUBLE PRECISION,
    disk_total_gb           DOUBLE PRECISION,
    interactive_user        TEXT,
    interactive_session_seen_at TIMESTAMPTZ,
    notes                   TEXT,
    tags                    TEXT[],
    tags_encrypted          TEXT,
    asset_tag               TEXT,
    asset_state             TEXT NOT NULL DEFAULT 'in_service'
                                 CHECK (asset_state IN ('stock','in_service','repair','retired','disposed','lost')),
    assigned_to             TEXT,
    purchase_date           DATE,
    warranty_expiry         DATE,
    asset_metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    asset_metadata_encrypted TEXT,
    device_identity_encrypted TEXT,
    private_data_encryption_version SMALLINT NOT NULL DEFAULT 0,
    client_cert_fingerprint TEXT,
    cloudflare_cert_id      TEXT,
    -- Last-known-applied value of each individually-addressable
    -- PUSH_LOCAL_POLICY setting (see server/policy_settings.py), keyed by
    -- setting key: {"rdp_enabled": {"value": true, "applied_at": "..."}}.
    -- Updated only when a PUSH_LOCAL_POLICY job for this endpoint reports
    -- success — not a live read-back of the registry, just what Warden last
    -- successfully pushed.
    policy_state            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_endpoints_company     ON endpt.endpoints(company_id);
CREATE INDEX idx_endpoints_installation_hash
    ON endpt.endpoints(company_id, installation_id_hash)
    WHERE installation_id_hash IS NOT NULL;
CREATE INDEX idx_endpoints_hardware_hash
    ON endpt.endpoints(company_id, hardware_id_hash)
    WHERE hardware_id_hash IS NOT NULL;
CREATE INDEX idx_endpoints_branch      ON endpt.endpoints(branch_id);
CREATE INDEX idx_endpoints_status_last ON endpt.endpoints(status, last_seen);
CREATE INDEX idx_endpoints_platform    ON endpt.endpoints(company_id, platform);
CREATE UNIQUE INDEX idx_endpoints_company_installation
    ON endpt.endpoints(company_id, installation_id)
    WHERE installation_id IS NOT NULL;

CREATE TABLE endpt.topology_floors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id UUID REFERENCES endpt.branches(id) ON DELETE SET NULL, building TEXT NOT NULL DEFAULT 'Office',
    name TEXT NOT NULL, level_order INTEGER NOT NULL DEFAULT 0,
    aspect_ratio NUMERIC(6,3) NOT NULL DEFAULT 1.778 CHECK (aspect_ratio BETWEEN 0.5 AND 4),
    layout_locked BOOLEAN NOT NULL DEFAULT FALSE, created_by UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(company_id, building, name)
);
CREATE INDEX idx_topology_floors_company ON endpt.topology_floors(company_id, level_order, name);
CREATE TABLE endpt.topology_rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id UUID NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE, name TEXT NOT NULL,
    x NUMERIC(7,3) NOT NULL CHECK (x BETWEEN 0 AND 100), y NUMERIC(7,3) NOT NULL CHECK (y BETWEEN 0 AND 100),
    width NUMERIC(7,3) NOT NULL CHECK (width BETWEEN 3 AND 100), height NUMERIC(7,3) NOT NULL CHECK (height BETWEEN 3 AND 100),
    color TEXT NOT NULL DEFAULT '#DCE9FF', capacity INTEGER CHECK (capacity IS NULL OR capacity >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(floor_id, name)
);
CREATE INDEX idx_topology_rooms_floor ON endpt.topology_rooms(floor_id);
CREATE TABLE endpt.topology_endpoint_placements (
    endpoint_id UUID PRIMARY KEY REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id UUID NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    room_id UUID REFERENCES endpt.topology_rooms(id) ON DELETE SET NULL,
    x NUMERIC(7,3) NOT NULL CHECK (x BETWEEN 0 AND 100), y NUMERIC(7,3) NOT NULL CHECK (y BETWEEN 0 AND 100),
    updated_by UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_topology_placements_floor ON endpt.topology_endpoint_placements(floor_id);

CREATE TABLE endpt.topology_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id UUID NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE, room_id UUID REFERENCES endpt.topology_rooms(id) ON DELETE SET NULL,
    node_type TEXT NOT NULL CHECK (node_type IN ('switch','firewall','router','server','access_point','printer','asset')),
    name TEXT NOT NULL, ip_address TEXT, details TEXT,
    x NUMERIC(7,3) NOT NULL CHECK (x BETWEEN 0 AND 100), y NUMERIC(7,3) NOT NULL CHECK (y BETWEEN 0 AND 100),
    created_by UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_topology_nodes_floor ON endpt.topology_nodes(floor_id);
CREATE TABLE endpt.topology_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id UUID NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL CHECK (source_type IN ('endpoint','node')), source_id UUID NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('endpoint','node')), target_id UUID NOT NULL,
    link_type TEXT NOT NULL DEFAULT 'ethernet' CHECK (link_type IN ('ethernet','fiber','wifi','vpn','logical')),
    label TEXT, status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('active','inactive','degraded','unknown')),
    created_by UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (NOT (source_type = target_type AND source_id = target_id)), UNIQUE(floor_id, source_type, source_id, target_type, target_id)
);
CREATE INDEX idx_topology_links_floor ON endpt.topology_links(floor_id);
CREATE TABLE endpt.topology_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id UUID NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now(), state JSONB NOT NULL
);
CREATE INDEX idx_topology_snapshots_floor_time ON endpt.topology_snapshots(company_id, floor_id, captured_at DESC);

-- Company-authored PUSH_LOCAL_POLICY templates: a named bundle of
-- individually-addressable settings (server/policy_settings.py) an admin
-- built from the curated catalog, deployable to one or many endpoints.
-- Distinct from the fixed, code-shipped LGPO templates in
-- server/policy_templates.py.
CREATE TABLE endpt.policy_templates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT,
    settings     JSONB NOT NULL,
    created_by   UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_policy_templates_company ON endpt.policy_templates(company_id);

-- Reusable zero-touch assignment policy. The short-lived/revocable token
-- below points at a profile so rebuilding an installer does not duplicate
-- its branch, matching, or pre-registration rules.
CREATE TABLE endpt.enrollment_profiles (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id               UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id                UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    name                     TEXT NOT NULL,
    deployment_method        TEXT NOT NULL DEFAULT 'intune'
                                 CHECK (deployment_method IN ('manual', 'gpo', 'intune', 'autopilot', 'sccm', 'rmm')),
    hostname_pattern         TEXT,
    domain_suffix            TEXT,
    require_pre_registration BOOLEAN NOT NULL DEFAULT FALSE,
    reclaim_existing         BOOLEAN NOT NULL DEFAULT TRUE,
    warden_only_mode         BOOLEAN NOT NULL DEFAULT TRUE,
    lockdown_config          JSONB,
    post_enrollment          JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_by               UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, name)
);
CREATE INDEX idx_enrollment_profiles_company
    ON endpt.enrollment_profiles(company_id, is_active);
CREATE UNIQUE INDEX idx_enrollment_profiles_company_name_ci
    ON endpt.enrollment_profiles(company_id, lower(name));

ALTER TABLE endpt.endpoints
    ADD COLUMN enrollment_profile_id UUID REFERENCES endpt.enrollment_profiles(id) ON DELETE SET NULL,
    ADD COLUMN device_identity JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX idx_endpoints_company_hardware
    ON endpt.endpoints(company_id, hardware_id) WHERE hardware_id IS NOT NULL;

CREATE TABLE endpt.enrollment_tokens (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id           UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id            UUID NOT NULL REFERENCES endpt.branches(id) ON DELETE CASCADE,
    token_hash           TEXT NOT NULL UNIQUE,
    is_active            BOOLEAN NOT NULL DEFAULT TRUE,
    use_count            INTEGER NOT NULL DEFAULT 0,
    -- NULL = single-use (legacy default, one enrollment then burned).
    -- A positive number allows that many enrollments before burning --
    -- e.g. a GPO/SCCM/Intune-deployed MSI enrolling many machines from one
    -- reusable token. NULL max_uses together with a real expires_at is how
    -- an admin scopes "reusable until this window closes" instead of
    -- "reusable N times" -- both bounds are enforced together, whichever
    -- is tighter.
    max_uses             INTEGER,
    profile_id           UUID REFERENCES endpt.enrollment_profiles(id) ON DELETE SET NULL,
    used_by_endpoint_id  UUID REFERENCES endpt.endpoints(id) ON DELETE SET NULL,
    expires_at           TIMESTAMPTZ NOT NULL,
    created_by           UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_enrollment_tokens_company ON endpt.enrollment_tokens(company_id);
CREATE INDEX idx_enrollment_tokens_hash_active
    ON endpt.enrollment_tokens(token_hash) WHERE is_active = TRUE;
CREATE INDEX idx_enrollment_tokens_profile ON endpt.enrollment_tokens(profile_id);
ALTER TABLE endpt.endpoints
    ADD CONSTRAINT endpoints_enrollment_token_id_fkey
    FOREIGN KEY (enrollment_token_id) REFERENCES endpt.enrollment_tokens(id) ON DELETE SET NULL;

CREATE TABLE endpt.enrollment_device_claims (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    profile_id         UUID NOT NULL REFERENCES endpt.enrollment_profiles(id) ON DELETE CASCADE,
    hardware_id        TEXT,
    serial_number      TEXT,
    entra_device_id    TEXT,
    expected_hostname  TEXT,
    provider_device_id TEXT,
    assigned_user      TEXT,
    status             TEXT NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending', 'enrolled', 'released')),
    endpoint_id        UUID REFERENCES endpt.endpoints(id) ON DELETE SET NULL,
    enrolled_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (hardware_id IS NOT NULL OR serial_number IS NOT NULL
           OR entra_device_id IS NOT NULL OR provider_device_id IS NOT NULL)
);
CREATE INDEX idx_enrollment_claims_profile
    ON endpt.enrollment_device_claims(profile_id, status);
CREATE UNIQUE INDEX idx_enrollment_claims_company_hardware
    ON endpt.enrollment_device_claims(company_id, lower(hardware_id)) WHERE hardware_id IS NOT NULL;
CREATE UNIQUE INDEX idx_enrollment_claims_company_serial
    ON endpt.enrollment_device_claims(company_id, lower(serial_number)) WHERE serial_number IS NOT NULL;
CREATE UNIQUE INDEX idx_enrollment_claims_company_provider
    ON endpt.enrollment_device_claims(company_id, provider_device_id) WHERE provider_device_id IS NOT NULL;
CREATE INDEX idx_enrollment_claims_company_entra
    ON endpt.enrollment_device_claims(company_id, lower(entra_device_id)) WHERE entra_device_id IS NOT NULL;

CREATE OR REPLACE FUNCTION endpt.sync_autopilot_device_claims(
    p_company_id UUID, p_profile_id UUID, p_devices JSONB
) RETURNS JSONB AS $$
DECLARE
    v_device JSONB; v_existing UUID; v_provider TEXT; v_serial TEXT; v_entra TEXT;
    v_added INTEGER := 0; v_updated INTEGER := 0;
BEGIN
    IF jsonb_typeof(p_devices) <> 'array' OR jsonb_array_length(p_devices) > 10000 THEN
        RAISE EXCEPTION 'p_devices must be an array of at most 10000 devices';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM endpt.enrollment_profiles WHERE id=p_profile_id AND company_id=p_company_id AND is_active=true) THEN
        RAISE EXCEPTION 'invalid enrollment profile';
    END IF;
    FOR v_device IN SELECT value FROM jsonb_array_elements(p_devices) LOOP
        v_provider := nullif(trim(v_device->>'provider_device_id'), '');
        v_serial := nullif(trim(v_device->>'serial_number'), '');
        v_entra := nullif(trim(v_device->>'entra_device_id'), '');
        IF v_provider IS NULL AND v_serial IS NULL AND v_entra IS NULL THEN CONTINUE; END IF;
        SELECT id INTO v_existing FROM endpt.enrollment_device_claims
         WHERE company_id=p_company_id AND ((v_provider IS NOT NULL AND provider_device_id=v_provider)
            OR (v_serial IS NOT NULL AND lower(serial_number)=lower(v_serial))
            OR (v_entra IS NOT NULL AND lower(entra_device_id)=lower(v_entra)))
         ORDER BY created_at ASC LIMIT 1;
        IF v_existing IS NULL THEN
            INSERT INTO endpt.enrollment_device_claims
                (company_id, profile_id, provider_device_id, serial_number, entra_device_id)
            VALUES (p_company_id, p_profile_id, v_provider, v_serial, v_entra);
            v_added := v_added + 1;
        ELSE
            UPDATE endpt.enrollment_device_claims SET profile_id=p_profile_id,
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

-- Atomically claim one use of an enrollment token, respecting max_uses.
-- A plain PostgREST PATCH can't express "increment use_count, but only if
-- still under max_uses" as a single atomic operation -- FOR UPDATE row-locks
-- the token row for the duration of this function's implicit transaction,
-- so concurrent /enroll requests against the SAME reusable token (the exact
-- scenario a GPO-deployed installer creates: many machines enrolling in a
-- tight window, e.g. after a domain-wide reboot) serialize correctly
-- instead of racing past each other's use_count read.
CREATE OR REPLACE FUNCTION endpt.claim_enrollment_token_use(p_token_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_use_count  INTEGER;
    v_max_uses   INTEGER;
    v_is_active  BOOLEAN;
    v_expires_at TIMESTAMPTZ;
BEGIN
    SELECT use_count, max_uses, is_active, expires_at
      INTO v_use_count, v_max_uses, v_is_active, v_expires_at
      FROM endpt.enrollment_tokens
     WHERE id = p_token_id
     FOR UPDATE;

    IF NOT FOUND OR NOT v_is_active OR v_expires_at <= now() THEN
        RETURN FALSE;
    END IF;

    IF v_max_uses IS NOT NULL AND v_use_count >= v_max_uses THEN
        UPDATE endpt.enrollment_tokens SET is_active = FALSE WHERE id = p_token_id;
        RETURN FALSE;
    END IF;

    UPDATE endpt.enrollment_tokens
       SET use_count = v_use_count + 1,
           is_active = NOT (v_max_uses IS NOT NULL AND v_use_count + 1 >= v_max_uses)
     WHERE id = p_token_id;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Return one claimed use when enrollment fails before an endpoint is
-- created (for example transient client-certificate issuance or database
-- failure). Row locking keeps release/claim updates correct for reusable
-- tokens enrolling many machines concurrently.
CREATE OR REPLACE FUNCTION endpt.release_enrollment_token_use(p_token_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_use_count  INTEGER;
    v_max_uses   INTEGER;
    v_expires_at TIMESTAMPTZ;
BEGIN
    SELECT use_count, max_uses, expires_at
      INTO v_use_count, v_max_uses, v_expires_at
      FROM endpt.enrollment_tokens
     WHERE id = p_token_id
     FOR UPDATE;

    IF NOT FOUND OR v_use_count <= 0 THEN
        RETURN FALSE;
    END IF;

    UPDATE endpt.enrollment_tokens
       SET use_count = v_use_count - 1,
           is_active = v_expires_at > now()
                       AND (v_max_uses IS NULL OR v_use_count - 1 < v_max_uses)
     WHERE id = p_token_id;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE endpt.tenant_access_grants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id    UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    requested_by  UUID NOT NULL REFERENCES endpt.admin_users(id),
    reason        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'denied', 'revoked')),
    reviewed_by   UUID REFERENCES endpt.admin_users(id),
    reviewed_at   TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tenant_access_grants_company   ON endpt.tenant_access_grants(company_id, status);
CREATE INDEX idx_tenant_access_grants_requester ON endpt.tenant_access_grants(requested_by, status);

CREATE TABLE endpt.firewall_blocked_ips (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address  INET NOT NULL UNIQUE,
    reason      TEXT,
    created_by  UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);
CREATE INDEX idx_firewall_blocked_ips_expires
    ON endpt.firewall_blocked_ips(expires_at) WHERE expires_at IS NOT NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- escalation_requests / jobs
-- payload/reason/result_log/log_output/error_msg: TEXT — per-tenant AES-GCM
-- ciphertext (base64), opaque to Postgres, not structured JSON.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE endpt.escalation_requests (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id              UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id               UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    endpoint_id             UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    windows_user            TEXT NOT NULL DEFAULT '',
    operation               TEXT NOT NULL,
    payload                 TEXT,
    reason                  TEXT,
    status                  TEXT NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'pending_secondary', 'approved',
                                                   'denied', 'expired', 'completed')),
    requires_dual_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    requested_by            UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    reviewed_by             UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    reviewed_at             TIMESTAMPTZ,
    secondary_reviewed_by   UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    secondary_reviewed_at   TIMESTAMPTZ,
    escalation_token        TEXT,
    token_expires_at        TIMESTAMPTZ,
    result_log              TEXT,
    result_exit             INTEGER,
    expires_at              TIMESTAMPTZ NOT NULL,
    requested_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_escalation_requests_company ON endpt.escalation_requests(company_id, status);
CREATE INDEX idx_escalation_requests_endpoint ON endpt.escalation_requests(endpoint_id);
CREATE INDEX idx_escalation_requests_requester ON endpt.escalation_requests(requested_by, status);

CREATE TABLE endpt.jobs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id              UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id               UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    endpoint_id             UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    type                    TEXT NOT NULL,
    payload                 TEXT,
    status                  TEXT NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'running',
                                                   'completed', 'failed', 'cancelled')),
    priority                INTEGER NOT NULL DEFAULT 0,
    created_by              UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    requires_dual_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    escalation_id           UUID REFERENCES endpt.escalation_requests(id) ON DELETE SET NULL,
    log_output              TEXT,
    exit_code               INTEGER,
    error_msg               TEXT,
    started_at              TIMESTAMPTZ,
    delivered_at            TIMESTAMPTZ,
    lease_expires_at        TIMESTAMPTZ,
    delivery_attempts       INTEGER NOT NULL DEFAULT 0,
    result_processing_at    TIMESTAMPTZ,
    result_processed_at     TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_jobs_company         ON endpt.jobs(company_id, created_at DESC);
CREATE INDEX idx_jobs_endpoint_status ON endpt.jobs(endpoint_id, status);
CREATE INDEX idx_jobs_dispatch_queue  ON endpt.jobs(endpoint_id, priority DESC, created_at ASC)
    WHERE status IN ('pending', 'approved', 'running');
CREATE INDEX idx_jobs_lease_expiry ON endpt.jobs(endpoint_id, lease_expires_at)
    WHERE status = 'running';
-- db.has_inflight_job() + db.create_job() (services/scheduler.py's
-- _check_auto_updates()) are two separate round-trips with no lock between
-- them -- fine with today's single scheduler thread, but nothing stops a
-- second scheduler instance (a scaled-out deployment, or preload_app turned
-- off) from racing the same check-then-insert and double-dispatching
-- UPDATE_AGENT to the same endpoint. Scoped to created_by IS NULL
-- (system-initiated only) so it can never block an admin's own manual
-- Update Agent click, even if one happens to be in flight already.
CREATE UNIQUE INDEX idx_jobs_no_dup_auto_update ON endpt.jobs(endpoint_id)
    WHERE type = 'UPDATE_AGENT' AND created_by IS NULL
      AND status IN ('pending', 'approved', 'running');

-- Atomically create system-scheduled work only when the same operation is not
-- already pending/running for the endpoint. An advisory transaction lock
-- closes the check-then-insert race across scheduler processes without
-- restricting deliberate admin-created jobs.
CREATE OR REPLACE FUNCTION endpt.create_system_job_once(
    p_company_id UUID, p_branch_id UUID, p_endpoint_id UUID,
    p_type TEXT, p_encrypted_payload TEXT
) RETURNS SETOF endpt.jobs
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_endpoint_id::text || ':' || p_type, 0));
    IF EXISTS (
        SELECT 1 FROM endpt.jobs
         WHERE endpoint_id=p_endpoint_id AND type=p_type
           AND status IN ('pending','approved','running')
    ) THEN
        RETURN;
    END IF;
    RETURN QUERY
    INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
    VALUES(p_company_id,p_branch_id,p_endpoint_id,p_type,p_encrypted_payload,'pending',NULL)
    RETURNING *;
END;
$$;
REVOKE ALL ON FUNCTION endpt.create_system_job_once(UUID,UUID,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_system_job_once(UUID,UUID,UUID,TEXT,TEXT) TO service_role;

CREATE TABLE endpt.policy_deployments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id       UUID NOT NULL REFERENCES endpt.branches(id) ON DELETE CASCADE,
    template_id     UUID REFERENCES endpt.policy_templates(id) ON DELETE SET NULL,
    template_name   TEXT NOT NULL,
    reason          TEXT,
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','paused','completed','cancelled')),
    targeted_count  INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at    TIMESTAMPTZ
);
ALTER TABLE endpt.policy_deployments ADD COLUMN idempotency_key TEXT;
CREATE UNIQUE INDEX idx_policy_deployments_idempotency
    ON endpt.policy_deployments(company_id,idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_policy_deployments_company
    ON endpt.policy_deployments(company_id, created_at DESC);

CREATE TABLE endpt.policy_deployment_targets (
    deployment_id UUID NOT NULL REFERENCES endpt.policy_deployments(id) ON DELETE CASCADE,
    endpoint_id   UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    job_id        UUID NOT NULL UNIQUE REFERENCES endpt.jobs(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, endpoint_id)
);
CREATE INDEX idx_policy_deployment_targets_deployment
    ON endpt.policy_deployment_targets(deployment_id);

CREATE OR REPLACE FUNCTION endpt.claim_jobs_for_endpoint(
    p_endpoint_id UUID, p_limit INTEGER DEFAULT 5, p_lease_seconds INTEGER DEFAULT 900
)
RETURNS SETOF endpt.jobs
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, public AS $$
BEGIN
    RETURN QUERY
    WITH candidates AS (
        SELECT j.id FROM endpt.jobs j
         WHERE j.endpoint_id = p_endpoint_id
           AND (j.status IN ('pending','approved') OR
                (j.status = 'running' AND
                 (j.lease_expires_at IS NULL OR j.lease_expires_at <= now())))
         ORDER BY j.priority DESC, j.created_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT LEAST(GREATEST(p_limit, 1), 20)
    )
    UPDATE endpt.jobs j
       SET status = 'running', started_at = COALESCE(j.started_at, now()),
           delivered_at = now(),
           lease_expires_at = now() + make_interval(secs => LEAST(GREATEST(p_lease_seconds, 60), 3600)),
           delivery_attempts = j.delivery_attempts + 1
      FROM candidates c WHERE j.id = c.id
    RETURNING j.*;
END;
$$;
REVOKE ALL ON FUNCTION endpt.claim_jobs_for_endpoint(UUID, INTEGER, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_jobs_for_endpoint(UUID, INTEGER, INTEGER) TO service_role;

CREATE OR REPLACE FUNCTION endpt.claim_job_result_processing(p_job_id UUID)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
 UPDATE endpt.jobs SET result_processing_at=now() WHERE id=p_job_id AND status IN('completed','failed')
  AND result_processed_at IS NULL AND (result_processing_at IS NULL OR result_processing_at<now()-interval '60 seconds');
 RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION endpt.claim_job_result_processing(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_job_result_processing(UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.complete_job_result_processing(p_job_id UUID)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
 UPDATE endpt.jobs SET result_processed_at=now(),result_processing_at=NULL WHERE id=p_job_id AND result_processed_at IS NULL;
 RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION endpt.complete_job_result_processing(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.complete_job_result_processing(UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.create_policy_deployment(
    p_company_id UUID, p_branch_id UUID, p_template_id UUID,
    p_template_name TEXT, p_encrypted_payload TEXT, p_created_by UUID,
    p_reason TEXT DEFAULT NULL, p_idempotency_key TEXT DEFAULT NULL
)
RETURNS TABLE(deployment_id UUID, targeted INTEGER, queued INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, public AS $$
DECLARE
    v_deployment_id UUID; v_endpoint RECORD; v_job_id UUID;
    v_targeted INTEGER := 0; v_queued INTEGER := 0;
BEGIN
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(p_company_id::text||':'||p_idempotency_key,0));
        SELECT id,targeted_count INTO v_deployment_id,v_targeted FROM endpt.policy_deployments
         WHERE company_id=p_company_id AND idempotency_key=p_idempotency_key;
        IF FOUND THEN SELECT count(*) INTO v_queued FROM endpt.policy_deployment_targets
            WHERE deployment_id=v_deployment_id; RETURN QUERY SELECT v_deployment_id,v_targeted,v_queued; RETURN; END IF;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM endpt.branches WHERE id=p_branch_id AND company_id=p_company_id) THEN
        RAISE EXCEPTION 'branch does not belong to company';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM endpt.policy_templates WHERE id=p_template_id AND company_id=p_company_id) THEN
        RAISE EXCEPTION 'template does not belong to company';
    END IF;
    SELECT count(*) INTO v_targeted FROM endpt.endpoints
     WHERE company_id=p_company_id AND branch_id=p_branch_id AND is_active=TRUE;
    INSERT INTO endpt.policy_deployments(company_id,branch_id,template_id,template_name,reason,targeted_count,created_by,idempotency_key)
    VALUES(p_company_id,p_branch_id,p_template_id,p_template_name,p_reason,v_targeted,p_created_by,p_idempotency_key)
    RETURNING id INTO v_deployment_id;
    FOR v_endpoint IN SELECT id FROM endpt.endpoints
        WHERE company_id=p_company_id AND branch_id=p_branch_id AND is_active=TRUE ORDER BY hostname
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(p_company_id,p_branch_id,v_endpoint.id,'PUSH_LOCAL_POLICY',p_encrypted_payload,'pending',p_created_by)
        RETURNING id INTO v_job_id;
        INSERT INTO endpt.policy_deployment_targets(deployment_id,endpoint_id,job_id)
        VALUES(v_deployment_id,v_endpoint.id,v_job_id);
        v_queued := v_queued + 1;
    END LOOP;
    RETURN QUERY SELECT v_deployment_id,v_targeted,v_queued;
END;
$$;
REVOKE ALL ON FUNCTION endpt.create_policy_deployment(UUID, UUID, UUID, TEXT, TEXT, UUID, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_policy_deployment(UUID, UUID, UUID, TEXT, TEXT, UUID, TEXT, TEXT) TO service_role;

CREATE OR REPLACE FUNCTION endpt.cancel_policy_deployment(p_deployment_id UUID,p_company_id UUID)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_cancelled INTEGER;
BEGIN
    UPDATE endpt.policy_deployments SET status='cancelled',cancelled_at=now()
     WHERE id=p_deployment_id AND company_id=p_company_id AND status='active';
    IF NOT FOUND THEN RETURN 0; END IF;
    UPDATE endpt.jobs j SET status='cancelled',completed_at=now(),lease_expires_at=NULL
      FROM endpt.policy_deployment_targets t
     WHERE t.deployment_id=p_deployment_id AND t.job_id=j.id AND j.status IN ('pending','approved');
    GET DIAGNOSTICS v_cancelled = ROW_COUNT;
    RETURN v_cancelled;
END;
$$;
REVOKE ALL ON FUNCTION endpt.cancel_policy_deployment(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.cancel_policy_deployment(UUID, UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.retry_policy_deployment(p_deployment_id UUID,p_company_id UUID)
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_target RECORD; v_new_job_id UUID; v_retried INTEGER:=0;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM endpt.policy_deployments
        WHERE id=p_deployment_id AND company_id=p_company_id FOR UPDATE) THEN RETURN 0; END IF;
    FOR v_target IN SELECT t.endpoint_id,t.job_id,j.company_id,j.branch_id,j.type,j.payload,j.created_by
        FROM endpt.policy_deployment_targets t JOIN endpt.jobs j ON j.id=t.job_id
        WHERE t.deployment_id=p_deployment_id AND j.status IN('failed','cancelled') FOR UPDATE OF t,j
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(v_target.company_id,v_target.branch_id,v_target.endpoint_id,v_target.type,
               v_target.payload,'pending',v_target.created_by) RETURNING id INTO v_new_job_id;
        UPDATE endpt.policy_deployment_targets SET job_id=v_new_job_id,created_at=now()
         WHERE deployment_id=p_deployment_id AND endpoint_id=v_target.endpoint_id;
        v_retried:=v_retried+1;
    END LOOP;
    IF v_retried>0 THEN UPDATE endpt.policy_deployments SET status='active',cancelled_at=NULL
        WHERE id=p_deployment_id; END IF;
    RETURN v_retried;
END;
$$;
REVOKE ALL ON FUNCTION endpt.retry_policy_deployment(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.retry_policy_deployment(UUID, UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.maybe_pause_policy_deployment(p_job_id UUID)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_deployment_id UUID; v_targeted INTEGER; v_failed INTEGER;
BEGIN
    SELECT d.id,d.targeted_count INTO v_deployment_id,v_targeted
      FROM endpt.policy_deployment_targets t JOIN endpt.policy_deployments d ON d.id=t.deployment_id
     WHERE t.job_id=p_job_id AND d.status='active' FOR UPDATE OF d;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT count(*) INTO v_failed FROM endpt.policy_deployment_targets t JOIN endpt.jobs j ON j.id=t.job_id
     WHERE t.deployment_id=v_deployment_id AND j.status='failed';
    IF v_failed<2 OR v_failed*100<GREATEST(v_targeted,1)*20 THEN RETURN NULL; END IF;
    UPDATE endpt.policy_deployments SET status='paused' WHERE id=v_deployment_id;
    UPDATE endpt.jobs j SET status='cancelled',completed_at=now(),lease_expires_at=NULL
      FROM endpt.policy_deployment_targets t WHERE t.deployment_id=v_deployment_id
       AND t.job_id=j.id AND j.status IN('pending','approved');
    RETURN v_deployment_id;
END;
$$;
REVOKE ALL ON FUNCTION endpt.maybe_pause_policy_deployment(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.maybe_pause_policy_deployment(UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.get_policy_deployment_summaries(p_company_id UUID,p_limit INTEGER DEFAULT 20)
RETURNS TABLE(id UUID,company_id UUID,branch_id UUID,branch_name TEXT,template_name TEXT,status TEXT,
 targeted_count INTEGER,pending BIGINT,running BIGINT,completed BIGINT,failed BIGINT,cancelled BIGINT,created_at TIMESTAMPTZ)
LANGUAGE sql SECURITY DEFINER SET search_path=endpt,public AS $$
 SELECT d.id,d.company_id,d.branch_id,b.name,d.template_name,d.status,d.targeted_count,
  count(*) FILTER(WHERE j.status IN('pending','approved')),count(*) FILTER(WHERE j.status='running'),
  count(*) FILTER(WHERE j.status='completed'),count(*) FILTER(WHERE j.status='failed'),
  count(*) FILTER(WHERE j.status='cancelled'),d.created_at
 FROM endpt.policy_deployments d JOIN endpt.branches b ON b.id=d.branch_id
 LEFT JOIN endpt.policy_deployment_targets t ON t.deployment_id=d.id LEFT JOIN endpt.jobs j ON j.id=t.job_id
 WHERE d.company_id=p_company_id GROUP BY d.id,b.name ORDER BY d.created_at DESC
 LIMIT LEAST(GREATEST(p_limit,1),100);
$$;
REVOKE ALL ON FUNCTION endpt.get_policy_deployment_summaries(UUID,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.get_policy_deployment_summaries(UUID,INTEGER) TO service_role;

CREATE OR REPLACE FUNCTION endpt.refresh_policy_deployment_status(p_job_id UUID)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_deployment_id UUID; v_status TEXT; v_open INTEGER;
BEGIN
 SELECT d.id,d.status INTO v_deployment_id,v_status FROM endpt.policy_deployment_targets t
  JOIN endpt.policy_deployments d ON d.id=t.deployment_id WHERE t.job_id=p_job_id FOR UPDATE OF d;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT count(*) INTO v_open FROM endpt.policy_deployment_targets t JOIN endpt.jobs j ON j.id=t.job_id
  WHERE t.deployment_id=v_deployment_id AND j.status IN('pending','approved','running');
 IF v_open=0 AND v_status='active' THEN UPDATE endpt.policy_deployments SET status='completed'
  WHERE id=v_deployment_id; RETURN 'completed'; END IF;
 RETURN v_status;
END;
$$;
REVOKE ALL ON FUNCTION endpt.refresh_policy_deployment_status(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.refresh_policy_deployment_status(UUID) TO service_role;

CREATE TABLE endpt.windows_users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id   UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    username      TEXT NOT NULL,
    display_name  TEXT,
    sid           TEXT,
    principal_name TEXT,
    account_type  TEXT NOT NULL DEFAULT 'local'
                      CHECK (account_type IN ('local', 'domain', 'entra', 'microsoft', 'unknown')),
    domain_name   TEXT,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    present       BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced   TIMESTAMPTZ,
    UNIQUE (endpoint_id, username)
);
CREATE INDEX idx_windows_users_endpoint ON endpt.windows_users(endpoint_id);
CREATE INDEX idx_windows_users_sid ON endpt.windows_users(sid) WHERE sid IS NOT NULL;

-- Atomically replace an endpoint's current account inventory. Rows are kept
-- with present=false instead of deleted so the central directory retains an
-- audit-friendly last-known record while its default view remains current.
CREATE OR REPLACE FUNCTION endpt.replace_windows_users(p_endpoint_id UUID, p_users JSONB)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=endpt,public
AS $$
DECLARE v_count INTEGER;
BEGIN
    IF p_users IS NULL OR jsonb_typeof(p_users) IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_users) > 512 THEN
        RAISE EXCEPTION 'invalid user inventory';
    END IF;

    UPDATE endpt.windows_users SET present=FALSE
    WHERE endpoint_id=p_endpoint_id;

    INSERT INTO endpt.windows_users (
        endpoint_id, username, display_name, sid, principal_name,
        account_type, domain_name, is_admin, is_enabled, present, last_synced
    )
    SELECT
        p_endpoint_id,
        item->>'username',
        NULLIF(item->>'display_name', ''),
        NULLIF(item->>'sid', ''),
        NULLIF(item->>'principal_name', ''),
        CASE WHEN item->>'account_type' IN ('local','domain','entra','microsoft','unknown')
             THEN item->>'account_type' ELSE 'unknown' END,
        NULLIF(item->>'domain_name', ''),
        COALESCE((item->>'is_admin')::BOOLEAN, FALSE),
        COALESCE((item->>'is_enabled')::BOOLEAN, TRUE),
        TRUE,
        now()
    FROM jsonb_array_elements(p_users) item
    WHERE NULLIF(item->>'username', '') IS NOT NULL
    ON CONFLICT (endpoint_id, username) DO UPDATE SET
        display_name=EXCLUDED.display_name,
        sid=EXCLUDED.sid,
        principal_name=EXCLUDED.principal_name,
        account_type=EXCLUDED.account_type,
        domain_name=EXCLUDED.domain_name,
        is_admin=EXCLUDED.is_admin,
        is_enabled=EXCLUDED.is_enabled,
        present=TRUE,
        last_synced=now();

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;
REVOKE ALL ON FUNCTION endpt.replace_windows_users(UUID, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.replace_windows_users(UUID, JSONB) TO service_role;

CREATE TABLE endpt.software_inventory (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id   UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    version       TEXT,
    publisher     TEXT,
    install_date  TEXT,
    install_location TEXT,
    executable_path TEXT
);
CREATE INDEX idx_software_inventory_endpoint ON endpt.software_inventory(endpoint_id);
CREATE INDEX idx_software_inventory_name     ON endpt.software_inventory(endpoint_id, name);

CREATE TABLE endpt.saved_escalations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id      UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    endpoint_id    UUID REFERENCES endpt.endpoints(id) ON DELETE SET NULL,
    windows_user   TEXT,
    scope          TEXT NOT NULL,
    operation      TEXT NOT NULL,
    payload_match  JSONB NOT NULL DEFAULT '{}',
    approved_by    UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    approved_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from     TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until    TIMESTAMPTZ,
    note           TEXT,
    revoked_by     UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    revoked_at     TIMESTAMPTZ
);
CREATE INDEX idx_saved_escalations_company ON endpt.saved_escalations(company_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_saved_escalations_lookup  ON endpt.saved_escalations(company_id, operation) WHERE revoked_at IS NULL;

CREATE TABLE endpt.alerts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id        UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    endpoint_id      UUID REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    type             TEXT NOT NULL,
    severity         TEXT NOT NULL,
    title            TEXT NOT NULL,
    message          TEXT,
    detail           JSONB NOT NULL DEFAULT '{}',
    detail_encrypted TEXT,
    is_resolved      BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_by      UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    resolved_at      TIMESTAMPTZ,
    resolution_note  TEXT,
    assigned_to      UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    snoozed_until    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_alerts_company_resolved ON endpt.alerts(company_id, is_resolved, created_at DESC);
CREATE INDEX idx_alerts_endpoint_open    ON endpt.alerts(endpoint_id, type) WHERE is_resolved = FALSE;
CREATE INDEX idx_alerts_assigned_open    ON endpt.alerts(assigned_to, created_at DESC) WHERE is_resolved = FALSE;

CREATE TABLE endpt.app_library (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID REFERENCES endpt.companies(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    size_bytes   BIGINT NOT NULL,
    description  TEXT,
    install_args TEXT NOT NULL DEFAULT '',
    self_service BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_app_library_company ON endpt.app_library(company_id);

CREATE TABLE endpt.patch_inventory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    endpoint_id     UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    update_id       TEXT NOT NULL,
    title           TEXT NOT NULL,
    kb_articles     TEXT[] NOT NULL DEFAULT '{}',
    severity        TEXT,
    categories      TEXT[] NOT NULL DEFAULT '{}',
    reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
    reported_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(endpoint_id, update_id)
);
CREATE INDEX idx_patch_inventory_company ON endpt.patch_inventory(company_id, severity);

CREATE TABLE endpt.audit_log (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     UUID REFERENCES endpt.companies(id) ON DELETE SET NULL,
    branch_id      UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    endpoint_id    UUID REFERENCES endpt.endpoints(id) ON DELETE SET NULL,
    actor_id       UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    escalation_id  UUID REFERENCES endpt.escalation_requests(id) ON DELETE SET NULL,
    action         TEXT NOT NULL,
    detail         JSONB NOT NULL DEFAULT '{}',
    detail_encrypted TEXT,
    prev_hash      TEXT,
    row_hash       TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_log_company  ON endpt.audit_log(company_id, created_at DESC);
CREATE INDEX idx_audit_log_endpoint ON endpt.audit_log(endpoint_id);
CREATE INDEX idx_audit_log_actor    ON endpt.audit_log(actor_id);

CREATE TABLE endpt.endpoint_metrics (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id   UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    cpu_pct       DOUBLE PRECISION,
    ram_used_pct  DOUBLE PRECISION,
    collected_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_endpoint_metrics_endpoint_time ON endpt.endpoint_metrics(endpoint_id, collected_at);

CREATE TABLE endpt.endpoint_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id  UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL,
    detail       JSONB NOT NULL DEFAULT '{}',
    detail_encrypted TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_endpoint_events_endpoint_time ON endpt.endpoint_events(endpoint_id, created_at DESC);
CREATE INDEX idx_endpoint_events_type_time     ON endpt.endpoint_events(endpoint_id, event_type, created_at DESC);

-- build_requests: written both by server/db.py (status/download_path/build_log/
-- completed_at) and the separate build-service/db.py process (status/
-- output_filename/updated_at/build_log) — both write paths are real.
CREATE TABLE endpt.build_requests (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id            UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id             UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    enrollment_token_id   UUID REFERENCES endpt.enrollment_tokens(id) ON DELETE SET NULL,
    config_json           JSONB NOT NULL,
    target_platform       TEXT NOT NULL DEFAULT 'windows-amd64'
                              CHECK (target_platform IN ('windows-amd64', 'linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64')),
    status                TEXT NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'building', 'completed', 'failed')),
    requested_by          UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    download_path         TEXT,
    output_filename       TEXT,
    build_log             TEXT,
    -- sha256/agent_version: the compiled warden-agent.exe is byte-identical
    -- across every tenant's build (same source, same build-time ldflags for
    -- server_url/pubkey/cert_fingerprint — those aren't per-tenant secrets,
    -- only config.json's enrollment_token/company_id/branch_id are). That
    -- means any successfully completed build's exe can serve as "the
    -- latest agent binary" for updating already-enrolled endpoints on ANY
    -- tenant — see server/routes/agent_api.py's latest-build lookup.
    sha256                TEXT,
    agent_version         TEXT,
    -- Set once build-service's best-effort MSI packaging (builder.py's
    -- build_msi(), via msitools/wixl) succeeds for this build -- a
    -- .msi wraps the exact same exe as the zip, just packaged for GPO
    -- Software Installation / SCCM / Intune deployment instead of manual
    -- per-machine install.bat. Independent of the main `status` column so
    -- an MSI packaging failure never fails the underlying build.
    msi_ready             BOOLEAN NOT NULL DEFAULT false,
    claim_token           UUID,
    lease_expires_at      TIMESTAMPTZ,
    completed_at          TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_build_requests_company ON endpt.build_requests(company_id, created_at DESC);
CREATE INDEX idx_build_requests_pending ON endpt.build_requests(status, created_at ASC) WHERE status = 'pending';
CREATE INDEX idx_build_requests_latest ON endpt.build_requests(completed_at DESC) WHERE status = 'completed';
CREATE INDEX idx_build_requests_target_latest ON endpt.build_requests(target_platform, completed_at DESC) WHERE status = 'completed';

CREATE OR REPLACE FUNCTION endpt.claim_next_build(p_lease_seconds INTEGER DEFAULT 900)
RETURNS SETOF endpt.build_requests AS $$
DECLARE v_id UUID;
BEGIN
    SELECT id INTO v_id FROM endpt.build_requests
    WHERE status = 'pending'
       OR (status = 'building' AND (lease_expires_at IS NULL OR lease_expires_at < now()))
    ORDER BY created_at ASC FOR UPDATE SKIP LOCKED LIMIT 1;
    IF v_id IS NULL THEN RETURN; END IF;
    RETURN QUERY UPDATE endpt.build_requests
       SET status='building', claim_token=gen_random_uuid(),
           lease_expires_at=now()+make_interval(secs => GREATEST(p_lease_seconds, 60)),
           updated_at=now()
     WHERE id=v_id RETURNING *;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION endpt.renew_build_claim(
    p_build_id UUID, p_claim_token UUID, p_lease_seconds INTEGER DEFAULT 900
) RETURNS BOOLEAN AS $$
DECLARE v_count INTEGER;
BEGIN
    UPDATE endpt.build_requests
       SET lease_expires_at=now()+make_interval(secs => GREATEST(p_lease_seconds, 60)), updated_at=now()
     WHERE id=p_build_id AND status='building' AND claim_token=p_claim_token;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE endpt.remote_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id  UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    admin_id     UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    company_id   UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'closed')),
    vnc_token    TEXT,
    novnc_path   TEXT,
    -- Set when the agent reports its side of the pairing failed (see
    -- agent-go/remote.go's reportRelayFailure) — lets the viewer show the
    -- real reason within a few seconds instead of only ever finding out via
    -- ws_proxy's 60s PAIR_TIMEOUT generic "agent did not connect in time".
    fail_reason  TEXT,
    consent_status TEXT NOT NULL DEFAULT 'not_required'
                     CHECK (consent_status IN ('not_required','pending','approved','denied','expired')),
    recording_status TEXT NOT NULL DEFAULT 'none'
                     CHECK (recording_status IN ('none','recording','completed','failed')),
    reconnect_until TIMESTAMPTZ,
    access_mode   TEXT NOT NULL DEFAULT 'full_control'
                     CHECK (access_mode IN ('view_only','full_control','unattended')),
    capabilities JSONB NOT NULL DEFAULT
                     '{"view":true,"control":true,"clipboard":true,"file_transfer":true,"process_manager":true,"reboot":true}'::jsonb,
    reason        TEXT,
    consent_required BOOLEAN NOT NULL DEFAULT FALSE,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at     TIMESTAMPTZ
);
CREATE INDEX idx_remote_sessions_endpoint ON endpt.remote_sessions(endpoint_id, started_at DESC);
CREATE INDEX idx_remote_sessions_token    ON endpt.remote_sessions(vnc_token) WHERE vnc_token IS NOT NULL;
CREATE UNIQUE INDEX idx_remote_sessions_one_active_endpoint
    ON endpt.remote_sessions(endpoint_id) WHERE status = 'active';

CREATE OR REPLACE FUNCTION endpt.create_or_get_remote_session(
    p_endpoint_id UUID, p_company_id UUID, p_admin_id UUID DEFAULT NULL
)
RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_session endpt.remote_sessions%ROWTYPE; v_created BOOLEAN := FALSE;
BEGIN
    PERFORM 1 FROM endpt.endpoints
     WHERE id=p_endpoint_id AND company_id=p_company_id AND is_active=TRUE FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO v_session FROM endpt.remote_sessions
     WHERE endpoint_id=p_endpoint_id AND status='active'
     ORDER BY started_at DESC LIMIT 1;
    IF NOT FOUND THEN
        INSERT INTO endpt.remote_sessions(endpoint_id,admin_id,company_id)
        VALUES(p_endpoint_id,p_admin_id,p_company_id) RETURNING * INTO v_session;
        v_created := TRUE;
    END IF;
    RETURN to_jsonb(v_session)||jsonb_build_object('_created',v_created);
END;
$$;
REVOKE ALL ON FUNCTION endpt.create_or_get_remote_session(UUID,UUID,UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_or_get_remote_session(UUID,UUID,UUID) TO service_role;

CREATE TABLE endpt.remote_session_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES endpt.remote_sessions(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    admin_id UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('note','chat_admin','chat_endpoint','consent','recording','system')),
    body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 4000),
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_remote_session_events_session ON endpt.remote_session_events(session_id, created_at);

CREATE TABLE endpt.remote_support_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    created_by UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 20),
    use_count INTEGER NOT NULL DEFAULT 0,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_remote_support_links_endpoint ON endpt.remote_support_links(endpoint_id, created_at DESC);

CREATE FUNCTION endpt.claim_remote_support_link(p_token_hash text)
RETURNS SETOF endpt.remote_support_links
LANGUAGE sql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
    UPDATE endpt.remote_support_links SET use_count = use_count + 1
    WHERE token_hash = p_token_hash AND revoked_at IS NULL
      AND expires_at > now() AND use_count < max_uses
    RETURNING *;
$$;
REVOKE ALL ON FUNCTION endpt.claim_remote_support_link(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_remote_support_link(text) TO service_role;

CREATE OR REPLACE FUNCTION endpt.release_remote_support_link_claim(p_link_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
BEGIN
    UPDATE endpt.remote_support_links
       SET use_count = use_count - 1
     WHERE id = p_link_id
       AND use_count > 0;
    RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION endpt.release_remote_support_link_claim(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.release_remote_support_link_claim(UUID) TO service_role;

CREATE TABLE endpt.notifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id    UUID NOT NULL REFERENCES endpt.admin_users(id) ON DELETE CASCADE,
    company_id  UUID REFERENCES endpt.companies(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    message     TEXT,
    type        TEXT NOT NULL DEFAULT 'info',
    link        TEXT,
    is_read     BOOLEAN NOT NULL DEFAULT FALSE,
    read_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_notifications_admin_unread ON endpt.notifications(admin_id, is_read, created_at DESC);

-- created_by FKs corrected from the legacy schema's nonexistent endpt.admins(id) to
-- the real endpt.admin_users(id) in both tables below.
CREATE TABLE endpt.compliance_policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id  UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id   UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    checks      JSONB NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_compliance_policies_company ON endpt.compliance_policies(company_id);

CREATE TABLE endpt.compliance_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id     UUID NOT NULL UNIQUE REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    company_id      UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    policy_id       UUID REFERENCES endpt.compliance_policies(id) ON DELETE SET NULL,
    overall_status  TEXT NOT NULL CHECK (overall_status IN ('compliant', 'non_compliant', 'error', 'unknown')),
    score           INTEGER CHECK (score >= 0 AND score <= 100),
    results         JSONB NOT NULL DEFAULT '[]',
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_compliance_results_company ON endpt.compliance_results(company_id);

CREATE TABLE endpt.scheduled_jobs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id        UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id         UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    -- An endpoint-specific schedule must disappear with its endpoint. SET
    -- NULL would silently turn it into a company-wide schedule.
    endpoint_id       UUID REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    job_type          TEXT NOT NULL,
    payload           JSONB NOT NULL DEFAULT '{}',
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    interval_seconds  INTEGER NOT NULL DEFAULT 86400,
    last_run_at       TIMESTAMPTZ,
    next_run_at       TIMESTAMPTZ,
    created_by        UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scheduled_jobs_company  ON endpt.scheduled_jobs(company_id);
CREATE INDEX idx_scheduled_jobs_next_run ON endpt.scheduled_jobs(next_run_at) WHERE enabled = TRUE;

CREATE OR REPLACE FUNCTION endpt.claim_due_scheduled_jobs(p_limit INTEGER DEFAULT 100)
RETURNS SETOF endpt.scheduled_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
BEGIN
    RETURN QUERY
    WITH due AS (
        SELECT s.id
          FROM endpt.scheduled_jobs s
         WHERE s.enabled = TRUE AND s.next_run_at <= now()
         ORDER BY s.next_run_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT LEAST(GREATEST(p_limit, 1), 500)
    )
    UPDATE endpt.scheduled_jobs s
       SET last_run_at = now(),
           next_run_at = now() + make_interval(
               secs => LEAST(GREATEST(s.interval_seconds, 3600), 31536000)
           )
      FROM due
     WHERE s.id = due.id
    RETURNING s.*;
END;
$$;
REVOKE ALL ON FUNCTION endpt.claim_due_scheduled_jobs(INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_due_scheduled_jobs(INTEGER) TO service_role;

-- company_id IS the primary key (not a separate id column): upsert_alert_config
-- POSTs with Prefer: resolution=merge-duplicates and no on_conflict= param, so
-- PostgREST's upsert conflict-detects on the table's primary key — this is
-- what makes "one row per company" work with db.py's existing query.
CREATE TABLE endpt.alert_config (
    company_id       UUID PRIMARY KEY REFERENCES endpt.companies(id) ON DELETE CASCADE,
    cpu_pct          INTEGER NOT NULL DEFAULT 90,
    ram_pct          INTEGER NOT NULL DEFAULT 90,
    disk_free_gb     INTEGER NOT NULL DEFAULT 5,
    offline_minutes  INTEGER NOT NULL DEFAULT 5,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Platform-operator control plane: product rollout, onboarding, incidents and DR evidence.
CREATE TABLE endpt.platform_feature_flags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), key TEXT NOT NULL UNIQUE CHECK (key ~ '^[a-z0-9_]+$'),
    name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL DEFAULT 'alpha' CHECK (stage IN ('alpha','beta','ga','retired')),
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    rollout_percent INTEGER NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100),
    platforms JSONB NOT NULL DEFAULT '["windows"]'::jsonb,
    created_by UUID REFERENCES endpt.admin_users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE endpt.tenant_feature_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), flag_id UUID NOT NULL REFERENCES endpt.platform_feature_flags(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE, enabled BOOLEAN NOT NULL,
    reason TEXT NOT NULL CHECK (length(trim(reason)) >= 3), expires_at TIMESTAMPTZ,
    created_by UUID REFERENCES endpt.admin_users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(flag_id, company_id)
);
CREATE TABLE endpt.tenant_onboarding (
    company_id UUID PRIMARY KEY REFERENCES endpt.companies(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'not_started' CHECK (status IN ('not_started','in_progress','blocked','complete')),
    steps JSONB NOT NULL DEFAULT '{}'::jsonb, owner_id UUID REFERENCES endpt.admin_users(id),
    target_date DATE, notes TEXT NOT NULL DEFAULT '', updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE endpt.platform_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    status TEXT NOT NULL DEFAULT 'investigating' CHECK (status IN ('investigating','identified','monitoring','resolved')),
    affected_tenants JSONB NOT NULL DEFAULT '[]'::jsonb, summary TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES endpt.admin_users(id), resolved_by UUID REFERENCES endpt.admin_users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), resolved_at TIMESTAMPTZ
);
CREATE TABLE endpt.platform_recovery_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_type TEXT NOT NULL CHECK (check_type IN ('database_backup','restore_test','uploads_backup','agent_artifacts','tenant_export','disaster_recovery')),
    status TEXT NOT NULL CHECK (status IN ('passed','warning','failed')), notes TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(), checked_by UUID REFERENCES endpt.admin_users(id)
);
CREATE INDEX platform_incidents_status_idx ON endpt.platform_incidents(status, created_at DESC);
CREATE INDEX recovery_checks_type_time_idx ON endpt.platform_recovery_checks(check_type, checked_at DESC);
CREATE INDEX feature_overrides_company_idx ON endpt.tenant_feature_overrides(company_id);
INSERT INTO endpt.platform_feature_flags (key,name,description,stage,is_enabled,rollout_percent,platforms) VALUES
 ('macos_agent','macOS agent','Cross-platform inventory, jobs and remote capabilities for macOS.','alpha',FALSE,0,'["macos"]'),
 ('linux_agent','Linux agent','Cross-platform inventory, jobs and remote capabilities for Linux.','alpha',FALSE,0,'["linux"]'),
 ('home_nodes','Warden Home Nodes','Tenant-operated peer file services and managed home directories.','alpha',FALSE,0,'["windows","linux"]'),
 ('autopilot_sync','Windows Autopilot sync','Tenant-owned Microsoft Graph integration for zero-touch enrollment.','beta',TRUE,100,'["windows"]'),
 ('packet_capture','Packet capture','Bounded, audited packet capture for endpoint troubleshooting.','beta',TRUE,100,'["windows"]');
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.platform_feature_flags, endpt.tenant_feature_overrides,
    endpt.tenant_onboarding, endpt.platform_incidents, endpt.platform_recovery_checks TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.topology_floors, endpt.topology_rooms,
    endpt.topology_endpoint_placements, endpt.topology_nodes, endpt.topology_links,
    endpt.topology_snapshots TO service_role;

-- Atomic security-sensitive state transitions used by fresh installations.
-- Upgrade installations receive the same definitions from the dated
-- migrations in migrations/.
CREATE OR REPLACE FUNCTION endpt.create_refresh_session(
    p_admin_id UUID, p_token_hash TEXT, p_ip_address TEXT,
    p_user_agent TEXT, p_expires_at TIMESTAMPTZ,
    p_absolute_expires_at TIMESTAMPTZ, p_max_sessions INTEGER
) RETURNS SETOF endpt.refresh_tokens
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, pg_temp AS $$
DECLARE created endpt.refresh_tokens%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_admin_id::text, 0));
    INSERT INTO endpt.refresh_tokens(
        admin_id, token_hash, ip_address, user_agent, expires_at,
        absolute_expires_at, family_id, last_used_at
    ) VALUES (
        p_admin_id, p_token_hash, p_ip_address, left(COALESCE(p_user_agent, ''), 500),
        p_expires_at, p_absolute_expires_at, gen_random_uuid(), now()
    ) RETURNING * INTO created;
    IF p_max_sessions > 0 THEN
        UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
         WHERE id IN (
             SELECT id FROM endpt.refresh_tokens
              WHERE admin_id = p_admin_id AND revoked = FALSE
                AND expires_at > now() AND absolute_expires_at > now()
              ORDER BY last_used_at DESC, created_at DESC OFFSET p_max_sessions
         );
    END IF;
    RETURN NEXT created;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.rotate_refresh_session(
    p_old_token_hash TEXT, p_new_token_hash TEXT,
    p_ip_address TEXT, p_user_agent TEXT,
    p_expires_at TIMESTAMPTZ, p_idle_minutes INTEGER
) RETURNS SETOF endpt.refresh_tokens
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, pg_temp AS $$
DECLARE old_token endpt.refresh_tokens%ROWTYPE;
DECLARE replacement endpt.refresh_tokens%ROWTYPE;
BEGIN
    SELECT * INTO old_token FROM endpt.refresh_tokens
     WHERE token_hash = p_old_token_hash FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    IF old_token.revoked THEN
        UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
         WHERE family_id = old_token.family_id AND revoked = FALSE;
        RETURN;
    END IF;
    IF old_token.expires_at <= now()
       OR old_token.absolute_expires_at <= now()
       OR old_token.last_used_at + make_interval(mins => p_idle_minutes) <= now() THEN
        UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
         WHERE family_id = old_token.family_id AND revoked = FALSE;
        RETURN;
    END IF;
    UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
     WHERE id = old_token.id;
    INSERT INTO endpt.refresh_tokens(
        admin_id, token_hash, ip_address, user_agent, expires_at,
        absolute_expires_at, family_id, last_used_at
    ) VALUES (
        old_token.admin_id, p_new_token_hash, p_ip_address,
        left(COALESCE(p_user_agent, ''), 500),
        LEAST(p_expires_at, old_token.absolute_expires_at),
        old_token.absolute_expires_at, old_token.family_id, now()
    ) RETURNING * INTO replacement;
    RETURN NEXT replacement;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.approve_escalation_request(
    p_request_id UUID, p_admin_id UUID, p_expected_status TEXT,
    p_is_secondary BOOLEAN, p_token_hash TEXT,
    p_token_expires_at TIMESTAMPTZ
) RETURNS SETOF endpt.escalation_requests
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, pg_temp AS $$
DECLARE current_request endpt.escalation_requests%ROWTYPE;
BEGIN
    SELECT * INTO current_request FROM endpt.escalation_requests
     WHERE id = p_request_id FOR UPDATE;
    IF NOT FOUND OR current_request.status <> p_expected_status THEN RETURN; END IF;
    IF current_request.requested_by IS NOT NULL AND current_request.requested_by = p_admin_id THEN
        RAISE EXCEPTION 'requester cannot approve own escalation' USING ERRCODE = '42501';
    END IF;
    IF p_is_secondary AND current_request.reviewed_by = p_admin_id THEN
        RAISE EXCEPTION 'same administrator cannot provide both approvals' USING ERRCODE = '42501';
    END IF;
    IF p_is_secondary THEN
        UPDATE endpt.escalation_requests SET secondary_reviewed_by = p_admin_id,
            secondary_reviewed_at = now(), status = 'approved', escalation_token = p_token_hash,
            token_expires_at = p_token_expires_at WHERE id = p_request_id RETURNING * INTO current_request;
    ELSE
        UPDATE endpt.escalation_requests SET reviewed_by = p_admin_id, reviewed_at = now(),
            status = CASE WHEN requires_dual_approval THEN 'pending_secondary' ELSE 'approved' END,
            escalation_token = p_token_hash, token_expires_at = p_token_expires_at
         WHERE id = p_request_id RETURNING * INTO current_request;
    END IF;
    RETURN NEXT current_request;
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_refresh_session(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION endpt.rotate_refresh_session(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION endpt.approve_escalation_request(UUID, UUID, TEXT, BOOLEAN, TEXT, TIMESTAMPTZ) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_refresh_session(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, INTEGER) TO service_role;
GRANT EXECUTE ON FUNCTION endpt.rotate_refresh_session(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER) TO service_role;
GRANT EXECUTE ON FUNCTION endpt.approve_escalation_request(UUID, UUID, TEXT, BOOLEAN, TEXT, TIMESTAMPTZ) TO service_role;
