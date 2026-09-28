-- Warden Home control plane. File contents travel directly between endpoint
-- agents and tenant-owned storage nodes; this database stores configuration,
-- authorization and audit metadata only.

CREATE TABLE IF NOT EXISTS endpt.home_storage_nodes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    name text NOT NULL,
    deployment_mode text NOT NULL CHECK (deployment_mode IN ('local','public','hybrid','p2p')),
    local_url text,
    public_url text,
    region text,
    failure_domain text,
    storage_cluster_id text,
    priority integer NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 1000),
    tls_fingerprint text,
    ca_certificate_pem text,
    node_public_key text,
    node_key_hash text NOT NULL UNIQUE,
    require_mtls boolean NOT NULL DEFAULT true,
    encrypted_at_rest boolean NOT NULL DEFAULT true,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','online','offline','disabled')),
    capacity_bytes bigint,
    used_bytes bigint,
    last_seen timestamptz,
    capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(company_id,name),
    CONSTRAINT home_storage_nodes_url_required_check
        CHECK (deployment_mode = 'p2p' OR local_url IS NOT NULL OR public_url IS NOT NULL),
    CONSTRAINT home_storage_nodes_public_tls_check
        CHECK (deployment_mode <> 'public' OR (public_url LIKE 'https://%' AND require_mtls))
);
CREATE INDEX IF NOT EXISTS idx_home_nodes_company ON endpt.home_storage_nodes(company_id,status,priority);

ALTER TABLE endpt.home_storage_nodes
    ADD COLUMN IF NOT EXISTS ca_certificate_pem text;

-- Renewable public certificates must not require a fixed leaf fingerprint:
-- the fingerprint changes at every ACME renewal. Public nodes still require
-- HTTPS and mTLS; endpoints always perform CA-chain and hostname validation.
ALTER TABLE endpt.home_storage_nodes
    DROP CONSTRAINT IF EXISTS home_storage_nodes_check;
ALTER TABLE endpt.home_storage_nodes
    DROP CONSTRAINT IF EXISTS home_storage_nodes_check1;
ALTER TABLE endpt.home_storage_nodes
    DROP CONSTRAINT IF EXISTS home_storage_nodes_url_required_check;
ALTER TABLE endpt.home_storage_nodes
    DROP CONSTRAINT IF EXISTS home_storage_nodes_public_tls_check;
ALTER TABLE endpt.home_storage_nodes
    DROP CONSTRAINT IF EXISTS home_storage_nodes_deployment_mode_check;
ALTER TABLE endpt.home_storage_nodes
    ADD CONSTRAINT home_storage_nodes_deployment_mode_check
    CHECK (deployment_mode IN ('local','public','hybrid','p2p'));
ALTER TABLE endpt.home_storage_nodes
    ADD CONSTRAINT home_storage_nodes_url_required_check
    CHECK (deployment_mode = 'p2p' OR local_url IS NOT NULL OR public_url IS NOT NULL);
ALTER TABLE endpt.home_storage_nodes
    ADD CONSTRAINT home_storage_nodes_public_tls_check
    CHECK (deployment_mode <> 'public' OR (public_url LIKE 'https://%' AND require_mtls));

CREATE TABLE IF NOT EXISTS endpt.home_spaces (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    name text NOT NULL,
    space_type text NOT NULL CHECK (space_type IN ('home','shared')),
    remote_prefix_template text NOT NULL DEFAULT 'homes/{identity_id}',
    mappings jsonb NOT NULL DEFAULT '[{"source":"Documents","target":"Documents"}]'::jsonb,
    sync_mode text NOT NULL DEFAULT 'two_way' CHECK (sync_mode IN ('download','upload','two_way')),
    conflict_policy text NOT NULL DEFAULT 'newest_wins' CHECK (conflict_policy IN ('newest_wins','server_wins','keep_both')),
    offline_cache boolean NOT NULL DEFAULT true,
    availability_mode text NOT NULL DEFAULT 'single' CHECK (availability_mode IN ('single','failover','shared_active_active')),
    active_writer_state text,
    quota_bytes bigint CHECK (quota_bytes IS NULL OR quota_bytes>0),
    max_file_bytes bigint NOT NULL DEFAULT 536870912 CHECK (max_file_bytes BETWEEN 1048576 AND 5368709120),
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(company_id,name)
);
CREATE INDEX IF NOT EXISTS idx_home_spaces_company ON endpt.home_spaces(company_id,enabled);

CREATE TABLE IF NOT EXISTS endpt.home_space_nodes (
    space_id uuid NOT NULL REFERENCES endpt.home_spaces(id) ON DELETE CASCADE,
    node_id uuid NOT NULL REFERENCES endpt.home_storage_nodes(id) ON DELETE CASCADE,
    priority integer NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 1000),
    writable boolean NOT NULL DEFAULT true,
    role text NOT NULL DEFAULT 'replica' CHECK (role IN ('primary','failover','replica')),
    PRIMARY KEY(space_id,node_id)
);
ALTER TABLE endpt.home_storage_nodes
    ADD COLUMN IF NOT EXISTS failure_domain text,
    ADD COLUMN IF NOT EXISTS storage_cluster_id text;
ALTER TABLE endpt.home_spaces
    ADD COLUMN IF NOT EXISTS availability_mode text NOT NULL DEFAULT 'single',
    ADD COLUMN IF NOT EXISTS active_writer_state text;
ALTER TABLE endpt.home_spaces DROP CONSTRAINT IF EXISTS home_spaces_availability_mode_check;
ALTER TABLE endpt.home_spaces ADD CONSTRAINT home_spaces_availability_mode_check
    CHECK (availability_mode IN ('single','failover','shared_active_active'));
ALTER TABLE endpt.home_space_nodes ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'replica';
UPDATE endpt.home_space_nodes SET role = CASE WHEN writable THEN 'primary' ELSE 'replica' END
WHERE role = 'replica' AND writable;
ALTER TABLE endpt.home_space_nodes DROP CONSTRAINT IF EXISTS home_space_nodes_role_check;
ALTER TABLE endpt.home_space_nodes ADD CONSTRAINT home_space_nodes_role_check
    CHECK (role IN ('primary','failover','replica'));

CREATE TABLE IF NOT EXISTS endpt.home_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    space_id uuid NOT NULL REFERENCES endpt.home_spaces(id) ON DELETE CASCADE,
    scope_type text NOT NULL CHECK (scope_type IN ('tenant','branch','tag','endpoint','identity')),
    scope_value text,
    access_mode text NOT NULL DEFAULT 'write' CHECK (access_mode IN ('read','write')),
    preferred_node_id uuid REFERENCES endpt.home_storage_nodes(id) ON DELETE SET NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope_type='tenant' AND scope_value IS NULL) OR
           (scope_type<>'tenant' AND length(trim(scope_value))>0))
);
ALTER TABLE endpt.home_assignments
    ADD COLUMN IF NOT EXISTS access_mode text NOT NULL DEFAULT 'write';
ALTER TABLE endpt.home_assignments
    DROP CONSTRAINT IF EXISTS home_assignments_scope_type_check;
ALTER TABLE endpt.home_assignments
    DROP CONSTRAINT IF EXISTS home_assignments_access_mode_check;
ALTER TABLE endpt.home_assignments
    ADD CONSTRAINT home_assignments_scope_type_check
    CHECK (scope_type IN ('tenant','branch','tag','endpoint','identity'));
ALTER TABLE endpt.home_assignments
    ADD CONSTRAINT home_assignments_access_mode_check
    CHECK (access_mode IN ('read','write'));
CREATE INDEX IF NOT EXISTS idx_home_assignments_scope
    ON endpt.home_assignments(company_id,scope_type,scope_value) WHERE enabled;
CREATE UNIQUE INDEX IF NOT EXISTS idx_home_assignments_unique_enabled
    ON endpt.home_assignments(company_id,space_id,scope_type,COALESCE(scope_value,'')) WHERE enabled;

CREATE TABLE IF NOT EXISTS endpt.home_access_log (
    id bigserial PRIMARY KEY,
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    endpoint_id uuid REFERENCES endpt.endpoints(id) ON DELETE SET NULL,
    identity_id uuid REFERENCES endpt.warden_identities(id) ON DELETE SET NULL,
    space_id uuid REFERENCES endpt.home_spaces(id) ON DELETE SET NULL,
    node_id uuid REFERENCES endpt.home_storage_nodes(id) ON DELETE SET NULL,
    action text NOT NULL,
    bytes_transferred bigint,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_home_access_company ON endpt.home_access_log(company_id,created_at DESC);

GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.home_storage_nodes TO service_role;
GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.home_spaces TO service_role;
GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.home_space_nodes TO service_role;
GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.home_assignments TO service_role;
GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.home_access_log TO service_role;
GRANT USAGE,SELECT ON SEQUENCE endpt.home_access_log_id_seq TO service_role;

NOTIFY pgrst, 'reload schema';
