BEGIN;
CREATE TABLE IF NOT EXISTS endpt.topology_nodes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id uuid NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    room_id uuid REFERENCES endpt.topology_rooms(id) ON DELETE SET NULL,
    node_type text NOT NULL CHECK (node_type IN ('switch','firewall','router','server','access_point','printer','asset')),
    name text NOT NULL, ip_address text, details text,
    x numeric(7,3) NOT NULL CHECK (x BETWEEN 0 AND 100), y numeric(7,3) NOT NULL CHECK (y BETWEEN 0 AND 100),
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_topology_nodes_floor ON endpt.topology_nodes(floor_id);
CREATE TABLE IF NOT EXISTS endpt.topology_links (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id uuid NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    source_type text NOT NULL CHECK (source_type IN ('endpoint','node')), source_id uuid NOT NULL,
    target_type text NOT NULL CHECK (target_type IN ('endpoint','node')), target_id uuid NOT NULL,
    link_type text NOT NULL DEFAULT 'ethernet' CHECK (link_type IN ('ethernet','fiber','wifi','vpn','logical')),
    label text, status text NOT NULL DEFAULT 'unknown' CHECK (status IN ('active','inactive','degraded','unknown')),
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (NOT (source_type = target_type AND source_id = target_id)),
    UNIQUE(floor_id, source_type, source_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_topology_links_floor ON endpt.topology_links(floor_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.topology_nodes TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.topology_links TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
