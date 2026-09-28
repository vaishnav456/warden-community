BEGIN;

ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS interactive_user text,
    ADD COLUMN IF NOT EXISTS interactive_session_seen_at timestamptz;

CREATE TABLE IF NOT EXISTS endpt.topology_floors (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id uuid REFERENCES endpt.branches(id) ON DELETE SET NULL,
    building text NOT NULL DEFAULT 'Main building',
    name text NOT NULL,
    level_order integer NOT NULL DEFAULT 0,
    aspect_ratio numeric(6,3) NOT NULL DEFAULT 1.778 CHECK (aspect_ratio BETWEEN 0.5 AND 4),
    layout_locked boolean NOT NULL DEFAULT false,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(company_id, building, name)
);
CREATE INDEX IF NOT EXISTS idx_topology_floors_company ON endpt.topology_floors(company_id, level_order, name);

CREATE TABLE IF NOT EXISTS endpt.topology_rooms (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id uuid NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    name text NOT NULL,
    x numeric(7,3) NOT NULL CHECK (x BETWEEN 0 AND 100),
    y numeric(7,3) NOT NULL CHECK (y BETWEEN 0 AND 100),
    width numeric(7,3) NOT NULL CHECK (width BETWEEN 3 AND 100),
    height numeric(7,3) NOT NULL CHECK (height BETWEEN 3 AND 100),
    color text NOT NULL DEFAULT '#DCE9FF',
    capacity integer CHECK (capacity IS NULL OR capacity >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(floor_id, name)
);
CREATE INDEX IF NOT EXISTS idx_topology_rooms_floor ON endpt.topology_rooms(floor_id);

CREATE TABLE IF NOT EXISTS endpt.topology_endpoint_placements (
    endpoint_id uuid PRIMARY KEY REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id uuid NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    room_id uuid REFERENCES endpt.topology_rooms(id) ON DELETE SET NULL,
    x numeric(7,3) NOT NULL CHECK (x BETWEEN 0 AND 100),
    y numeric(7,3) NOT NULL CHECK (y BETWEEN 0 AND 100),
    updated_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_topology_placements_floor ON endpt.topology_endpoint_placements(floor_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.topology_floors TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.topology_rooms TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.topology_endpoint_placements TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
