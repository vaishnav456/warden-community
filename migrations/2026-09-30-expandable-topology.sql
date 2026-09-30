BEGIN;
-- Preserve all existing layouts and permit expansion on every side.
ALTER TABLE endpt.topology_rooms
    DROP CONSTRAINT IF EXISTS topology_rooms_x_check,
    DROP CONSTRAINT IF EXISTS topology_rooms_y_check,
    DROP CONSTRAINT IF EXISTS topology_rooms_width_check,
    DROP CONSTRAINT IF EXISTS topology_rooms_height_check,
    DROP CONSTRAINT IF EXISTS topology_rooms_extent_check,
    ADD CHECK (x BETWEEN -9000 AND 9000),
    ADD CHECK (y BETWEEN -9000 AND 9000),
    ADD CHECK (width BETWEEN 3 AND 9000),
    ADD CHECK (height BETWEEN 3 AND 9000),
    ADD CONSTRAINT topology_rooms_extent_check CHECK (x + width <= 9000 AND y + height <= 9000);
ALTER TABLE endpt.topology_endpoint_placements
    DROP CONSTRAINT IF EXISTS topology_endpoint_placements_x_check,
    DROP CONSTRAINT IF EXISTS topology_endpoint_placements_y_check,
    ADD CHECK (x BETWEEN -9000 AND 9000),
    ADD CHECK (y BETWEEN -9000 AND 9000);
ALTER TABLE endpt.topology_nodes
    DROP CONSTRAINT IF EXISTS topology_nodes_x_check,
    DROP CONSTRAINT IF EXISTS topology_nodes_y_check,
    ADD CHECK (x BETWEEN -9000 AND 9000),
    ADD CHECK (y BETWEEN -9000 AND 9000);
NOTIFY pgrst, 'reload schema';
COMMIT;
