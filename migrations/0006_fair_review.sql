
-- Fair-review / dispute metadata for durable tasks. Nullable so every
-- pre-existing row remains valid without a data rewrite.
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS dispute_reason TEXT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS dispute_opened_at BIGINT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS dispute_opened_by BIGINT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS dispute_deadline BIGINT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS resolution_notes TEXT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS resolution_outcome TEXT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS resolved_at BIGINT;
ALTER TABLE tasks_pg ADD COLUMN IF NOT EXISTS resolved_by BIGINT;

INSERT INTO schema_migrations (version, applied_at)
SELECT 6, EXTRACT(EPOCH FROM NOW())::BIGINT
WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 6);
