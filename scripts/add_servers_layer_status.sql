-- Runtime status columns for servers (Angelos + L4 Sparta + L7 Athens).
-- Safe to run multiple times on existing databases.

-- Angelos orchestrator status (Status column in UI) — may already exist from add_servers_service_status.sql
SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'servers' AND COLUMN_NAME = 'service_status'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE servers ADD COLUMN service_status VARCHAR(32) NULL DEFAULT NULL AFTER status',
  'SELECT ''service_status already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- L4 layer (sparta.service)
SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'servers' AND COLUMN_NAME = 'l4_status'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE servers ADD COLUMN l4_status VARCHAR(32) NULL DEFAULT NULL AFTER service_status',
  'SELECT ''l4_status already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- L7 layer (athens.service)
SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'servers' AND COLUMN_NAME = 'l7_status'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE servers ADD COLUMN l7_status VARCHAR(32) NULL DEFAULT NULL AFTER l4_status',
  'SELECT ''l7_status already exists'' AS note'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
