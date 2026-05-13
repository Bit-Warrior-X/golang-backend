-- Deploy/runtime summary from create_server (deployed | running | stopped).
-- Keeps `status` as the existing operational ENUM (e.g. Normal, Pause, Expired).
ALTER TABLE servers
  ADD COLUMN service_status VARCHAR(32) NULL DEFAULT NULL
  AFTER status;
