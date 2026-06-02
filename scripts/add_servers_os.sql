-- Target OS for the deployed Dorian payload (e.g. ubuntu-22.04), set at server create.
ALTER TABLE servers
  ADD COLUMN os VARCHAR(64) NULL DEFAULT NULL
  AFTER version;
