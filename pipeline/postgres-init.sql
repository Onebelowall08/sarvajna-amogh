-- Revocation list. The application polls this; the response worker writes it.
--
-- principal is the user identifier the correlator attributed the alert to.
-- Under forgery that is the victim's identifier, not the attacker's, which is
-- the entire point of the measurement.
CREATE TABLE IF NOT EXISTS revocations (
  principal_user   TEXT PRIMARY KEY,
  principal_tenant TEXT        NOT NULL DEFAULT '',
  run_id           TEXT        NOT NULL DEFAULT '',
  alert_type       TEXT        NOT NULL DEFAULT '',
  revoked_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS revocations_run_idx ON revocations (run_id);
