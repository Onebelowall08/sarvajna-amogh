CREATE DATABASE IF NOT EXISTS sarvajna;

-- One row per alert emitted by the correlator.
--
-- enrich_retries / enrich_delay_s / enforce_revocation are stamped by the
-- harness on every row. Earlier suites recorded the Tetragon enrichment
-- setting only in the cell name of the enrichment sweep, so for every other
-- cell the setting in force could not be recovered after the fact.
CREATE TABLE IF NOT EXISTS sarvajna.detections (
  run_id             String,
  config             LowCardinality(String),
  concurrency        UInt16,
  window_ms          UInt32,
  enrich_retries     UInt8,
  enrich_delay_s     UInt8,
  enforce_revocation UInt8,
  attack_id          Nullable(String),
  trace_id           Nullable(String),
  alert_type         LowCardinality(String),
  correlated         UInt8,
  join_mode          LowCardinality(String),
  matched_on         LowCardinality(String),
  user_id            Nullable(String),
  tenant_id          Nullable(String),
  pod_name           String,
  tier               UInt8,
  action_type        LowCardinality(String),
  action_ok          UInt8,
  action_err         Nullable(String),
  t_app_emit         Nullable(DateTime64(6)),
  t_kernel           DateTime64(6),
  t_kernel_true      Nullable(DateTime64(6)),
  t_collector        Nullable(DateTime64(6)),
  t_correlate        DateTime64(6),
  t_soar_in          DateTime64(6),
  t_action           DateTime64(6),
  t_enforced         Nullable(DateTime64(6)),
  mttr_ms            Float64,
  mttr_e2e_ms        Nullable(Float64),
  mttr_app_ms        Nullable(Float64),
  mttr_pipeline_ms   Nullable(Float64)
) ENGINE = MergeTree
ORDER BY (run_id, t_kernel);

-- One row per request issued by the workload generator.
--
-- http_status and blocked are written by the generator after the response
-- returns. blocked = 1 means the request was rejected because its principal
-- had been revoked, which is how collateral damage is counted.
CREATE TABLE IF NOT EXISTS sarvajna.ground_truth (
  run_id       String,
  attack_id    String,
  label        Enum8('benign' = 0, 'attack' = 1),
  attack_type  LowCardinality(String),
  user_id      String,
  tenant_id    String DEFAULT '',
  payload      String,
  victim_user  String DEFAULT '',
  victim_trace String DEFAULT '',
  http_status  UInt16 DEFAULT 0,
  blocked      UInt8  DEFAULT 0,
  t_sent       DateTime64(6)
) ENGINE = MergeTree
ORDER BY (run_id, t_sent);

-- One row per user-scoped response action. Separate from detections because
-- the question "who did the system act against" must be answerable without
-- reference to whether the attribution was correct.
CREATE TABLE IF NOT EXISTS sarvajna.revocations (
  run_id           String,
  attack_id        Nullable(String),
  trace_id         Nullable(String),
  alert_type       LowCardinality(String),
  principal_user   String,
  principal_tenant String,
  enforced         UInt8,
  action_ok        UInt8,
  action_err       Nullable(String),
  t_action         DateTime64(6)
) ENGINE = MergeTree
ORDER BY (run_id, t_action);

CREATE TABLE IF NOT EXISTS sarvajna.raw_telemetry (
  ingest_time    DateTime64(6),
  event_time     DateTime64(6),
  app_time       Nullable(DateTime64(6)),
  kernel_time    Nullable(DateTime64(6)),
  collector_time Nullable(DateTime64(6)),
  runtime_time   Nullable(DateTime64(6)),
  source         LowCardinality(String),
  event_type     LowCardinality(String),
  pod_name       String,
  trace_id       String,
  attack_id      String,
  raw_payload    String
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ingest_time)
ORDER BY (event_time, pod_name)
TTL toDateTime(ingest_time) + INTERVAL 14 DAY;
