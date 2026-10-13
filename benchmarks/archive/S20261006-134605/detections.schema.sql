CREATE TABLE sarvajna.detections
(
    `run_id` String,
    `config` LowCardinality(String),
    `concurrency` UInt16,
    `window_ms` UInt32,
    `enrich_retries` UInt8,
    `enrich_delay_s` UInt8,
    `enforce_revocation` UInt8,
    `attack_id` Nullable(String),
    `trace_id` Nullable(String),
    `alert_type` LowCardinality(String),
    `correlated` UInt8,
    `join_mode` LowCardinality(String),
    `matched_on` LowCardinality(String),
    `user_id` Nullable(String),
    `tenant_id` Nullable(String),
    `pod_name` String,
    `tier` UInt8,
    `action_type` LowCardinality(String),
    `action_ok` UInt8,
    `action_err` Nullable(String),
    `t_app_emit` Nullable(DateTime64(6)),
    `t_kernel` DateTime64(6),
    `t_kernel_true` Nullable(DateTime64(6)),
    `t_collector` Nullable(DateTime64(6)),
    `t_correlate` DateTime64(6),
    `t_soar_in` DateTime64(6),
    `t_action` DateTime64(6),
    `t_enforced` Nullable(DateTime64(6)),
    `mttr_ms` Float64,
    `mttr_e2e_ms` Nullable(Float64),
    `mttr_app_ms` Nullable(Float64),
    `mttr_pipeline_ms` Nullable(Float64)
)
ENGINE = MergeTree
ORDER BY (run_id, t_kernel)
SETTINGS index_granularity = 8192
