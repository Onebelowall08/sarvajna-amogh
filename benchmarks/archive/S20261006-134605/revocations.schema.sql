CREATE TABLE sarvajna.revocations
(
    `run_id` String,
    `attack_id` Nullable(String),
    `trace_id` Nullable(String),
    `alert_type` LowCardinality(String),
    `principal_user` String,
    `principal_tenant` String,
    `enforced` UInt8,
    `action_ok` UInt8,
    `action_err` Nullable(String),
    `t_action` DateTime64(6)
)
ENGINE = MergeTree
ORDER BY (run_id, t_action)
SETTINGS index_granularity = 8192
