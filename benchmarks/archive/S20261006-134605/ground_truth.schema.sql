CREATE TABLE sarvajna.ground_truth
(
    `run_id` String,
    `attack_id` String,
    `label` Enum8('benign' = 0, 'attack' = 1),
    `attack_type` LowCardinality(String),
    `user_id` String,
    `tenant_id` String DEFAULT '',
    `payload` String,
    `victim_user` String DEFAULT '',
    `victim_trace` String DEFAULT '',
    `http_status` UInt16 DEFAULT 0,
    `blocked` UInt8 DEFAULT 0,
    `t_sent` DateTime64(6)
)
ENGINE = MergeTree
ORDER BY (run_id, t_sent)
SETTINGS index_granularity = 8192
