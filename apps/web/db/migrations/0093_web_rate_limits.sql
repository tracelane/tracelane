-- Durable fixed-window abuse counters. Only SHA-256 key digests are persisted.
CREATE TABLE IF NOT EXISTS web_rate_limits (
    key_hash bytea NOT NULL,
    window_start timestamptz NOT NULL,
    count integer NOT NULL,
    PRIMARY KEY (key_hash, window_start)
);
CREATE INDEX IF NOT EXISTS web_rate_limits_window_start_idx
    ON web_rate_limits (window_start);
