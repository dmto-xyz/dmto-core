-- The mint's per-denomination signing keys, so the keyset id is stable across
-- restarts. Private keys are stored as raw 32-byte secp256k1 scalars.
CREATE TABLE mint_key (
    value   BIGINT PRIMARY KEY,
    privkey BYTEA  NOT NULL
);

-- Spent note secrets, for double-spend prevention. Populated in a later slice
-- when the spend path becomes database-backed.
CREATE TABLE spent_secret (
    secret   BYTEA       PRIMARY KEY,
    value    BIGINT      NOT NULL,
    spent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
