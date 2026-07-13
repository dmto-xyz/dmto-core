-- The relay's issuer identity: a single stable keypair. Only one row is allowed,
-- so the issuer id is stable across restarts.
CREATE TABLE issuer_key (
    singleton BOOLEAN PRIMARY KEY DEFAULT true,
    privkey   BYTEA   NOT NULL,
    CHECK (singleton)
);
