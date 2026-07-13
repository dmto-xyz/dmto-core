-- Total value issued per denomination, for supply accounting. Redeemed value is
-- derived from spent_secret; outstanding = issued - redeemed.
CREATE TABLE issued_total (
    value BIGINT PRIMARY KEY,
    total BIGINT NOT NULL DEFAULT 0
);
