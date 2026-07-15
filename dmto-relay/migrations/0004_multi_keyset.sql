-- Let one relay host multiple mints (issuers/keysets), each identified by a
-- text `label`. Existing rows become the 'primary' mint.

ALTER TABLE mint_key ADD COLUMN label TEXT NOT NULL DEFAULT 'primary';
ALTER TABLE mint_key DROP CONSTRAINT mint_key_pkey, ADD PRIMARY KEY (label, value);

ALTER TABLE spent_secret ADD COLUMN label TEXT NOT NULL DEFAULT 'primary';
ALTER TABLE spent_secret DROP CONSTRAINT spent_secret_pkey, ADD PRIMARY KEY (label, secret);

ALTER TABLE issued_total ADD COLUMN label TEXT NOT NULL DEFAULT 'primary';
ALTER TABLE issued_total DROP CONSTRAINT issued_total_pkey, ADD PRIMARY KEY (label, value);

-- issuer_key was a single-row table; make it per-label.
DROP TABLE issuer_key;
CREATE TABLE issuer_key (
    label   TEXT  PRIMARY KEY,
    privkey BYTEA NOT NULL
);
