CREATE TABLE tx (
    id TEXT PRIMARY KEY,
    election_id TEXT NOT NULL,
    tx_type TEXT NOT NULL,
    tx_value TEXT NOT NULL
);

CREATE INDEX idx_tx_tx_type ON tx(tx_type);
CREATE INDEX idx_tx_election_id ON tx(election_id);
CREATE INDEX idx_tx_election_id_tx_type ON tx(election_id, tx_type);
