CREATE EXTENSION IF NOT EXISTS hstore;

CREATE TABLE ballots_<election-id> (
  ballot_id char(128) NOT NULL, --@@TODO: change to 64 on move to SHA256
  tags hstore, 
  ballot text NOT NULL
);

CREATE INDEX ballot_id_idx ON ballots_<election-id> (ballot_id);
CREATE INDEX tags_idx on ballots_<election-id> (tags);