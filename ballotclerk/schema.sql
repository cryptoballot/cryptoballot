CREATE EXTENSION IF NOT EXISTS hstore;

CREATE TABLE ballots (
  ballot_id char(128) NOT NULL, 
  public_key text NOT NULL, 
  tags hstore, 
  ballot text NOT NULL
);

CREATE INDEX ballot_id_idx ON ballots (ballot_id);
CREATE INDEX public_key_idx ON ballots (public_key);
CREATE INDEX tags_idx on ballots (tags);