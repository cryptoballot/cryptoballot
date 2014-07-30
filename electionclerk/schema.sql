CREATE TABLE fulfilled_signature_requests_<election-id> (
  request_id char(128) NOT NULL,  --@@TODO: change to 64 on move to SHA256
  public_key text NOT NULL, 
  ballot_hash char(128) NOT NULL, --@@TODO: change to 64 on move to SHA256
  signature text NOT NULL,
  ballot_signature text NOT NULL,
);

CREATE INDEX request_id_idx ON ballots (ballot_id);
CREATE INDEX public_key_idx ON ballots (public_key);
