use super::*;
use uuid::Uuid;

#[test]
fn basic_end_to_end_election() {
    // Create an authenticator
    let (authenticator, authn_secret) = Authenticator::new();

    // Create a ballot (TODO: make this a proper struct)
    let ballot_id = Uuid::new_v4();

    // Create an election transaction with a trusted public-key and a single ballot
    let mut election = ElectionTransaction::default();
    let (election_secret, election_public) = ecies::utils::generate_keypair();
    election.public_key = election_public.serialize().to_vec();
    election.ballots = vec![ballot_id];
    election.authenticators = vec![authenticator.clone()];

    // Validate the election transaction
    election.validate().unwrap();

    // Generate keypairs for the voter
    let (voter_secret, voter_public) = generate_keypair();

    // Authenticate the voter (for a real election the voter would pass additional auth info)
    let authentication = authenticator
        .authenticate(&authn_secret, election.id, ballot_id, &voter_public)
        .unwrap();

    // Create a vote transaction
    let secret_vote = "Barak Obama";

    // Encrypt the secret vote
    let encrypted_vote = encrypt_vote(&election.public_key, secret_vote.as_bytes()).unwrap();

    let vote = VoteTransaction {
        id: Uuid::new_v4(),
        election: election.id,
        encrypted_vote: encrypted_vote,
        ballot_id: ballot_id,
        public_key: voter_public,
        authentication: vec![authentication],
    };

    // Validate the vote transaction
    vote.validate(&election).unwrap();

    // Election is over
    // ----------------

    // Recover election key from trustees  -- TODO
    let election_key = election_secret.serialize();

    // Decrypt the votes
    let decrypted_vote = decrypt_vote(&election_key, &vote.encrypted_vote).unwrap();

    // Create decryption transaction
    let decryption = DecryptionTransaction::new(&vote, decrypted_vote);

    // Validate decryption transaction
    decryption.validate().unwrap();

    // TODO: tally!
}
