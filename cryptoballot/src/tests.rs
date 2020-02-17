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

    // Generate an empty vote transaction
    let (mut vote, voter_secret) = VoteTransaction::new(election.id, ballot_id);

    // Authenticate the voter (for a real election the voter would pass additional auth info)
    let authentication =
        authenticator.authenticate(&authn_secret, election.id, ballot_id, &vote.public_key);
    vote.authentication.push(authentication);

    // Create a  vote transaction
    let secret_vote = "Barak Obama";

    // Encrypt the secret vote
    vote.encrypted_vote = encrypt_vote(&election.public_key, secret_vote.as_bytes()).unwrap();

    // Validate the vote transaction
    vote.validate(&election).unwrap();

    // Election is over
    // ----------------

    // Recover election key from trustees  -- TODO
    let election_key = election_secret.serialize();

    // Decrypt the votes
    let decrypted_vote = decrypt_vote(&election_key, &vote.encrypted_vote).unwrap();

    // Create decryption transaction
    let decryption = DecryptionTransaction::new(election.id, vote.id, decrypted_vote);

    // Validate decryption transaction
    decryption.validate().unwrap();

    // TODO: tally!
}
