use super::*;
use uuid::Uuid;

#[test]
fn end_to_end_election() {
    // Create an authenticator
    let (authenticator, authn_secret) = Authenticator::new();

    // Create 3 trustees
    let (trustee_1, trustee_1_secret) = Trustee::new();
    let (trustee_2, trustee_2_secret) = Trustee::new();
    let (trustee_3, trustee_3_secret) = Trustee::new();

    // Create a ballot (TODO: make this a proper struct)
    let ballot_id = Uuid::new_v4();

    // Create an election transaction with a single ballot
    let (mut election, election_secret) = ElectionTransaction::new();
    election.ballots = vec![ballot_id];
    election.authenticators = vec![authenticator.clone()];
    election.trustees = vec![trustee_1.clone(), trustee_2.clone(), trustee_3.clone()];

    // Deal the secret shares to the trustees
    let mut shares = deal_secret_shares(
        election.trustees_threshold,
        election.trustees.len(),
        &election_secret.serialize(),
    );
    let trustee_1_share = shares.pop().unwrap();
    let trustee_2_share = shares.pop().unwrap();

    // TODO: In the future, don't rely on a trusted dealer, instead do verifiable distributed key generation using ElGamal

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

    // Publish SecretShare transactions
    let secret_share_1 = SecretShareTransaction::new(election.id, trustee_1, trustee_1_share);
    let secret_share_2 = SecretShareTransaction::new(election.id, trustee_2, trustee_2_share);

    // Validate SecretShare transactions
    secret_share_1.validate(&election).unwrap();
    secret_share_2.validate(&election).unwrap();

    // Recover election key from two trustees
    let shares = vec![secret_share_1.secret_share, secret_share_2.secret_share];
    let election_key = recover_secret_shares(election.trustees_threshold, shares).unwrap();

    // Decrypt the votes
    let decrypted_vote = decrypt_vote(&election_key, &vote.encrypted_vote).unwrap();

    // Create decryption transaction
    let decryption = DecryptionTransaction::new(election.id, vote.id, decrypted_vote);

    // Validate decryption transaction
    decryption.validate().unwrap();

    // TODO: tally!
}
