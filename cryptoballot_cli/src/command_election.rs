use super::expand;
use cryptoballot::Authenticator;
use cryptoballot::ElectionTransaction;
use cryptoballot::Signed;
use cryptoballot::Trustee;
use std::fs::read_to_string;

pub fn command_election(matches: &clap::ArgMatches) {
    // Subcommands
    if let Some(matches) = matches.subcommand_matches("generate") {
        command_election_generate(matches);
        std::process::exit(0);
    }
}

pub fn command_election_generate(matches: &clap::ArgMatches) {
    // Unwraps are OK, both these args are required
    // TODO: Multiple
    let authn_file = expand(matches.value_of("authn-file").unwrap());
    let trustee_file = expand(matches.value_of("trustee-file").unwrap());

    let authn: Authenticator = serde_json::from_str(&read_to_string(authn_file).unwrap()).unwrap();
    let trustee: Trustee = serde_json::from_str(&read_to_string(trustee_file).unwrap()).unwrap();

    // TODO: Create election authority key-pair seperately and pass them in
    let (authority_secret, authority_public) = cryptoballot::generate_keypair();

    // Create an election transaction with a single ballot
    let mut election = ElectionTransaction::new(authority_public);

    // TODO: Split secret key and deal it to tustees
    election.ballots = vec![uuid::Uuid::nil()];

    // TODO: Multiple authn
    election.authenticators = vec![authn];

    // TODO: Multiple trustees
    election.trustees = vec![trustee];

    //  Turn it into a signed transaction
    let election_tx = Signed::sign(&authority_secret, election).unwrap();

    // Serialize it and print it
    let election_tx = serde_json::to_string_pretty(&election_tx).unwrap();
    println!("{}", election_tx);
}
