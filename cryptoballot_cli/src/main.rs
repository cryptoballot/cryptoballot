use clap::AppSettings;
use clap::{App, Arg, SubCommand};
use cryptoballot::*;
use ed25519_dalek::SecretKey;

mod command_authn;
mod command_e2e;
mod command_election;
mod command_keygen;
mod command_post_transaction;
mod command_trustee;
mod command_vote;
mod command_voting_end;
mod rest;

fn main() {
    let mut app = App::new("CryptoBallot")
        .version("1.0")
        .author("Patrick Hayes <patrick.d.hayes@gmail.com>")
        .about("CryptoBallot command-line tool")
        .arg(
            Arg::with_name("uri")
                .help("Set the cryptoballot uri - can also be set with CRYPTOBALLOT_URI")
                .required(false),
        )
        .arg(
            Arg::with_name("secret-key")
                .help("Set the cryptoballot secret-key - can also be set with CRYPTOBALLOT_SECRET_KEY")
                .required(false),
        )
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(SubCommand::with_name("keygen").about("Generate keypair"))
        .subcommand(
            SubCommand::with_name("sign")
                .setting(AppSettings::ArgRequiredElseHelp)
                .about("Sign transaction")
                .arg(
                    Arg::with_name("INPUT")
                        .index(1)
                        .required(true) // TODO: allow stdin
                        .help("Transaction file in JSON or CBOR format"),
                )
                .arg(
                    Arg::with_name("secret")
                        .long("secret")
                        .takes_value(true)
                        .help("Secret ed25519 key file location in hex format")
                        .required(true), // TODO: allow environment variable && PEM format
                ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("GET transaction")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("id")
                        .index(1)
                        .required(true) // TODO: allow stdin
                        .help("Get Transaction by ID"),
                )
                .arg(
                    Arg::with_name("pretty")
                        .long("pretty")
                        .help("Pretty print JSON"),
                ),
        )
        .subcommand(
            SubCommand::with_name("post")
                .about("Post transaction")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("INPUT")
                        .index(1)
                        .required(true) // TODO: allow stdin
                        .help("Transaction file in JSON or CBOR format"),
                ),
        )
        .subcommand(
            SubCommand::with_name("tally")
                .about("Tally Election")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("election-id")
                        .index(1)
                        .required(true) // TODO: allow stdin
                        .help("Tally votes in an election to get a winner"),
                ),
        )
        .subcommand(
            SubCommand::with_name("e2e")
                .about("End-to-End Election Verification")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("ELECTION-ID")
                        .index(1)
                        .required(true) 
                        .help("Election ID"),
                )
                .arg(
                    Arg::with_name("print-votes")
                        .long("print-votes")
                        .help("Print all the recorded votes"),
                )
                .arg(
                    Arg::with_name("print-tally")
                        .long("print-tally")
                        .help("Print the tally"),
                )
                .arg(
                    Arg::with_name("print-results")
                        .long("print-results")
                        .help("Print the election results"),
                ),
        )
        .subcommand(
            SubCommand::with_name("trustee")
                .about("Trustee related commands")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .about("Generate new trustee")
                        .arg(
                            Arg::with_name("secret")
                                .long("secret")
                                .help("File location to write secret key")
                                .takes_value(true)
                                .required(true), // TODO: allow PEM format with password
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("authn")
                .about("Authenticator related commands")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .about("Generate new authenticator")
                        .arg(
                            Arg::with_name("secret")
                                .long("secret")
                                .help("File location to write secret keys")
                                .takes_value(true)
                                .required(true), // TODO: allow PEM format with password
                        )
                        .arg(
                            Arg::with_name("keysize")
                                .long("keysize")
                                .help("Length of RSA key, anything less than 2048 is insecure")
                                .takes_value(true)
                                .default_value("4096"),
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("election")
                .about("Election related commands")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .about("Generate new election")
                        .arg(
                            Arg::with_name("post")
                                .long("post")
                                .help("Post the transaction")
                                .takes_value(false)
                                .required(false),
                        )
                ),
        )
        .subcommand(
            SubCommand::with_name("voting_end")
                .about("Voting End commands")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .about("End voting on an election with a voting_end transaction")
                        .arg(
                            Arg::with_name("ELECTION-ID")
                                .index(1)
                                .required(true)
                                .help("election identifier"),
                        )
                        .arg(
                            Arg::with_name("post")
                                .long("post")
                                .help("Post the transaction")
                                .takes_value(false)
                                .required(false),
                        )
                ),
        )
        .subcommand(
            SubCommand::with_name("vote")
                .about("Voter related commands")
                .setting(AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    SubCommand::with_name("generate")
                        .about("Generate new vote")
                        .arg(
                            Arg::with_name("ELECTION-ID")
                                .index(1)
                                .required(true)
                                .help("election identifier"),
                        )
                        .arg(
                            Arg::with_name("VOTE")
                                .index(2)
                                .required(true)
                                .help("vote payload value"),
                        )
                        .arg(
                            Arg::with_name("post")
                                .long("post")
                                .help("Post the transaction")
                                .takes_value(false)
                                .required(false),
                        )
                ),
        );

    let matches = app.clone().get_matches();

    // Gets a value for config if supplied by user
    let env_var = std::env::var("CRYPTOBALLOT_URI");
    let uri = match matches.value_of("uri") {
        Some(uri) => uri.to_string(),
        None => env_var.unwrap_or("http://localhost:8080".to_string()),
    };

    // Gets a value for config if supplied by user
    let env_var = std::env::var("CRYPTOBALLOT_SECRET_KEY");
    let secret_key = match matches.value_of("secret-key") {
        Some(key) => Some(key.to_string()),
        None => match env_var {
            Ok(key) => Some(key),
            Err(_) => None,
        },
    };
    let secret_key = secret_key.map(|key| {
        let bytes = hex::decode(key).unwrap_or_else(|e| {
            eprintln!("Invalid secret key: {}", e);
            std::process::exit(1);
        });
        let secret_key = SecretKey::from_bytes(&bytes).unwrap_or_else(|e| {
            eprintln!("Invalid secret key: {}", e);
            std::process::exit(1);
        });

        secret_key
    });

    // Subcommands
    if let Some(matches) = matches.subcommand_matches("post") {
        command_post_transaction::command_post_transaction(matches, &uri, secret_key.as_ref());
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("keygen") {
        command_keygen::command_keygen(matches);
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("sign") {
        command_sign_transaction(matches);
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("get") {
        command_get_transaction(matches, &uri);
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("tally") {
        command_tally(matches, &uri);
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("e2e") {
        command_e2e::command_e2e(matches, &uri);
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("trustee") {
        command_trustee::command_trustee(matches);
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("authn") {
        command_authn::command_authn(matches);
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("election") {
        command_election::command_election(matches, &uri, secret_key.as_ref());
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("vote") {
        command_vote::command_vote(matches, &uri, secret_key.as_ref());
        std::process::exit(0);
    }
    if let Some(matches) = matches.subcommand_matches("voting_end") {
        command_voting_end::command_voting_end(matches, &uri, secret_key.as_ref());
        std::process::exit(0);
    }

    // No command, just print help
    app.print_help().expect("Unable to print help message");
    println!(""); // Trailing linebreak
}

fn command_sign_transaction(matches: &clap::ArgMatches) {
    // Unwraps OK - required args
    let filename = expand(matches.value_of("algorithim").unwrap());
    let secret_location = expand(matches.value_of("secret").unwrap());

    let file_bytes = match std::fs::read(&filename) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("cryptoballot post: unable to read {}: {}, ", &filename, e);
            std::process::exit(1);
        }
    };

    // TODO: FINISH THIS
    let _tx = cryptoballot::Transaction::from_bytes(&file_bytes).unwrap_or_else(|e| {
        // Maybe it's already signed?
        if cryptoballot::SignedTransaction::from_bytes(&file_bytes).is_ok() {
            eprintln!("cryptoballot sign: {} is already signed", filename);
        } else {
            eprintln!("cryptoballot post: unable to read {}: {}, ", filename, e);
        }

        std::process::exit(1);
    });

    let _key = std::fs::read_to_string(secret_location);

    todo!("command sign transaction not finish"); // TODO
}

fn command_get_transaction(matches: &clap::ArgMatches, uri: &str) {
    // Unwraps OK - required args
    let id = matches.value_of("id").unwrap();
    let id = id.parse().unwrap();

    // TODO: remove unwrap
    let tx = rest::get_transaction(uri, id).unwrap();

    let json_tx = if matches.is_present("pretty") {
        serde_json::to_string_pretty(&tx).unwrap()
    } else {
        serde_json::to_string(&tx).unwrap()
    };

    println!("{}", json_tx);
}

fn command_tally(matches: &clap::ArgMatches, uri: &str) {
    // Unwraps OK - required args
    let election_id = matches.value_of("election-id").unwrap();
    let election_id = election_id.parse().unwrap();

    // TODO: remove these unwraps, use try_into();
    let election = rest::get_transaction(uri, election_id).unwrap();
    let _election: ElectionTransaction = election.into();

    //let vote_txs =
    //    rest::get_multiple_transactions(election.id(), Some(TransactionType::Decryption), uri)
    //        .unwrap();

    // TODO: Use a real tally / ballot / contest system
    //let mut tally = DefaultPluralityTally::new(1);

    //for vote in vote_txs {
    // TODO: use try_into();
    //    let vote: Signed<DecryptionTransaction> = vote.into();

    //    let selection = std::str::from_utf8(&vote.decrypted_vote)
    //        .unwrap()
    //        .to_owned();
    //    tally.add(selection);
    //}

    //let winners = tally.winners().into_unranked();
    //println!("The winner is {}", winners[0]);
}

// Utility Functions
// -----------------

// Performs shell expansion on filenames (mostly to handle ~)
pub fn expand(filename: &str) -> String {
    shellexpand::full(filename)
        .unwrap_or_else(|e| {
            eprintln!("cryptoballot: error expanding {}: {}", filename, e);
            std::process::exit(1);
        })
        .into_owned()
}
