use cryptoballot::*;
use std::str;
use tallystick::plurality::DefaultPluralityTally;

pub fn command_e2e(matches: &clap::ArgMatches, uri: &str) {
    let election_id = crate::expand(matches.value_of("ELECTION-ID").unwrap());

    if election_id.len() < 15 {
        eprintln!("cryptoballot e2e: invalid election-id");
        std::process::exit(1);
    }
    let prefix = &election_id[0..15];

    let mut store = MemStore::default();

    let transactions = crate::rest::get_transactions_by_prefix(uri, &prefix).unwrap();

    if transactions.len() == 0 {
        eprint!("No Transactions present");
        std::process::exit(1)
    }

    let first_transaction = &transactions[0];
    if first_transaction.transaction_type() != TransactionType::Election {
        eprint!("Frist transaction must be an election transaction");
        std::process::exit(1)
    }
    let election_id = first_transaction.id();

    for tx in transactions {
        match tx.validate(&store) {
            Ok(()) => store.set(tx),
            Err(e) => {
                eprint!("Failed to validate transaction {}: {}", tx.id(), e);
                std::process::exit(1)
            }
        }
    }

    println!("> Election verified OK");

    if matches.is_present("print-votes") {
        println!("Votes:");
        let votes = store.get_multiple(election_id, TransactionType::Decryption);
        for vote in votes {
            let vote: DecryptionTransaction = vote.into();
            let vote = vote.decrypted_vote;

            for selection in vote {
                // TODO: Print if it's a write-in
                println!("  {}:{}", selection.rank, selection.selection);
                println!("");
            }
        }
    }

    if matches.is_present("print-tally") {
        println!("Tally:");

        // TODO: Use a real tally / ballot / contest system
        let mut tally = DefaultPluralityTally::new(1);

        let votes = store.get_multiple(election_id, TransactionType::Decryption);
        for vote in votes {
            let vote: DecryptionTransaction = vote.into();
            let vote = vote.decrypted_vote;
            tally.add(vote[0].selection.clone());
        }

        for (candidate, num_votes) in tally.totals().iter() {
            println!("  {} got {} votes", candidate, num_votes);
        }
    }

    if matches.is_present("print-results") {
        println!("Results:");

        // TODO: Use a real tally / ballot / contest system
        let mut tally = DefaultPluralityTally::new(1);

        let votes = store.get_multiple(election_id, TransactionType::Decryption);
        for vote in votes {
            let vote: DecryptionTransaction = vote.into();
            let vote = vote.decrypted_vote;

            // For now, assume it's a string
            tally.add(vote[0].selection.clone());
        }

        let winners = tally.winners().into_unranked();
        println!("  The winner is {}", winners[0]);
    }
}
