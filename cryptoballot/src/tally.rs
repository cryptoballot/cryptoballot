use crate::*;
use indexmap::IndexMap;
use rust_decimal::prelude::*;
use tallystick::RankedCandidate;
use tallystick::RankedWinners;

pub struct TallyTransaction {
    pub id: Identifier,
    pub election_id: Identifier,

    pub tally: IndexMap<String, TallyResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TallyResult {
    pub contest_id: String,
    pub contest_index: u32,

    pub num_votes: usize,
    pub totals: IndexMap<String, Decimal>,
    pub results: Vec<RankedCandidate<String>>,
    pub winners: RankedWinners<String>,
    pub spoiled_ballots: IndexMap<Identifier, SpoiledBallotError>,
}

impl TallyResult {
    pub fn tally(
        contest_id: String,
        contest_index: u32,
        num_winners: u32,
        contest_type: ContestType,
        votes: Vec<Vec<Selection>>,
    ) -> Self {
        let num_votes = votes.len();

        // Make sure selections are in order
        let votes: Vec<Vec<Selection>> = votes
            .into_iter()
            .map(|mut vote| {
                vote.sort_by(|a, b| a.score.cmp(&b.score));
                vote
            })
            .collect();

        match contest_type {
            ContestType::Plurality => {
                use tallystick::plurality::DefaultPluralityTally;
                let mut tally = DefaultPluralityTally::new(num_winners as usize);

                for vote in votes {
                    for selection in vote {
                        tally.add_ref(&selection.selection)
                    }
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::Score => {
                use tallystick::score::DefaultScoreTally;
                let mut tally = DefaultScoreTally::new(num_winners as usize);

                for vote in votes {
                    let vote: Vec<(String, u64)> = vote.into_iter().map(|v| v.into()).collect();
                    tally.add_ref(&vote);
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::Approval => {
                use tallystick::approval::DefaultApprovalTally;
                let mut tally = DefaultApprovalTally::new(num_winners as usize);

                for vote in votes {
                    let vote: Vec<String> = vote.into_iter().map(|v| v.selection).collect();
                    tally.add_ref(&vote);
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::Condorcet => {
                use tallystick::condorcet::DefaultCondorcetTally;
                let mut tally = DefaultCondorcetTally::new(num_winners as usize);

                for vote in votes {
                    let vote: Vec<(String, u32)> = vote.into_iter().map(|v| v.into()).collect();
                    tally
                        .ranked_add(&vote)
                        .expect("Unexpected duplicate candidate");
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(format!("{} > {}", candidate.0, candidate.1), total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::SchulzeWinning => {
                use tallystick::schulze::DefaultSchulzeTally;
                use tallystick::schulze::Variant;
                let mut tally = DefaultSchulzeTally::new(num_winners as usize, Variant::Winning);

                for vote in votes {
                    let vote: Vec<(String, u32)> = vote.into_iter().map(|v| v.into()).collect();
                    tally
                        .ranked_add(&vote)
                        .expect("Unexpected duplicate candidate");
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(format!("{} > {}", candidate.0, candidate.1), total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::SchulzeMargin => {
                use tallystick::schulze::DefaultSchulzeTally;
                use tallystick::schulze::Variant;
                let mut tally = DefaultSchulzeTally::new(num_winners as usize, Variant::Margin);

                for vote in votes {
                    let vote: Vec<(String, u32)> = vote.into_iter().map(|v| v.into()).collect();
                    tally
                        .ranked_add(&vote)
                        .expect("Unexpected duplicate candidate");
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(format!("{} > {}", candidate.0, candidate.1), total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::SchulzeRatio => {
                // use tallystick::schulze::SchulzeTally;
                // use tallystick::schulze::Variant;

                // TODO: Decimal needs to implement NumCast before this can work.

                unimplemented!();
            }
            ContestType::Borda => {
                use tallystick::borda::DefaultBordaTally;
                use tallystick::borda::Variant;

                let mut tally = DefaultBordaTally::new(num_winners as usize, Variant::Borda);

                for vote in votes {
                    let vote: Vec<String> = vote.into_iter().map(|v| v.selection).collect();
                    tally
                        .add_ref(&vote)
                        .expect("Unexpected duplicate candidate");
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::BordaClassic => {
                use tallystick::borda::DefaultBordaTally;
                use tallystick::borda::Variant;

                let mut tally = DefaultBordaTally::new(num_winners as usize, Variant::ClassicBorda);

                for vote in votes {
                    let vote: Vec<String> = vote.into_iter().map(|v| v.selection).collect();
                    tally
                        .add_ref(&vote)
                        .expect("Unexpected duplicate candidate");
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::BordaDowdall => {
                use tallystick::borda::DefaultBordaTally;
                use tallystick::borda::Variant;

                let mut tally = DefaultBordaTally::new(num_winners as usize, Variant::Dowdall);

                for vote in votes {
                    let vote: Vec<String> = vote.into_iter().map(|v| v.selection).collect();
                    tally
                        .add_ref(&vote)
                        .expect("Unexpected duplicate candidate");
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
            ContestType::BordaModifiedClassic => {
                use tallystick::borda::DefaultBordaTally;
                use tallystick::borda::Variant;

                let mut tally =
                    DefaultBordaTally::new(num_winners as usize, Variant::ModifiedClassicBorda);

                for vote in votes {
                    let vote: Vec<String> = vote.into_iter().map(|v| v.selection).collect();
                    tally
                        .add_ref(&vote)
                        .expect("Unexpected duplicate candidate");
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total.into());
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes,
                    totals,
                    results: ranked,
                    winners,
                    spoiled_ballots: IndexMap::new(),
                }
            }
        }
    }
}
