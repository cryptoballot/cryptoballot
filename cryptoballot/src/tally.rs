use crate::*;
use indexmap::IndexMap;
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
    pub totals: IndexMap<String, f64>,
    pub results: Vec<RankedCandidate<String>>,
    pub winners: RankedWinners<String>,
}

impl TallyResult {
    pub fn tally(
        contest_id: String,
        contest_index: u32,
        num_winners: u32,
        contest_type: ContestType,
        votes: &[Vec<Selection>],
    ) -> Self {
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
                    totals.insert(candidate, total as f64);
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes: votes.len(),
                    totals,
                    results: ranked,
                    winners,
                }
            }
            ContestType::Score => {
                use tallystick::score::DefaultScoreTally;
                let mut tally = DefaultScoreTally::new(num_winners as usize);

                for vote in votes {
                    let vote: Vec<(String, u64)> = vote.iter().map(|v| v.clone().into()).collect();
                    tally.add_ref(&vote);
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total as f64);
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes: votes.len(),
                    totals,
                    results: ranked,
                    winners,
                }
            }
            ContestType::Approval => {
                use tallystick::approval::DefaultApprovalTally;
                let mut tally = DefaultApprovalTally::new(num_winners as usize);

                for vote in votes {
                    let vote: Vec<String> = vote.iter().map(|v| v.selection).collect();
                    tally.add_ref(&vote);
                }

                let mut totals = IndexMap::new();
                for (candidate, total) in tally.totals() {
                    totals.insert(candidate, total as f64);
                }

                let ranked = tally.ranked();
                let winners = tally.winners();

                TallyResult {
                    contest_id,
                    contest_index,
                    num_votes: votes.len(),
                    totals,
                    results: ranked,
                    winners,
                }
            }
            _ => {
                unimplemented!();
            }
        }
    }
}
