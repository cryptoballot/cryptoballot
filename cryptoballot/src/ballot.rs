use indexmap::IndexMap;
use prost::Message;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ballot {
    pub id: String,
    pub contests: Vec<u32>, // List of contest indexes

    /// Application specific properties.
    ///
    /// Hashmaps are not allowed because their unstable ordering leads to non-determinism.
    #[serde(default)]
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub properties: IndexMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Contest {
    pub id: String,
    pub index: u32,

    pub contest_type: ContestType,
    pub num_winners: u32,
    pub write_in: bool,
    pub candidates: Vec<Candidate>,

    /// Application specific properties.
    ///
    /// Hashmaps are not allowed because their unstable ordering leads to non-determinism.
    #[serde(default)]
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub properties: IndexMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Candidate {
    pub id: String,

    /// Application specific properties.
    ///
    /// Hashmaps are not allowed because their unstable ordering leads to non-determinism.
    #[serde(default)]
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub properties: IndexMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ContestType {
    /// Plurality voting is an electoral system in which each voter is allowed to vote for only one candidate and the candidate
    /// who polls the most among their counterparts (a plurality) is elected. It may be called first-past-the-post (FPTP),
    /// single-choice voting, simple plurality, or relative/simple majority.
    ///
    ///  For Plurality tally, `Selection.score` has no meaning.
    Plurality,

    /// Score voting or “range voting” is an electoral system in which voters give each candidate a score, the scores are summed,
    /// and the candidate with the highest total is elected. It has been described by various other names including “evaluative voting”,
    /// “utilitarian voting”, and “the point system”.
    ///
    /// For Score tally, `Selection.score` represents the number of points assigned to each candidate. Zero is the worst score that can be asssigned to a candidate.
    Score,

    /// Approval voting is a single-winner electoral system where each voter may select (“approve”) any number of candidates.
    /// The winner is the most-approved candidate.
    ///
    ///  For Approval tally, `Selection.score` has no meaning.
    Approval,

    /// The Condorcet method is a ranked-choice voting system that elects the candidate that would win a majority of the vote in all of the head-to-head elections against each of the other candidates.
    /// The Condorcet method isn’t guarunteed to produce a single-winner due to the non-transitive nature of group choice.
    ///
    /// For Condorcet tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    Condorcet,

    /// The standard Borda count where each candidate is assigned a number of points equal to the number of candidates ranked lower than them.
    /// It is known as the "Starting at 0" Borda count since the least-significantly ranked candidate is given zero points.
    /// Each candidate is given points according to:
    ///
    /// ```number-candidates - candidate-position - 1```
    ///
    /// Example point allocation for a single ballot:
    ///
    /// | Position on ballot  | Candiate | Points |
    /// | --------------------|----------|--------|
    /// | 0                   | Alice    | 3      |
    /// | 1                   | Bob      | 2      |
    /// | 2                   | Carlos   | 1      |
    /// | 3                   | Dave     | 0      |
    ///
    /// For Borda tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    Borda,

    /// The classic Borda count as defined in Jean-Charles de Borda's [original proposal](http://gerardgreco.free.fr/IMG/pdf/MA_c_moire-Borda-1781.pdf).
    /// It is known as the "Starting at 1" Borda count since the least-significantly ranked candidate is given one point.
    /// Each candidate is given points according to:
    ///
    /// ```number-candidates - candidate-position```
    ///
    /// Example point allocation for a single ballot:
    ///
    /// | Position on ballot  | Candiate | Points |
    /// | --------------------|----------|--------|
    /// | 0                   | Alice    | 4      |
    /// | 1                   | Bob      | 3      |
    /// | 2                   | Carlos   | 2      |
    /// | 3                   | Dave     | 1      |
    ///
    /// For BordaClassic tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    BordaClassic,

    /// In the Dowdall system, the highest-ranked candidate obtains 1 point, while the 2nd-ranked candidate receives ½ a point, the 3rd-ranked candidate receives ⅓ of a point, etc.
    /// An important difference of this method from the others is that the number of points assigned to each preference does not depend on the number of candidates.
    /// Each candidate is given points according to:
    ///
    /// ```1 / (candidate-position + 1)```
    ///
    /// If Dowdall is selected, tallystick will panic if an integer count type is used in the tally. This variant should only be used with a float or rational tally.
    ///
    /// Example point allocation for a single ballot:
    ///
    /// | Position on ballot  | Candiate | Points |
    /// | --------------------|----------|--------|
    /// | 0                   | Alice    | 1      |
    /// | 1                   | Bob      | ½      |
    /// | 2                   | Carlos   | ⅓      |
    /// | 3                   | Dave     | ¼      |
    ///
    /// For BordaDowdall tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    BordaDowdall,

    /// In a modified Borda count, the number of points given for a voter's first and subsequent preferences is determined by the total number of candidates they have actually ranked, rather than the total number listed.
    /// This is to say, typically, on a ballot of `n` candidates, if a voter casts only `m` preferences (where `n ≥ m ≥ 1`), a first preference gets `m` points, a second preference `m – 1` points, and so on.
    /// Modified Borda counts are used to counteract the problem of [bullet voting](https://en.wikipedia.org/wiki/Bullet_voting).
    /// Each candidate is given points according to:
    ///
    /// ```number-marked - candidate-position```
    ///
    /// For BordaModifiedClassic tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    BordaModifiedClassic,

    /// The Schulze method is an voting system that selects a single winner using votes that express preferences.
    /// In SchulzeWinning Strength of a link is measured by its support. You should use this Schulze variant if you are unsure.
    ///
    /// For SchulzeWinning tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    SchulzeWinning,

    /// The Schulze method is an voting system that selects a single winner using votes that express preferences.
    /// In SchulzeRatio, the strength of a link is measured by the difference between its support and opposition.
    ///
    /// For SchulzeRatio tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    SchulzeRatio,

    /// The Schulze method is an voting system that selects a single winner using votes that express preferences.
    /// In SchulzeMargin, the strength of a link is measured by the ratio of its support and opposition.
    ///
    /// For SchulzeMargin tally, `Selection.score` is interpreted as the candidate rank, where the best ranked candidate has a rank of zero.
    /// Candidates that have the same rank are considered to be of equal preference.
    SchulzeMargin,
}

#[derive(Serialize, Deserialize, Clone, Message, PartialEq, Eq)]
pub struct Selection {
    /// true if the `selection` field is a free-form write-in, false if the `selection` field corresponds to a known candidate-id
    #[prost(bool)]
    #[serde(default)]
    pub write_in: bool,

    /// Score has different meanings depending on the tally type:
    /// STV, Condorcet, Borda and Schulze: `score` means candidate rank, where a zero is the best rank that can be assigned to a candidate.
    /// Score: `score` is the points assinged to this candidate. Zero is the worst score that can be asssigned to a candidate.
    /// Plurality, Approval, and InstantRunoff: `score` is meaningless and has no effect.
    #[prost(uint32)]
    #[serde(default)]
    pub score: u32,

    /// Known candidate-id or free-form text, depending on the value of the `write_in` field.
    #[prost(string)]
    pub selection: String,
}

impl Into<(String, u64)> for Selection {
    fn into(self) -> (String, u64) {
        (self.selection, self.score as u64)
    }
}

impl Into<(String, u32)> for Selection {
    fn into(self) -> (String, u32) {
        (self.selection, self.score)
    }
}
