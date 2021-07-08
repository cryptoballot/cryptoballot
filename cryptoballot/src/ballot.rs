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
    Custom,
    Plurality,
    Score,
    Approval,
    STV,
    InstantRunOff,
    Condorcet,
    Borda,
    BordaClassic,
    BordaDowdall,
    BordaModifiedClassic,
    SchulzeWinning, // Use this for Schulz if unsure
    SchulzeRatio,
    SchulzeMargin,
}

#[derive(Serialize, Deserialize, Clone, Message, PartialEq, Eq)]
pub struct Selection {
    #[prost(bool)]
    #[serde(default)]
    pub write_in: bool,

    #[prost(uint32)]
    #[serde(default)]
    pub rank: u32,

    #[prost(string)]
    pub selection: String,
}
