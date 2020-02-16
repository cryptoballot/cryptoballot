pub struct KeyGenerationTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
    pub trustee: uuid::Uuid,
    pub shared: Vec<u8>,
    pub signature: Option<Signature>,
}

pub struct ElectionKeyTransaction {
    pub election_key: PublicKey,
}

pub struct ReEncryptionTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
    pub vote: uuid::Uuid,
    pub previous_reencryption: Option<uuid::Uuid>,
    pub reencrypted: Vec<u8>,
}

pub struct VoteDecryptionTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
    pub voter_public_key: PublicKey,
}

pub struct ElectionTallyTransaction {
    pub id: uuid::Uuid,
    pub election: uuid::Uuid,
}
