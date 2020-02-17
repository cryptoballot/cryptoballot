use crate::*;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use sharks::{Share, Sharks};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretShareTransaction {
    pub id: Identifier,
    pub election: Identifier,
    pub trustee_id: Uuid,
    pub public_key: PublicKey,
    pub secret_share: Vec<u8>,
}

impl SecretShareTransaction {
    pub fn new(election_id: Identifier, trustee: Trustee, secret_share: Vec<u8>) -> Self {
        let secret_share = SecretShareTransaction {
            id: Identifier::new(election_id, TransactionType::SecretShare),
            election: election_id,
            trustee_id: trustee.id,
            public_key: trustee.public_key,
            secret_share: secret_share,
        };

        secret_share
    }

    pub fn validate(&self, election: &ElectionTransaction) -> Result<(), ValidationError> {
        // TODO: check self.id.election_id vs self.election_id
        if self.election != election.id {
            return Err(ValidationError::ElectionMismatch);
        }
        let trustee = election
            .get_trustee(self.trustee_id)
            .ok_or(ValidationError::TrusteeDoesNotExist)?;

        if trustee.public_key != self.public_key {
            return Err(ValidationError::InvalidPublicKey);
        }

        Ok(())
    }
}

impl Signable for SecretShareTransaction {
    fn id(&self) -> Identifier {
        self.id
    }

    // TODO: election authority public key
    fn public(&self) -> Option<PublicKey> {
        Some(self.public_key)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Trustee {
    pub id: uuid::Uuid,
    pub public_key: PublicKey,
}

impl Trustee {
    pub fn new() -> (Self, SecretKey) {
        let (secret, public) = generate_keypair();

        let trustee = Trustee {
            id: Uuid::new_v4(),
            public_key: public,
        };
        return (trustee, secret);
    }
}

pub fn deal_secret_shares(theshold: u8, num_trustees: usize, secret: &[u8]) -> Vec<Vec<u8>> {
    let sharks = Sharks(theshold);
    let dealer = sharks.dealer(secret);

    let mut all_shares = Vec::with_capacity(num_trustees);
    for s in dealer.take(num_trustees) {
        all_shares.push(Vec::from(&s));
    }

    all_shares
}

pub fn recover_secret_shares(threshold: u8, shares: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let shares: Vec<Share> = shares.iter().map(|s| Share::from(s.as_slice())).collect();

    let sharks = Sharks(threshold);

    let secret = sharks
        .recover(&shares)
        .map_err(|_| Error::SecretRecoveryFailed)?;

    Ok(secret)
}
