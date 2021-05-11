use crate::*;
use rand::{CryptoRng, Rng};
use cryptid::elgamal::PublicKey as ElGamalPublicKey;
use cryptid::elgamal::{CurveElem};
use cryptid::threshold::{
    Decryption, KeygenCommitment, Threshold, ThresholdGenerator, ThresholdParty,
};
use cryptid::util::AsBase64;
use cryptid::Scalar;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use std::collections::HashMap;
use std::convert::TryInto;
use uuid::Uuid;

/// A trustee is responsible for safeguarding a secret share (a portion of the secret vote decryption key),
/// distributed by the election authority via Shamir Secret Sharing.
///
/// Most elections will have a handful of trustees (between 3 and 30), with a quorum being set to about 2/3
/// the total number of trustees. Any quorum of trustees may decrypt the votes.
pub struct Trustee {
    pub id: uuid::Uuid,
    pub index: usize,
    pub public_key: PublicKey,
    pub num_trustees: usize,
    pub threshold: usize,
}

impl Trustee {

    // Generate a cryptid generator derived from the secret-key
    fn generator(&self, sk: &SecretKey) -> ThresholdGenerator {
        use rand_chacha::rand_core::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use sha2::Sha256;
        use hkdf::Hkdf;

        // Generate a HKDF
        // TODO: Should we use the public key as the salt?
        let h = Hkdf::<Sha256>::new(None, sk.as_bytes());
        let mut seed = [0u8; 32]; // 256 bits of security
        h.expand(b"cryptoballot_trustee_generator", &mut seed).unwrap();
 
        let mut rng = ChaCha20Rng::from_seed(seed);

        ThresholdGenerator::new(&mut rng, self.index, self.threshold, self.num_trustees)
    }

    /// Create a new trustee
    pub fn new(index: usize, num_trustees: usize, threshold: usize) -> (Self, SecretKey) {
        if index == 0 {
            panic!("Trustee index cannot be zero");
        }

        let (secret, public) = generate_keypair();
 
        let trustee = Trustee {
            id: Uuid::new_v4(),
            index,
            public_key: public,
            num_trustees, 
            threshold
        };
        return (trustee, secret);
    }

    pub fn keygen_commitment(&self, sk: &SecretKey) -> KeygenCommitment {
        self.generator(sk).get_commitment()
    }

    pub fn generate_shares(
        &self,
        sk: &SecretKey, 
        commitments: &[(usize, KeygenCommitment)],
    ) -> Vec<(usize, usize, Scalar)> {
        // From, to, Share
        let mut theshold_generator =  self.generator(sk);

        for (index, commitment) in commitments {
            theshold_generator
                .receive_commitment(*index, commitment)
                .expect("Invalid commitment") // TODO Result
        }

        let mut shares = Vec::new();
        for (index, _commitment) in commitments {
            let share = theshold_generator.get_polynomial_share(*index).unwrap();
            shares.push((self.index, *index, share));
        }

        shares
    }

    fn generate_party(
        &self,
        sk: &SecretKey, 
        commitments: &[(usize, KeygenCommitment)],
        shares: &[(usize, Scalar)], // From, Share
    ) -> ThresholdParty {
        let mut theshold_generator = self.generator(sk);

        for (index, commitment) in commitments {
            theshold_generator
                .receive_commitment(*index, commitment)
                .expect("Invalid commitment") // TODO Result
        }

        for (index, share) in shares {
            theshold_generator
                .receive_share(*index, &share)
                .expect("Invalid share") // TODO Result
        }

        theshold_generator.finish().unwrap()
    }

    pub fn generate_public_key(
        &self,
        sk: &SecretKey, 
        commitments: &[(usize, KeygenCommitment)],
        shares: &[(usize, Scalar)], // From, Share
    ) -> ElGamalPublicKey {
        let party = self.generate_party(sk, commitments, shares);
        party.pubkey()
    }
}

#[test]
fn trustee_test() {
    let (trustee_1, skey_1) = Trustee::new(1, 3, 2);
    let (trustee_2, skey_2) = Trustee::new(2, 3, 2);
    let (trustee_3, skey_3) = Trustee::new(3, 3, 2);

    let commit_1 = trustee_1.keygen_commitment(&skey_1);
    let commit_2 = trustee_2.keygen_commitment(&skey_2);
    let commit_3 = trustee_3.keygen_commitment(&skey_3);

    let commitments = [
        (1, commit_1),
        (2, commit_2),
        (3, commit_3),
    ];

    let mut shares = vec![];

    shares.extend(trustee_1.generate_shares(&skey_1,  &commitments));
    shares.extend(trustee_2.generate_shares(&skey_2, &commitments));
    shares.extend(trustee_3.generate_shares(&skey_3,  &commitments));

    let mut trustee_1_shares = vec![];
    let mut trustee_2_shares = vec![];
    let mut trustee_3_shares = vec![];

    for (from, to, share) in shares {
        match to {
            1 => trustee_1_shares.push((from, share)),
            2 => trustee_2_shares.push((from, share)),
            3 => trustee_3_shares.push((from, share)),
            _ => panic!("Invalid trustee share index"),
        }
    }

    let trustee_1_pubkey = trustee_1.generate_public_key(&skey_1, &commitments, &trustee_1_shares);
    let trustee_2_pubkey = trustee_2.generate_public_key(&skey_2, &commitments, &trustee_2_shares);
    let trustee_3_pubkey = trustee_3.generate_public_key(&skey_3, &commitments, &trustee_3_shares);

    assert_eq!(trustee_1_pubkey, trustee_2_pubkey);
    assert_eq!(trustee_1_pubkey, trustee_3_pubkey);
}
