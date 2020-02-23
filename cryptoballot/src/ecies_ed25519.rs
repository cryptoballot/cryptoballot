use crate::generate_keypair;
use curve25519_dalek::constants;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use ed25519_dalek::{PublicKey, SecretKey};
use hkdf::Hkdf;
use rand::{thread_rng, Rng};
use sha2::Sha256;
use sha2::Sha512;

pub type AesKey = [u8; 32];
pub type SharedSecret = [u8; 32];

fn hkdf_sha256(master: &[u8]) -> AesKey {
    let h = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    h.expand(&[], &mut out).unwrap();
    out
}

fn secret_to_public_point(sk: &SecretKey) -> CompressedEdwardsY {
    let point = &Scalar::from_bits(sk.to_bytes()) * &constants::ED25519_BASEPOINT_TABLE;
    point.compress()
}

fn public_to_point(pk: &PublicKey) -> EdwardsPoint {
    CompressedEdwardsY::from_slice(pk.as_bytes())
        .decompress()
        .unwrap()
}

fn secret_to_scalar(sk: &SecretKey) -> Scalar {
    Scalar::from_bits(sk.to_bytes())
}

pub fn generate_shared(secret: &SecretKey, public: &CompressedEdwardsY) -> SharedSecret {
    let public = public.decompress().unwrap();
    let shared_point = public * secret_to_scalar(secret);
    let shared_point = shared_point.compress();
    shared_point.as_bytes().to_owned()
}

pub fn encapsulate(emphemeral_sk: &SecretKey, peer_pk: &CompressedEdwardsY) -> AesKey {
    let shared_point = generate_shared(emphemeral_sk, peer_pk);

    let emphemeral_pk = secret_to_public_point(emphemeral_sk);

    let mut master = Vec::with_capacity(32 * 2);
    master.extend(emphemeral_pk.as_bytes().iter());
    master.extend(shared_point.iter());
    hkdf_sha256(master.as_slice())
}

pub fn decapsulate(sk: &SecretKey, emphemeral_pk: &CompressedEdwardsY) -> AesKey {
    let shared_point = generate_shared(sk, emphemeral_pk);

    let mut master = Vec::with_capacity(32 * 2);
    master.extend(emphemeral_pk.as_bytes().iter());
    master.extend(shared_point.iter());

    hkdf_sha256(master.as_slice())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_shared() {
        let (emphemeral_sk, _) = generate_keypair();
        let (peer_sk, _) = generate_keypair();

        let emphemeral_pk = secret_to_public_point(&emphemeral_sk);
        let peer_pk = secret_to_public_point(&peer_sk);

        assert_eq!(
            generate_shared(&emphemeral_sk, &peer_pk),
            generate_shared(&peer_sk, &emphemeral_pk)
        )
    }

    #[test]
    fn test_encapsulation() {
        let (emphemeral_sk, _) = generate_keypair();
        let (peer_sk, _) = generate_keypair();

        let emphemeral_pk = secret_to_public_point(&emphemeral_sk);
        let peer_pk = secret_to_public_point(&peer_sk);

        assert_eq!(
            encapsulate(&emphemeral_sk, &peer_pk),
            decapsulate(&peer_sk, &emphemeral_pk)
        )
    }
}
