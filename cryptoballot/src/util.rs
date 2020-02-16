use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let mut csprng = rand::rngs::OsRng {};
    let Keypair { public, secret } = Keypair::generate(&mut csprng);
    (secret, public)
}
