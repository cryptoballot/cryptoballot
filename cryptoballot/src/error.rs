use crate::*;
use failure::Fail;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "cryptoballot: sinature error: {}", 0)]
    SignatureError(ed25519_dalek::SignatureError),

    #[fail(display = "cryptoballot: RSA error: {}", 0)]
    RSAError(rsa::errors::Error),

    #[fail(display = "cryptoballot: mismatched public keys")]
    MismatchedPublicKeys,

    #[fail(display = "cryptoballot: secret recovery failed")]
    SecretRecoveryFailed,

    #[fail(display = "cryptoballot: invalid identifier - invalid hexidecimal")]
    IdentifierBadHex,

    #[fail(display = "cryptoballot: invalid identifier - wrong length")]
    IdentifierBadLen,

    #[fail(display = "cryptoballot: CBOR error deserializing transaction: {}", 0)]
    CBORDeserialization(serde_cbor::Error),

    #[fail(display = "cryptoballot: JSON error deserializing transaction: {}", 0)]
    JSONDeserialization(serde_json::Error),

    #[fail(display = "cryptoballot: error deserializing transaction: unknown format")]
    DeserializationUnknownFormat,

    #[fail(display = "cryptoballot: ecies error: {}", 0)]
    EciesError(ecies_ed25519::Error),

    #[fail(display = "cryptoballot: failed to decrypt vote")]
    DecryptionError,
}

impl From<serde_cbor::error::Error> for Error {
    fn from(err: serde_cbor::error::Error) -> Self {
        Error::CBORDeserialization(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::JSONDeserialization(err)
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Error::SignatureError(err)
    }
}

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::RSAError(err)
    }
}

impl From<ecies_ed25519::Error> for Error {
    fn from(err: ecies_ed25519::Error) -> Self {
        Error::EciesError(err)
    }
}

/// Transaction Validation errors
#[derive(Debug, Fail)]
pub enum ValidationError {
    #[fail(display = "cryptoballot validation: election authority public key mismatch")]
    AuthorityPublicKeyMismatch,

    #[fail(
        display = "cryptoballot validation: trustee public key mismatch for trustee {}",
        0
    )]
    TrusteePublicKeyMismatch(uuid::Uuid),

    #[fail(
        display = "cryptoballot validation: mismatched encryption_key for trustee {})",
        0
    )]
    MismatchedEncryptionKey(uuid::Uuid),

    #[fail(display = "cryptoballot validation: threshold is invalid for number of trustees")]
    InvalidTrusteeThreshold,

    #[fail(display = "cryptoballot validation: threshold is invalid for number of authenticators")]
    InvalidAuthThreshold,

    #[fail(display = "cryptoballot validation: invalid public key")]
    InvalidPublicKey,

    #[fail(display = "cryptoballot validation: election mismatch")]
    ElectionMismatch,

    #[fail(display = "cryptoballot validation: ballot does not exist in election")]
    BallotDoesNotExist,

    #[fail(display = "cryptoballot validation: authentication does not exist in election")]
    AuthDoesNotExist,

    #[fail(
        display = "cryptoballot validation: trustee {} does not exist in election (or possibly mismatched public keys)",
        0
    )]
    TrusteeDoesNotExist(uuid::Uuid),

    #[fail(
        display = "cryptoballot validation: missing keygen_public_key transaction for trustee {})",
        0
    )]
    MissingKeyGenPublicKeyTransaction(uuid::Uuid),

    #[fail(display = "cryptoballot validation: wrong number of keygen_public_key transactions)")]
    WrongNumberOfPublicKeyTransactions,

    #[fail(display = "cryptoballot validation: trustee {} share is missing)", 0)]
    TrusteeShareMissing(uuid::Uuid),

    #[fail(display = "cryptoballot validation: wrong number of shares")]
    WrongNumberOfShares,

    #[fail(display = "cryptoballot validation: authentication failed")]
    AuthFailed,

    #[fail(display = "cryptoballot: secret recovery failed")]
    SecretRecoveryFailed,

    #[fail(display = "cryptoballot: vote decryption failed: {}", 0)]
    VoteDecryptionFailed(cryptid::CryptoError),

    #[fail(display = "cryptoballot: vote decryption failed: decrypted vote mismatch")]
    VoteDecryptionMismatch,

    #[fail(display = "cryptoballot: auth signature verification failed")]
    AuthSignatureVerificationFailed,

    #[fail(
        display = "cryptoballot: not enough secret shares: need {}, found {}",
        0, 1
    )]
    NotEnoughShares(usize, usize),

    #[fail(display = "cryptoballot: {}", 0)]
    TransactionNotFound(TransactionNotFound),

    #[fail(display = "cryptoballot validation: signature error: {}", 0)]
    SignatureError(ed25519_dalek::SignatureError),

    #[fail(display = "cryptoballot validation: ecies decryption error: {}", 0)]
    EciesError(ecies_ed25519::Error),

    #[fail(display = "cryptoballot: partial decryption proof failed to verify")]
    PartialDecryptionProofFailed,
}

impl From<ed25519_dalek::SignatureError> for ValidationError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        ValidationError::SignatureError(err)
    }
}

impl From<TransactionNotFound> for ValidationError {
    fn from(err: TransactionNotFound) -> Self {
        ValidationError::TransactionNotFound(err)
    }
}

impl From<ecies_ed25519::Error> for ValidationError {
    fn from(err: ecies_ed25519::Error) -> Self {
        Self::EciesError(err)
    }
}
