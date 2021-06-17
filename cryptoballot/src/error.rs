use crate::*;

use thiserror::Error;

/// Error types
#[derive(Debug, Error)]
pub enum Error {
    #[error("cryptoballot: sinature error: {0}")]
    SignatureError(#[from] ed25519_dalek::SignatureError),

    #[error("cryptoballot: RSA error: {0}")]
    RSAError(#[from] rsa::errors::Error),

    #[error("cryptoballot: mismatched public keys")]
    MismatchedPublicKeys,

    #[error("cryptoballot: secret recovery failed")]
    SecretRecoveryFailed,

    #[error("cryptoballot: invalid identifier - invalid hexidecimal")]
    IdentifierBadHex,

    #[error("cryptoballot: invalid identifier - wrong length")]
    IdentifierBadLen,

    #[error("cryptoballot: CBOR error deserializing transaction: {0}")]
    CBORDeserialization(#[from] serde_cbor::Error),

    #[error("cryptoballot: JSON error deserializing transaction: {0}")]
    JSONDeserialization(#[from] serde_json::Error),

    #[error("cryptoballot: error deserializing transaction: unknown format")]
    DeserializationUnknownFormat,

    #[error("cryptoballot: share decryption error")]
    ShareDecryptionError,

    #[error("cryptoballot: failed to decrypt vote")]
    DecryptionError,

    #[error("cryptoballot: shuffle error: {0}")]
    ShuffleError(cryptid::CryptoError),

    #[error("cryptoballot: invalid x25519 public key")]
    InvalidX25519PublicKey,

    #[error("{0}")]
    ValidationError(#[from] ValidationError),

    #[error("{0}")]
    TransactionNotFound(#[from] TransactionNotFound),
}

/// Transaction Validation errors
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("cryptoballot: invalid identifier - incorrectly composed")]
    IdentifierBadComposition,

    #[error("cryptoballot validation: election authority public key mismatch")]
    AuthorityPublicKeyMismatch,

    #[error("cryptoballot validation: trustee public key mismatch for trustee {0}")]
    TrusteePublicKeyMismatch(u8),

    #[error("cryptoballot validation: mismatched encryption_key for trustee {0})")]
    MismatchedEncryptionKey(u8),

    #[error("cryptoballot validation: threshold is invalid for number of trustees")]
    InvalidTrusteeThreshold,

    #[error("cryptoballot validation: threshold is invalid for number of authenticators")]
    InvalidAuthThreshold,

    #[error("cryptoballot validation: invalid public key")]
    InvalidPublicKey,

    #[error("cryptoballot validation: election mismatch")]
    ElectionMismatch,

    #[error("cryptoballot validation: ballot does not exist in election")]
    BallotDoesNotExist,

    #[error("cryptoballot validation: authentication does not exist in election")]
    AuthDoesNotExist,

    #[error(
        "cryptoballot validation: trustee with index {0} does not exist in election (or possibly mismatched public keys)"
    )]
    TrusteeDoesNotExist(u8),

    #[error("cryptoballot validation: missing keygen_public_key transaction for trustee {0})")]
    MissingKeyGenPublicKeyTransaction(u8),

    #[error("cryptoballot validation: wrong number of keygen_public_key transactions)")]
    WrongNumberOfPublicKeyTransactions,

    #[error("cryptoballot validation: trustee {0} share is missing)")]
    TrusteeShareMissing(u8),

    #[error("cryptoballot validation: trustee {0} cannot be found)")]
    TrusteeMissing(u8),

    #[error("cryptoballot validation: wrong number of shares")]
    WrongNumberOfShares,

    #[error("cryptoballot validation: authentication failed")]
    AuthFailed,

    #[error("cryptoballot: encryption_key transaction not does yet exist")]
    EncryptionKeyTransactionDoesNotExist,

    #[error("cryptoballot: secret recovery failed")]
    SecretRecoveryFailed,

    #[error("cryptoballot: vote decryption failed: {0}")]
    VoteDecryptionFailed(cryptid::CryptoError),

    #[error("cryptoballot: vote decryption failed: decrypted vote mismatch")]
    VoteDecryptionMismatch,

    #[error("cryptoballot: auth signature verification failed")]
    AuthSignatureVerificationFailed,

    #[error("cryptoballot: not enough secret shares: need {0}, found {1}")]
    NotEnoughShares(usize, usize),

    #[error("cryptoballot: transaction not found: {0}")]
    TransactionNotFound(#[from] TransactionNotFound),

    #[error("cryptoballot: Missing voting_end transaction")]
    MisingVotingEndTransaction,

    #[error("cryptoballot validation: signature error: {0}")]
    SignatureError(#[from] ed25519_dalek::SignatureError),

    #[error("cryptoballot validation: share decryption error")]
    ShareDecryptionError,

    #[error("cryptoballot: partial decryption proof failed to verify")]
    PartialDecryptionProofFailed,

    #[error("cryptoballot: mismatched transaction type and id type")]
    MismatchedTransactionType,

    #[error("cryptoballot: voting has ended")]
    VotingHasEnded,

    #[error("cryptoballot: shuffle verification failed")]
    ShuffleVerificationFailed,

    #[error("cryptoballot: no mixnet configured for election")]
    NoMixnetConfig,

    #[error("cryptoballot: out of order mix")]
    OutOfOrderMix,

    #[error("cryptoballot: missing previous mix transaction")]
    MissingPrevMixTransaction,

    #[error("cryptoballot: invalid previous mix transaction")]
    InvalidPrevMixTransaction,

    #[error("cryptoballot: mix vote_ids are not sorted ascending")]
    MixVoteIdsNotSorted,

    #[error("cryptoballot: wrong number of votes in mix")]
    MixWrongNumberOfVotes,

    #[error("cryptoballot: not all votes accounted for in mix")]
    MixVotesNotAccountedFor,

    #[error("cryptoballot: invalid upstream transaction ID")]
    InvalidUpstreamID,

    #[error("cryptoballot: invalid upstream index")]
    InvalidUpstreamIndex,

    #[error("cryptoballot: wrong mix selected for decryption")]
    WrongMixSelected,
}
