use failure::Fail;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "cryptoballot: transaction failed to unpack: {}", 0)]
    UnpackError(serde_cbor::error::Error),

    #[fail(display = "cryptoballot: sinature error: {}", 0)]
    SignatureError(ed25519_dalek::SignatureError),

    #[fail(display = "cryptoballot: decryption error: {}", 0)]
    DecryptionError(secp256k1::Error),

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
}

impl From<serde_cbor::error::Error> for Error {
    fn from(err: serde_cbor::error::Error) -> Self {
        Error::UnpackError(err)
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Error::SignatureError(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::DecryptionError(err)
    }
}

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::RSAError(err)
    }
}

/// Transaction Validation errors
#[derive(Debug, Fail)]
pub enum ValidationError {
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

    #[fail(display = "cryptoballot validation: trustee does not exist in election")]
    TrusteeDoesNotExist,

    #[fail(display = "cryptoballot validation: authentication failed")]
    AuthFailed,

    #[fail(display = "cryptoballot: secret recovery failed")]
    SecretRecoveryFailed,

    #[fail(display = "cryptoballot: decrypt vote failed")]
    DecryptVoteFailed,

    #[fail(display = "cryptoballot: mismatched decrypted vote")]
    MismatchedDecryptedVote,

    #[fail(display = "cryptoballot: auth signature verification failed")]
    AuthSignatureVerificationFailed,

    #[fail(display = "cryptoballot validation: signature error: {}", 0)]
    SignatureError(ed25519_dalek::SignatureError),
}

impl From<ed25519_dalek::SignatureError> for ValidationError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        ValidationError::SignatureError(err)
    }
}
