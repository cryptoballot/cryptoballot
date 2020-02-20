use failure::Fail;
use sawtooth_sdk::processor::handler::ContextError;

#[derive(Debug, Fail)]
pub enum TPError {
    #[fail(display = "validation error: {}", 0)]
    ValidationError(cryptoballot::ValidationError),

    #[fail(display = "internal error: {}", 0)]
    InternalError(cryptoballot::Error),

    #[fail(display = "state error: could not find {}", 0)]
    StateNotFound(String),

    #[fail(display = "cannot parse transaction: {}", 0)]
    CannotParseTransaction(String),

    #[fail(display = "sawtooth context error: {}", 0)]
    ContextError(String),
}

impl From<cryptoballot::ValidationError> for TPError {
    fn from(err: cryptoballot::ValidationError) -> Self {
        TPError::ValidationError(err)
    }
}

impl From<cryptoballot::Error> for TPError {
    fn from(err: cryptoballot::Error) -> Self {
        TPError::InternalError(err)
    }
}

impl From<ContextError> for TPError {
    fn from(err: ContextError) -> Self {
        TPError::ContextError(format!("{}", err))
    }
}
