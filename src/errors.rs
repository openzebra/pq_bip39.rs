use hmac::digest::InvalidLength;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Bip39Error {
    #[error("Invalid word count: {0}")]
    BadWordCount(usize),

    #[error("HMAC key error: {0}")]
    HmacError(InvalidLength),
}

impl From<InvalidLength> for Bip39Error {
    fn from(error: InvalidLength) -> Self {
        Bip39Error::HmacError(error)
    }
}
