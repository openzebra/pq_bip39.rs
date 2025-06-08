use hmac::digest::InvalidLength;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Bip39Error {
    #[error("Invalid word count: {0}")]
    BadWordCount(usize),

    #[error("entropy was not between 128-256 bits or not a multiple of 32 bits: {0} bits")]
    BadEntropyBitCount(usize),

    #[error("mnemonic contains an unknown word (word {0})")]
    UnknownWord(usize),

    #[error("the mnemonic has an invalid checksum")]
    InvalidChecksum,

    #[error("HMAC key error: {0}")]
    HmacError(InvalidLength),
}

impl From<InvalidLength> for Bip39Error {
    fn from(error: InvalidLength) -> Self {
        Bip39Error::HmacError(error)
    }
}
