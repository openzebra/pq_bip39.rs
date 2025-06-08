use crate::{errors::Bip39Error, rng::Rng, utils::is_invalid_word_count};
use core::fmt;
use sha2::{Digest, Sha256};

pub const MIN_NB_WORDS: usize = 12;
pub const MAX_NB_WORDS: usize = 33;
pub const MAX_WORDS_DICT: usize = 2048;
pub const SEED_BYTE_LEN: usize = 64;

const EOF: u16 = u16::max_value();

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Mnemonic<'a> {
    lang_words: &'a [&'a str; MAX_WORDS_DICT],
    indicators: [u16; MAX_NB_WORDS],
    word_count: usize,
}

pub struct MnemonicIter<'a, 'b> {
    mnemonic: &'b Mnemonic<'a>,
    position: usize,
}

impl<'a, 'b> Iterator for MnemonicIter<'a, 'b> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.mnemonic.word_count {
            return None;
        }
        let word_index = self.mnemonic.indicators[self.position] as usize;
        self.position += 1;
        Some(self.mnemonic.lang_words[word_index])
    }
}

impl<'a> fmt::Display for Mnemonic<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, word) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(word)?;
        }
        Ok(())
    }
}

impl<'a> Mnemonic<'a> {
    pub fn from(dictionary: &'a [&'a str; MAX_WORDS_DICT]) -> Self {
        Self {
            lang_words: dictionary,
            indicators: [0u16; MAX_NB_WORDS],
            word_count: 0,
        }
    }

    pub fn iter<'b>(&'b self) -> MnemonicIter<'a, 'b> {
        MnemonicIter {
            mnemonic: self,
            position: 0,
        }
    }

    pub fn from_entropy(
        lang_words: &'a [&'a str; 2048],
        entropy: &[u8],
    ) -> Result<Self, Bip39Error> {
        const MAX_ENTROPY_BITS: usize = 256;
        const MIN_ENTROPY_BITS: usize = 128;
        const MAX_CHECKSUM_BITS: usize = 8;

        let nb_bytes = entropy.len();
        let nb_bits = nb_bytes * 8;

        if nb_bits % 32 != 0 || nb_bits < MIN_ENTROPY_BITS || nb_bits > MAX_ENTROPY_BITS {
            return Err(Bip39Error::BadEntropyBitCount(nb_bits));
        }

        let hash = Sha256::digest(entropy);
        let cs_bits = nb_bits / 32;
        let checksum = (hash[0] >> (8 - cs_bits)) & ((1 << cs_bits) - 1);

        let mut bits = [false; MAX_ENTROPY_BITS + MAX_CHECKSUM_BITS];
        for (i, &byte) in entropy.iter().enumerate() {
            for j in 0..8 {
                bits[i * 8 + j] = (byte & (1 << (7 - j))) != 0;
            }
        }
        for i in 0..cs_bits {
            bits[nb_bits + i] = (checksum & (1 << (cs_bits - 1 - i))) != 0;
        }

        let total_bits = nb_bits + cs_bits;
        let word_count = total_bits / 11;
        let mut indicators = [0u16; MAX_NB_WORDS];
        for i in 0..word_count {
            let mut idx = 0u16;
            for j in 0..11 {
                if bits[i * 11 + j] {
                    idx |= 1 << (10 - j);
                }
            }
            indicators[i] = idx;
        }

        Ok(Mnemonic {
            lang_words,
            indicators,
            word_count,
        })
    }

    pub fn generate<R: Rng>(
        rng: &mut R,
        lang_words: &'a [&'a str; MAX_WORDS_DICT],
        word_count: usize,
    ) -> Result<Self, Bip39Error> {
        if is_invalid_word_count(word_count) {
            return Err(Bip39Error::BadWordCount(word_count));
        }

        let entropy_bytes = (word_count / 3) * 4;
        let mut entropy = [0u8; (MAX_NB_WORDS / 3) * 4];

        Rng::fill_bytes(rng, &mut entropy[0..entropy_bytes]);

        let indicators = [0u16; MAX_NB_WORDS];

        Ok(Mnemonic {
            lang_words,
            indicators,
            word_count,
        })
    }
}
