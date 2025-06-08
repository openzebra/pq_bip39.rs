use crate::mnemonic::{MAX_NB_WORDS, MIN_NB_WORDS};

#[inline]
pub fn is_invalid_word_count(word_count: usize) -> bool {
    word_count < MIN_NB_WORDS || word_count % 3 != 0 || word_count > MAX_NB_WORDS
}
