pub const MIN_NB_WORDS: usize = 12;
pub const MAX_NB_WORDS: usize = 33;
pub const MAX_WORDS_DICT: usize = 2048;

const EOF: u16 = u16::max_value();

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Mnemonic<'a> {
    lang_words: [&'a str; MAX_WORDS_DICT],
    indicators: [u16; MAX_NB_WORDS],
}

impl<'a> Mnemonic<'a> {
    pub fn from(dictionary: [&'a str; MAX_WORDS_DICT]) -> Self {
        Self {
            lang_words: dictionary,
            indicators: [0u16; MAX_NB_WORDS],
        }
    }
}
