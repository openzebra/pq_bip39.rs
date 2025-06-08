use core::fmt;

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
}
