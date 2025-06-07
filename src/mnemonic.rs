pub const MIN_NB_WORDS: usize = 12;
pub const MAX_NB_WORDS: usize = 33;

const EOF: u16 = u16::max_value();

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Mnemonic {
    indicators: [u16; MAX_NB_WORDS],
}
