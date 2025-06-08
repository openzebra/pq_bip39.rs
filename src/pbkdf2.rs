use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

use crate::{
    errors::Bip39Error,
    mnemonic::{Mnemonic, SEED_BYTE_LEN},
};

const SALT_PREFIX: &str = "mnemonic";

fn mnemonic_byte_len<'a, I>(iter: I) -> usize
where
    I: Iterator<Item = &'a str>,
{
    let mut len = 0;
    let mut count: usize = 0;
    for word in iter {
        len += word.len();
        count += 1;
    }

    len + count.saturating_sub(1)
}

#[inline]
fn xor(a: &mut [u8], b: &[u8]) {
    for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
        *a_byte ^= *b_byte;
    }
}

pub fn pbkdf2<'a>(
    mnemonic: &Mnemonic<'a>,
    passphrase: &[u8],
    c: u32,
) -> Result<[u8; SEED_BYTE_LEN], Bip39Error> {
    const BLOCK_SIZE: usize = 128;
    let mut key_buffer = [0u8; BLOCK_SIZE];

    let mnemonic_len = mnemonic_byte_len(mnemonic.iter());

    let key = if mnemonic_len > BLOCK_SIZE {
        let mut hasher = Sha512::new();
        for (i, word) in mnemonic.iter().enumerate() {
            if i > 0 {
                hasher.update(b" ");
            }
            hasher.update(word.as_bytes());
        }
        let hashed_key = hasher.finalize();
        let len = hashed_key.len();
        key_buffer[..len].copy_from_slice(&hashed_key);
        &key_buffer[..len]
    } else {
        let mut cursor = 0;
        for (i, word) in mnemonic.iter().enumerate() {
            if i > 0 {
                key_buffer[cursor] = b' ';
                cursor += 1;
            }
            let word_bytes = word.as_bytes();
            let word_len = word_bytes.len();
            key_buffer[cursor..cursor + word_len].copy_from_slice(word_bytes);
            cursor += word_len;
        }
        &key_buffer[..cursor]
    };

    let prf = Hmac::<Sha512>::new_from_slice(key)?;
    let h_len = <Sha512 as Digest>::output_size();
    let mut result = [0u8; SEED_BYTE_LEN];

    for (i, chunk) in result.chunks_mut(h_len).enumerate() {
        let i_be = ((i + 1) as u32).to_be_bytes();

        let mut mac = prf.clone();
        mac.update(SALT_PREFIX.as_bytes());
        mac.update(passphrase);
        mac.update(&i_be);
        let mut u = mac.finalize().into_bytes();

        chunk.copy_from_slice(&u);

        for _ in 1..c {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes();
            xor(chunk, &u);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests_pbkdf2 {
    use super::*;

    #[test]
    fn test_mnemonic_byte_len() {
        let words: [&str; 0] = [];
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 0);

        let words = ["hello"];
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 5);

        let words = ["abandon", "ability", "able"];
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 20);

        let words = ["a", "b", "c", "d"];
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 7);
    }

    #[test]
    fn test_xor() {
        let mut a1 = [0b10101010, 0b11001100];
        let b1 = [0b11110000, 0b00110011];
        let expected1 = [0b01011010, 0b11111111];
        xor(&mut a1, &b1);
        assert_eq!(a1, expected1);

        let mut a2 = [1, 2, 3, 4];
        let b2 = [0, 0, 0, 0];
        let expected2 = [1, 2, 3, 4];
        xor(&mut a2, &b2);
        assert_eq!(a2, expected2);

        let mut a3 = [0xDE, 0xAD, 0xBE, 0xEF];
        let b3 = a3.clone();
        let expected3 = [0, 0, 0, 0];
        xor(&mut a3, &b3);
        assert_eq!(a3, expected3);
    }
}
