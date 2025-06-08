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
        // Тестовый случай 1: пустой итератор
        let words: [&str; 0] = [];
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 0);

        // Тестовый случай 2: одно слово
        let words = ["hello"];
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 5);

        // Тестовый случай 3: несколько слов
        let words = ["abandon", "ability", "able"];
        // 7 (abandon) + 1 (space) + 7 (ability) + 1 (space) + 4 (able) = 20
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 20);

        // Тестовый случай 4: слова разной длины
        let words = ["a", "b", "c", "d"];
        // 1 + 1 + 1 + 1 + 1 + 1 + 1 = 7
        assert_eq!(mnemonic_byte_len(words.iter().cloned()), 7);
    }
}
