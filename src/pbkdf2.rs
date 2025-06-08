use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

const SALT_PREFIX: &str = "mnemonic";

fn mnemonic_byte_len<'a, M>(mnemonic: M) -> usize
where
    M: Iterator<Item = &'a str> + Clone,
{
    let mut len = 0;
    for (i, word) in mnemonic.enumerate() {
        if i > 0 {
            len += 1;
        }
        len += word.len();
    }
    len
}

#[inline]
fn xor(a: &mut [u8], b: &[u8]) {
    for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
        *a_byte ^= *b_byte;
    }
}

pub fn pbkdf2<'a, M>(mnemonic: M, salt: &[u8], c: u32, res: &mut [u8])
where
    M: Iterator<Item = &'a str> + Clone,
{
    const BLOCK_SIZE: usize = 128;
    let mut key_buffer = [0u8; BLOCK_SIZE];

    let key = if mnemonic_byte_len(mnemonic.clone()) > BLOCK_SIZE {
        let mut hasher = Sha512::new();
        for (i, word) in mnemonic.enumerate() {
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
        for (i, word) in mnemonic.enumerate() {
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

    let prf = Hmac::<Sha512>::new_from_slice(key).expect("HMAC can accept any key size");
    let h_len = <Sha512 as Digest>::output_size();

    for (i, chunk) in res.chunks_mut(h_len).enumerate() {
        let i_be = ((i + 1) as u32).to_be_bytes();

        let mut mac = prf.clone();
        mac.update(salt);
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
}
