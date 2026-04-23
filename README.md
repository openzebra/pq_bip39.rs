# pqbip39

A no_std compatible Rust implementation of the BIP-39 mnemonic code standard for generating and validating mnemonic phrases used in cryptocurrency wallets.

## Features

- Supports 12 to 33-word mnemonic phrases
- Generates seeds from mnemonics using PBKDF2
- Validates checksums and word counts
- Converts between entropy and mnemonic phrases
- Compatible with `no_std` environments
- Optional `std` and `zeroize` features
- Full mnemonic secret protection via `secrecy` crate — phrases, seeds, and entropy are wrapped in `SecretString`/`SecretBox`/`SecretSlice`

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
pqbip39 = "0.2.0"
```

## Usage

### Generating a Mnemonic

```rust
use pqbip39::{Mnemonic, rng::Rng};
use rand::rngs::OsRng;

const EN_WORDS: [&str; 2048] = [/* English BIP-39 wordlist */];

let mut rng = OsRng;
let mnemonic = Mnemonic::generate(&mut rng, &EN_WORDS, 12).unwrap();
let phrase = mnemonic.to_phrase(); // SecretString
println!("{:?}", phrase.expose_secret());
```

### Parsing a Mnemonic

```rust
use pqbip39::Mnemonic;
use secrecy::SecretString;

const EN_WORDS: [&str; 2048] = [/* English BIP-39 wordlist */];

let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::parse_str(&EN_WORDS, &SecretString::from(phrase)).unwrap();
```

### Parsing without Checksum Validation

```rust
let mnemonic = Mnemonic::parse_str_without_checksum(&EN_WORDS, &SecretString::from(phrase)).unwrap();
```

### Converting to Seed

```rust
let seed = mnemonic.to_seed(&SecretString::from("TREZOR")).unwrap();
// seed is SecretBox<[u8; 64]>, access via .expose_secret()
```

### Converting to Entropy

```rust
let entropy = mnemonic.to_entropy(); // SecretSlice<u8>
let bytes = entropy.expose_secret();
```

### Converting from Entropy

```rust
let mnemonic = Mnemonic::from_entropy(&EN_WORDS, &entropy_bytes).unwrap();
```

### Getting the Checksum

```rust
let checksum: u8 = mnemonic.checksum();
```

### Iterating Words

```rust
for word in mnemonic.words() { // yields SecretString
    println!("{:?}", word.expose_secret());
}
```

## Features

- `std` (default): Enables Unicode normalization via `unicode-normalization`.
- `zeroize`: Adds secure zeroing of sensitive data via the `zeroize` crate.

To disable `std` (for `no_std`):

```toml
[dependencies]
pqbip39 = { version = "0.2.0", default-features = false }
```

## Testing

Run tests with:

```bash
cargo test
```

The library includes comprehensive tests for English and Japanese wordlists, entropy conversion, checksum validation, and PBKDF2 seed generation, including BIP-39 test vectors.

## License

MIT

## Repository

[https://github.com/openzebra/pq_bip39.rs](https://github.com/openzebra/pq_bip39.rs)
