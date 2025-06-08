# pqbip39

A no_std compatible Rust implementation of the BIP-39 mnemonic code standard for generating and validating mnemonic phrases used in cryptocurrency wallets.

## Features

- Supports 12 to 24-word mnemonic phrases
- Generates seeds from mnemonics using PBKDF2
- Validates checksums and word counts
- Converts between entropy and mnemonic phrases
- Compatible with `no_std` environments
- Optional `std` and `zeroize` features
- Includes English wordlist (2048 words)

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
pqbip39 = "0.1.0"
```

## Usage

### Generating a Mnemonic

```rust
use pqbip39::{Mnemonic, rng::Rng};
use rand::rngs::OsRng;

const EN_WORDS: [&str; 2048] = [/* English BIP-39 wordlist */];

let mut rng = OsRng;
let mnemonic = Mnemonic::generate(&mut rng, &EN_WORDS, 12).unwrap();
println!("{}", mnemonic); // e.g., "abandon ability able ..."
```

### Parsing a Mnemonic

```rust
use pqbip39::Mnemonic;

const EN_WORDS: [&str; 2048] = [/* English BIP-39 wordlist */];

let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::parse_str(&EN_WORDS, phrase).unwrap();
```

### Converting to Seed

```rust
let seed = mnemonic.to_seed("TREZOR").unwrap();
```

### Converting to Entropy

```rust
let entropy: Vec<u8> = mnemonic.to_entropy().collect();
```

## Features

- `std`: Enables `std` library features like Unicode normalization (default).
- `zeroize`: Adds secure zeroing of sensitive data.

To disable `std` (for `no_std`):

```toml
[dependencies]
pqbip39 = { version = "0.1.0", default-features = false }
```

## Testing

Run tests with:

```bash
cargo test
```

The library includes comprehensive tests for entropy conversion, checksum validation, and PBKDF2 seed generation, including BIP-39 test vectors.

## License

MIT

## Repository

[https://github.com/openzebra/pq_bip39.rs](https://github.com/openzebra/pq_bip39.rs)
