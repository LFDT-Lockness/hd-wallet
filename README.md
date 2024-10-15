![License](https://img.shields.io/crates/l/hd-wallet.svg)
[![Docs](https://docs.rs/hd-wallet/badge.svg)](https://docs.rs/hd-wallet)
[![Crates io](https://img.shields.io/crates/v/hd-wallet.svg)](https://crates.io/crates/hd-wallet)
[![Discord](https://img.shields.io/discord/905194001349627914?logo=discord&logoColor=ffffff&label=Discord)](https://discordapp.com/channels/905194001349627914/1285268686147424388)

# HD wallets derivation

This crate supports the following HD derivations:
* [SLIP10][slip10-spec] (compatible with [BIP32][bip32-spec]), see `Slip10`
* Non-standard `Edwards` derivation for ed25519 curve

To perform HD derivation, use `HdWallet` trait.

### Example: SLIP10 derivation

Derive a master key from the seed, and then derive a child key m/1<sub>H</sub>/10:
```rust
use hd_wallet::{slip10, curves::Secp256k1};

let seed = b"16-64 bytes of high entropy".as_slice();
let master_key = slip10::derive_master_key::<Secp256k1>(seed)?;
let master_key_pair = hd_wallet::ExtendedKeyPair::from(master_key);

let child_key_pair = slip10::derive_child_key_pair_with_path(
    &master_key_pair,
    [1 + hd_wallet::H, 10],
);
```

### Example: via HdWallet trait

`HdWallet` trait generalizes HD derivation algorithm, you can use it with generics:
```rust
use hd_wallet::{Slip10Like, curves::Secp256r1};

fn derive_using_generic_algo<E: generic_ec::Curve, Hd: hd_wallet::HdWallet<E>>(
    master_key: hd_wallet::ExtendedKeyPair<E>,
) -> hd_wallet::ExtendedKeyPair<E>
{
    Hd::derive_child_key_pair_with_path(
        &master_key,
        [1 + hd_wallet::H, 10],
    )
}

// Use it with any HD derivation:
let seed = b"16-64 bytes of high entropy".as_slice();
let master_key = hd_wallet::slip10::derive_master_key(seed)?;
let master_key_pair = hd_wallet::ExtendedKeyPair::from(master_key);
let child_key = derive_using_generic_algo::<Secp256r1, Slip10Like>(master_key_pair);

```

### Features
* `std`: enables std library support (mainly, it just implements `Error`
  trait for the error types)
* `curve-secp256k1`, `curve-secp256r1`, `curve-ed25519` add curve implementation into the crate
  curves module

[slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[bip32-spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
