# # HD wallets derivation

This crate supports the following HD derivations:
* [SLIP10][slip10-spec] (compatible with [BIP32][bip32-spec]), see `Slip10`
* Non-standard `Edwards` derivation for ed25519 curve

To perform HD derivation, use `HdWallet` trait.

### Example: SLIP10 derivation

Derive a master key from the seed, and then derive a child key m/1<sub>H</sub>/10:
```rust
use hd_wallet::{HdWallet, Slip10, curves::Secp256k1};

let seed = b"16-64 bytes of high entropy".as_slice();
let master_key = hd_wallet::slip10::derive_master_key::<Secp256k1>(seed)?;
let master_key_pair = hd_wallet::ExtendedKeyPair::from(master_key);

let child_key_pair = Slip10::derive_child_key_pair_with_path(
    &master_key_pair,
    [1 + hd_wallet::H, 10],
);
```

### Features
* `std`: enables std library support (mainly, it just implements `Error`
  trait for the error types)
* `curve-secp256k1`, `curve-secp256r1`, `curve-ed25519` add curve implementation into the crate
  curves module

[slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[bip32-spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
