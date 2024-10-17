# SLIP-10: Deterministic key generation

> !Warning
>
> <div class="warning">
>
> `slip-10` crate has been restructured and renamed into
> [`hd-wallet`](https://crates.io/crates/hd-wallet)! `slip-10` is not likely
> to receive any future updates. Please, consider switching to successor library.
>
> In order to migrate to the successor `hd-wallet v0.5`, include it into Cargo.toml:
> ```toml
> hd-wallet = "0.5"
> ```
>
> Then you'll need to change `slip_10::` references in your code to `hd_wallet::`. For instance,
> `slip_10::HardenedIndex` becomes `hd_wallet::HardenedIndex`.
>
> The functions for child wallet derivation has been moved. Derivation algorithm that is used
> in `slip_10` crate corresponds to `hd_wallet::slip10_like`. E.g. if you were deriving a child
> key using `slip_10::derive_child_public_key`, now you need to use `hd_wallet::slip10_like::derive_child_public_key`
> instead.
>
> If you have any problems with migration, don't hesitate to reach out to us [in Discord `#lockness` room](https://discordapp.com/channels/905194001349627914/1294284489635139585).
>
> </div>

[SLIP10][slip10-spec] is a specification for implementing HD wallets. It aims at supporting many
curves while being compatible with [BIP32][bip32-spec].

The implementation is based on generic-ec library that provides generic
elliptic curve arithmetic. The crate is `no_std` and `no_alloc` friendly.

### Curves support
Implementation currently does not support ed25519 curve. All other curves are
supported: both secp256k1 and secp256r1. In fact, implementation may work with any
curve, but only those are covered by the SLIP10 specs.

The crate also re-exports supported curves in supported_curves module (requires
enabling a feature), but any other curve implementation will work with the crate.

### Features
* `std`: enables std library support (mainly, it just implements `Error`
  trait for the error types)
* `curve-secp256k1` and `curve-secp256r1` add curve implementation into the crate supported_curves
  module

### Examples

Derive a master key from the seed, and then derive a child key m/1<sub>H</sub>/10:
```rust
use slip_10::supported_curves::Secp256k1;

let seed = b"16-64 bytes of high entropy".as_slice();
let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
let master_key_pair = slip_10::ExtendedKeyPair::from(master_key);

let child_key_pair = slip_10::derive_child_key_pair_with_path(
    &master_key_pair,
    [1 + slip_10::H, 10],
);
```

[slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
[bip32-spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
