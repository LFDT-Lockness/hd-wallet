//! Edwards HD derivation
//!
//! This module provides [`Edwards`] derivation as well as aliases for calling
//! `<Edwards as HdWallet<_>>::*` methods for convenience when you don't need to support
//! generic HD derivation algorithm.
//!
//! See [`Edwards`] docs to learn more about the derivation method.

use generic_ec::{curves, Point, Scalar};
use hmac::Mac;

use crate::{
    DeriveShift, DerivedShift, ExtendedKeyPair, ExtendedPublicKey, HardenedIndex, NonHardenedIndex,
};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// HD derivation for Ed25519 curve
///
/// This type of derivation isn't defined in any known to us standards, but it can be often
/// found in other libraries. It is secure and efficient.
///
/// ## Example
/// ```rust
/// use hd_wallet::{HdWallet, Edwards, curves::Ed25519};
///
/// # fn load_key() -> hd_wallet::ExtendedKeyPair<Ed25519> {
/// #     hd_wallet::ExtendedSecretKey {
/// #         secret_key: generic_ec::SecretScalar::random(&mut rand::rngs::OsRng),
/// #         chain_code: rand::Rng::gen(&mut rand::rngs::OsRng),
/// #     }.into()
/// # }
/// #
/// let parent_key: hd_wallet::ExtendedKeyPair<Ed25519> = load_key();
///
/// let child_key_pair = Edwards::derive_child_key_pair_with_path(
///     &parent_key,
///     [1 + hd_wallet::H, 10],
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Edwards;

impl DeriveShift<curves::Ed25519> for Edwards {
    fn derive_public_shift(
        parent_public_key: &ExtendedPublicKey<curves::Ed25519>,
        child_index: NonHardenedIndex,
    ) -> DerivedShift<curves::Ed25519> {
        let hmac = HmacSha512::new_from_slice(&parent_public_key.chain_code)
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .clone()
            .chain_update(parent_public_key.public_key.to_bytes(true))
            // we append 0 byte to the public key for compatibility with other libs
            .chain_update([0x00])
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift(parent_public_key, i)
    }

    fn derive_hardened_shift(
        parent_key: &ExtendedKeyPair<curves::Ed25519>,
        child_index: HardenedIndex,
    ) -> DerivedShift<curves::Ed25519> {
        let hmac = HmacSha512::new_from_slice(parent_key.chain_code())
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .clone()
            .chain_update([0x00])
            .chain_update(parent_key.secret_key.secret_key.as_ref().to_be_bytes())
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift(&parent_key.public_key, i)
    }
}

impl Edwards {
    fn calculate_shift(
        parent_public_key: &ExtendedPublicKey<curves::Ed25519>,
        i: hmac::digest::Output<HmacSha512>,
    ) -> DerivedShift<curves::Ed25519> {
        let (i_left, i_right) = split_into_two_halves(&i);

        let shift = Scalar::from_be_bytes_mod_order(i_left);
        let child_pk = parent_public_key.public_key + Point::generator() * shift;

        DerivedShift {
            shift,
            child_public_key: ExtendedPublicKey {
                public_key: child_pk,
                chain_code: (*i_right).into(),
            },
        }
    }
}

/// Splits array `I` of 64 bytes into two arrays `I_L = I[..32]` and `I_R = I[32..]`
fn split_into_two_halves(
    i: &generic_array::GenericArray<u8, generic_array::typenum::U64>,
) -> (
    &generic_array::GenericArray<u8, generic_array::typenum::U32>,
    &generic_array::GenericArray<u8, generic_array::typenum::U32>,
) {
    generic_array::sequence::Split::split(i)
}

super::create_aliases!(Edwards, edwards, hd_wallet::curves::Ed25519);
