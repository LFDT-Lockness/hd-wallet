//! Stark HD derivation
//!
//! This module provides [`Stark`] derivation as well as aliases for calling
//! `<Stark as HdWallet<_>>::*` methods for convenience when you don't need to support
//! generic HD derivation algorithm.
//!
//! See [`Stark`] docs to learn more about the derivation method.

use generic_ec::{curves, Point, Scalar};
use hmac::Mac;

use crate::{
    DeriveShift, DerivedShift, ExtendedKeyPair, ExtendedPublicKey, HardenedIndex, NonHardenedIndex,
};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// HD derivation for stark curve
///
/// ## Algorithm
/// The algorithm is a modification of BIP32:
///
/// ```text
/// def derive_child_key(parent_public_key[, parent_secret_key], parent_chain_code, child_index):
///   if is_hardened(child_index):
///     i = HMAC_SHA512(key = parent_chain_code, 0x00 || 0x00 || parent_secret_key || child_index)
///         || HMAC_SHA512(key = parent_chain_code, 0x01 || 0x00 || parent_secret_key || child_index)
///   else:
///     i = HMAC_SHA512(key = parent_chain_code, 0x00 || parent_public_key || child_index)
///         || HMAC_SHA512(key = parent_chain_code, 0x01 || parent_public_key || child_index)
///   shift = i[..96] mod order
///   child_secret_key = parent_secret_key + shift and/or child_public_key = parent_public_key + shift G
///   child_chain_code = i[N..]
///   return child_public_key[, child_secret_key], child_chain_code
/// ```
///
/// ## Other known methods for stark HD derivation
/// There's another known method for HD derivation on stark curve implemented in
/// [argent-x], which basically derives secp256k1 child key from a seed, and then
/// uses grinding function to deterministically convert it into stark key.
///
/// We decided not to implement it due to its cons:
/// * No support for non-hardened derivation
/// * Grinding is a probabilistic algorithm which does a lot of hashing (32 hashes
///   on average, but in worst case can be 1000+).
/// * In general, it's strange to derive secp256k1 key and then convert it to stark key
///
/// Our derivation algorithm addresses these flaws: it yields a stark key right away (without
/// any intermediate secp256k1 keys), supports non-hardened derivation, does only 2 hashes per
/// derivation.
///
/// [argent-x]: https://github.com/argentlabs/argent-x/blob/13142607d83fea10b297d6a23452e810605784d1/packages/extension/src/shared/signer/ArgentSigner.ts#L14-L25,
pub struct Stark;

impl DeriveShift<curves::Stark> for Stark {
    fn derive_public_shift(
        parent_public_key: &ExtendedPublicKey<curves::Stark>,
        child_index: NonHardenedIndex,
    ) -> DerivedShift<curves::Stark> {
        let hmac = HmacSha512::new_from_slice(&parent_public_key.chain_code)
            .expect("this never fails: hmac can handle keys of any size");
        let i0 = hmac
            .clone()
            .chain_update([0x00])
            .chain_update(parent_public_key.public_key.to_bytes(true))
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        let i1 = hmac
            .chain_update([0x01])
            .chain_update(parent_public_key.public_key.to_bytes(true))
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift(parent_public_key, i0, i1)
    }

    fn derive_hardened_shift(
        parent_key: &ExtendedKeyPair<curves::Stark>,
        child_index: HardenedIndex,
    ) -> DerivedShift<curves::Stark> {
        let hmac = HmacSha512::new_from_slice(parent_key.chain_code())
            .expect("this never fails: hmac can handle keys of any size");
        let i0 = hmac
            .clone()
            .chain_update([0x00])
            .chain_update([0x00])
            .chain_update(parent_key.secret_key.secret_key.as_ref().to_be_bytes())
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        let i1 = hmac
            .chain_update([0x01])
            .chain_update([0x00])
            .chain_update(parent_key.secret_key.secret_key.as_ref().to_be_bytes())
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift(&parent_key.public_key, i0, i1)
    }
}

impl Stark {
    fn calculate_shift(
        parent_public_key: &ExtendedPublicKey<curves::Stark>,
        i0: hmac::digest::Output<HmacSha512>,
        i1: hmac::digest::Output<HmacSha512>,
    ) -> DerivedShift<curves::Stark> {
        let i = generic_array::sequence::Concat::concat(i0, i1);
        let (shift, chain_code) = split(&i);

        let shift = Scalar::from_be_bytes_mod_order(shift);
        let child_pk = parent_public_key.public_key + Point::generator() * shift;

        DerivedShift {
            shift,
            child_public_key: ExtendedPublicKey {
                public_key: child_pk,
                chain_code: (*chain_code).into(),
            },
        }
    }
}

fn split(
    i: &generic_array::GenericArray<u8, generic_array::typenum::U128>,
) -> (
    &generic_array::GenericArray<u8, generic_array::typenum::U96>,
    &generic_array::GenericArray<u8, generic_array::typenum::U32>,
) {
    generic_array::sequence::Split::split(i)
}

super::create_aliases!(Stark, stark, hd_wallet::curves::Stark);
