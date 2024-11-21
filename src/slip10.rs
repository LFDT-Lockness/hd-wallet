//! SLIP10 derivation
//!
//! [SLIP10][slip10-spec] is a specification for implementing HD wallets. It aims at supporting more
//! curves than [BIP32][bip32-spec] while being compatible with it.
//!
//! Refer to [`Slip10`] docs to learn more about the derivation method.
//!
//! This module provides [`derive_master_key`] function that can be used to derive a master key
//! from the seed, as well as aliases for calling `<Slip10 as HdWallet>::*` methods for convenience
//! when you don't need to support generic HD derivation algorithm.
//!
//! [slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//! [bip32-spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use generic_ec::{Curve, Point, Scalar};
use hmac::Mac as _;

use crate::{
    DeriveShift, DerivedShift, ExtendedKeyPair, ExtendedPublicKey, HardenedIndex, NonHardenedIndex,
};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// [SLIP10][slip10-spec] HD wallet derivation
///
/// Performs HD derivation as defined in the spec. Only supports secp256k1 and secp256r1 curves.
///
/// ## Limitations
/// We do not support SLIP10 instantiated with ed25519 or curve25519 due to the limitations.
/// Ed25519 and curve25519 are special-cases in SLIP10 standard, they only support hardened
/// derivation, and they operate on EdDSA and X25519 private keys instead of elliptic points
/// and scalars as in other cases. This library only supports HD derivations in which
/// secret keys are represented as scalars and public keys as points, see [`ExtendedSecretKey`]
/// and [`ExtendedPublicKey`].
///
/// If you need HD derivation on Ed25519 curve, we recommend using [`Edwards`] HD derivation,
/// which supports both hardened and non-hardened derivation.
///
/// ## Master key derivation from the seed
/// [`slip10::derive_master_key`] can be used to derive a master key from the seed as defined
/// in the spec.
///
/// ## Example
/// Derive a master key from the seed, and then derive a child key m/1<sub>H</sub>/10:
/// ```rust
/// use hd_wallet::{HdWallet, Slip10, curves::Secp256k1};
///
/// let seed = b"16-64 bytes of high entropy".as_slice();
/// let master_key = hd_wallet::slip10::derive_master_key::<Secp256k1>(seed)?;
/// let master_key_pair = hd_wallet::ExtendedKeyPair::from(master_key);
///
/// let child_key_pair = Slip10::derive_child_key_pair_with_path(
///     &master_key_pair,
///     [1 + hd_wallet::H, 10],
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
pub struct Slip10;

impl Slip10 {
    /// Derives public shift for any curve, regardless whether it's in the slip10 spec
    /// or not
    ///
    /// DO NOT use it with curves not specified in slip10. Other curves might be subject to
    /// DoS attack: attacker may find inputs to HD derivation which would result in a lot of
    /// iterations of HMAC-ing. Only curves from the spec are proven to be resistant to this
    /// attack.
    fn derive_public_shift_for_any_curve<E: Curve>(
        parent_public_key: &ExtendedPublicKey<E>,
        child_index: NonHardenedIndex,
    ) -> DerivedShift<E> {
        let hmac = HmacSha512::new_from_slice(&parent_public_key.chain_code)
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .clone()
            .chain_update(parent_public_key.public_key.to_bytes(true))
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift_for_any_curve(&hmac, parent_public_key, *child_index, i)
    }

    /// Derives hardened shift for any curve, regardless whether it's in the slip10 spec
    /// or not
    ///
    /// DO NOT use it with curves not specified in slip10. Other curves might be subject to
    /// DoS attack: attacker may find inputs to HD derivation which would result in a lot of
    /// iterations of HMAC-ing. Only curves from the spec are proven to be resistant to this
    /// attack.
    fn derive_hardened_shift_for_any_curve<E: Curve>(
        parent_key: &ExtendedKeyPair<E>,
        child_index: HardenedIndex,
    ) -> DerivedShift<E> {
        let hmac = HmacSha512::new_from_slice(parent_key.chain_code())
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .clone()
            .chain_update([0x00])
            .chain_update(parent_key.secret_key.secret_key.as_ref().to_be_bytes())
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift_for_any_curve(&hmac, &parent_key.public_key, *child_index, i)
    }

    fn calculate_shift_for_any_curve<E: Curve>(
        hmac: &HmacSha512,
        parent_public_key: &ExtendedPublicKey<E>,
        child_index: u32,
        mut i: hmac::digest::Output<HmacSha512>,
    ) -> DerivedShift<E> {
        loop {
            let (i_left, i_right) = split_into_two_halves(&i);

            if let Ok(shift) = Scalar::<E>::from_be_bytes(i_left) {
                let child_pk = parent_public_key.public_key + Point::generator() * shift;
                if !child_pk.is_zero() {
                    return DerivedShift {
                        shift,
                        child_public_key: ExtendedPublicKey {
                            public_key: child_pk,
                            chain_code: (*i_right).into(),
                        },
                    };
                }
            }

            i = hmac
                .clone()
                .chain_update([0x01])
                .chain_update(i_right)
                .chain_update(child_index.to_be_bytes())
                .finalize()
                .into_bytes()
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

impl<E> DeriveShift<E> for Slip10
where
    E: Curve + SupportedCurve,
{
    fn derive_public_shift(
        parent_public_key: &ExtendedPublicKey<E>,
        child_index: NonHardenedIndex,
    ) -> DerivedShift<E> {
        Slip10::derive_public_shift_for_any_curve(parent_public_key, child_index)
    }
    fn derive_hardened_shift(
        parent_key: &ExtendedKeyPair<E>,
        child_index: HardenedIndex,
    ) -> DerivedShift<E> {
        Slip10::derive_hardened_shift_for_any_curve(parent_key, child_index)
    }
}

/// Marker for a curve supported by SLIP10 specs and this library
///
/// Only implement this trait for the curves that are supported by SLIP10 specs.
/// Curves provided by the crate out-of-box in [curves](crate::curves) module already
/// implement this trait.
///
/// Note: this library does not support ed25519 or curve25519 key types to
/// be used with slip10. Only secp256k1 and secp256r1 are supported.
pub trait SupportedCurve {
    /// Specifies which curve it is
    const CURVE_TYPE: CurveType;
}
#[cfg(feature = "curve-secp256k1")]
impl SupportedCurve for generic_ec::curves::Secp256k1 {
    const CURVE_TYPE: CurveType = CurveType::Secp256k1;
}
#[cfg(feature = "curve-secp256r1")]
impl SupportedCurve for generic_ec::curves::Secp256r1 {
    const CURVE_TYPE: CurveType = CurveType::Secp256r1;
}

/// Curves supported by SLIP-10 spec
///
/// It's either secp256k1 or secp256r1. Note that SLIP-10 also supports ed25519 curve, but this library
/// does not support it.
///
/// `CurveType` is only needed for master key derivation.
#[derive(Clone, Copy, Debug)]
pub enum CurveType {
    /// Secp256k1 curve
    Secp256k1,
    /// Secp256r1 curve
    Secp256r1,
}

/// Derives a master key from the seed
///
/// Seed must be 16-64 bytes long, otherwise an error is returned
pub fn derive_master_key<E: generic_ec::Curve + SupportedCurve>(
    seed: &[u8],
) -> Result<crate::ExtendedSecretKey<E>, crate::errors::InvalidLength> {
    let curve_tag = match E::CURVE_TYPE {
        CurveType::Secp256k1 => "Bitcoin seed",
        CurveType::Secp256r1 => "Nist256p1 seed",
    };
    derive_master_key_with_curve_tag(curve_tag.as_bytes(), seed)
}

/// Derives a master key from the seed and the curve tag as defined in SLIP10
///
/// It's preferred to use [derive_master_key] instead, as it automatically infers
/// the curve tag for supported curves. The curve tag is not validated by the function,
/// it's caller's responsibility to make sure that it complies with SLIP10.
///
/// Seed must be 16-64 bytes long, otherwise an error is returned
pub fn derive_master_key_with_curve_tag<E: generic_ec::Curve>(
    curve_tag: &[u8],
    seed: &[u8],
) -> Result<crate::ExtendedSecretKey<E>, crate::errors::InvalidLength> {
    if !(16 <= seed.len() && seed.len() <= 64) {
        return Err(crate::errors::InvalidLength);
    }

    let hmac = HmacSha512::new_from_slice(curve_tag)
        .expect("this never fails: hmac can handle keys of any size");
    let mut i = hmac.clone().chain_update(seed).finalize().into_bytes();

    loop {
        let (i_left, i_right) = split_into_two_halves(&i);

        if let Ok(mut sk) = generic_ec::Scalar::<E>::from_be_bytes(i_left) {
            if !bool::from(subtle::ConstantTimeEq::ct_eq(
                &sk,
                &generic_ec::Scalar::zero(),
            )) {
                return Ok(crate::ExtendedSecretKey {
                    secret_key: generic_ec::SecretScalar::new(&mut sk),
                    chain_code: (*i_right).into(),
                });
            }
        }

        i = hmac.clone().chain_update(&i[..]).finalize().into_bytes()
    }
}

super::create_aliases!(Slip10, slip10);
