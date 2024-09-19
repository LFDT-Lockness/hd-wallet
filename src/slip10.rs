//! SLIP10-specific function
//!
//! [SLIP10][slip10-spec] is a specification for implementing HD wallets. It aims at supporting many
//! curves while being compatible with [BIP32][bip32-spec].
//!
//! ### Curves support
//! ed25519 and curve25519 keys are not supported by this library.
//!
//! Only secp256k1 and secp256r1 curve are supported.
//!
//! ### Slip10-like derivation
//! SLIP10 standard is only defined for a specific set of curves and key types, however,
//! it can be extended to support any curve. [`Slip10Like`] works with any curve, not limited
//! to what defined in the standard.
//!
//! We do not recommend using SLIP10-like derivation with Ed25519 curve:
//! 1. it's confusing as ed25519 curve is defined in SLIP10, however,
//!    `Slip10Like<Ed25519>` will not follow SLIP10 standard
//! 2. it's quite inefficient
//!
//! Prefer using [`Edwards`](crate::Edwards) derivation method for ed25519 curve.
//!
//! [slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//! [bip32-spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use hmac::Mac as _;

pub use crate::Slip10Like;

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

    let hmac = crate::HmacSha512::new_from_slice(curve_tag)
        .expect("this never fails: hmac can handle keys of any size");
    let mut i = hmac.clone().chain_update(seed).finalize().into_bytes();

    loop {
        let (i_left, i_right) = crate::split_into_two_halves(&i);

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
