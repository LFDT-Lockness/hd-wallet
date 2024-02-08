//! SLIP-10: Deterministic key generation
//!
//! [SLIP10][slip10-spec] is a specification for implementing HD wallets. It aims at supporting many
//! curves while being compatible with [BIP32][bip32-spec].
//!
//! The implementation is based on [generic-ec](generic_ec) library that provides generic
//! elliptic curve arithmetic. The crate is `no_std` and `no_alloc` friendly.
//!
//! ### Curves support
//! Implementation currently does not support ed25519 curve. All other curves are
//! supported: both secp256k1 and secp256r1. In fact, implementation may work with any
//! curve, but only those are covered by the SLIP10 specs.
//!
//! The crate also re-exports supported curves in [supported_curves] module (requires
//! enabling a feature), but any other curve implementation will work with the crate.
//!
//! ### Features
//! * `std`: enables std library support (mainly, it just implements [`Error`](std::error::Error)
//!   trait for the error types)
//! * `curve-secp256k1` and `curve-secp256r1` add curve implementation into the crate [supported_curves]
//!   module
//!
//! ### Examples
//!
//! Derive a master key from the seed, and then derive a child key m/1<sub>H</sub>/10:
//! ```rust
//! use slip_10::supported_curves::Secp256k1;
//!
//! let seed = b"16-64 bytes of high entropy".as_slice();
//! let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
//! let master_key_pair = slip_10::ExtendedKeyPair::from(master_key);
//!
//! let child_key_pair = slip_10::derive_child_key_pair_with_path(
//!     &master_key_pair,
//!     [1 + slip_10::H, 10],
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [slip10-spec]: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//! [bip32-spec]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(missing_docs, unsafe_code)]

use core::ops;

use generic_array::{
    typenum::{U32, U64},
    GenericArray,
};
use generic_ec::{Curve, Point, Scalar, SecretScalar};
use hmac::Mac as _;

#[cfg(any(
    feature = "curve-secp256k1",
    feature = "curve-secp256r1",
    feature = "all-curves"
))]
pub use generic_ec::curves as supported_curves;

pub mod errors;

type HmacSha512 = hmac::Hmac<sha2::Sha512>;
/// Beggining of hardened child indexes
///
/// $H = 2^{31}$ defines the range of hardened indexes. All indexes $i$ such that $H \le i$ are hardened.
///
/// ## Example
/// Derive a child key with a path m/1<sub>H</sub>
/// ```rust
/// use slip_10::supported_curves::Secp256k1;
///
/// # let seed = b"do not use this seed in prod :)".as_slice();
/// let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
/// let master_key_pair = slip_10::ExtendedKeyPair::from(master_key);
///
/// let hardened_child = slip_10::derive_child_key_pair(
///     &master_key_pair,
///     1 + slip_10::H,
/// );
/// #
/// # Ok::<(), slip_10::errors::InvalidLength>(())
/// ```
pub const H: u32 = 1 << 31;

/// Child index, whether hardened or not
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(into = "u32"))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(from = "u32"))]
pub enum ChildIndex {
    /// Hardened index
    Hardened(HardenedIndex),
    /// Non-hardened index
    NonHardened(NonHardenedIndex),
}

/// Child index in range $2^{31} \le i < 2^{32}$ corresponing to a hardened wallet
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(into = "u32"))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(try_from = "u32"))]
pub struct HardenedIndex(u32);

/// Child index in range $0 \le i < 2^{31}$ corresponing to a non-hardened wallet
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(into = "u32"))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(try_from = "u32"))]
pub struct NonHardenedIndex(u32);

/// Extended public key
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct ExtendedPublicKey<E: Curve> {
    /// The public key that can be used for signature verification
    pub public_key: Point<E>,
    /// A chain code that is used to derive child keys
    pub chain_code: ChainCode,
}

/// Extended secret key
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct ExtendedSecretKey<E: Curve> {
    /// The secret key that can be used for signing
    pub secret_key: SecretScalar<E>,
    /// A chain code that is used to derive child keys
    pub chain_code: ChainCode,
}

/// Pair of extended secret and public keys
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct ExtendedKeyPair<E: Curve> {
    public_key: ExtendedPublicKey<E>,
    secret_key: ExtendedSecretKey<E>,
}

/// A shift that can be applied to parent key to obtain a child key
///
/// It contains an already derived child public key as it needs to be derived
/// in process of calculating the shift value
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct DerivedShift<E: Curve> {
    /// Derived shift
    pub shift: Scalar<E>,
    /// Derived child extended public key
    pub child_public_key: ExtendedPublicKey<E>,
}

/// Chain code of extended key as defined in SLIP-10
pub type ChainCode = [u8; 32];

impl HardenedIndex {
    /// The smallest possible value of hardened index. Equals to $2^{31}$
    pub const MIN: Self = Self(H);
    /// The largest possible value of hardened index. Equals to $2^{32} - 1$
    pub const MAX: Self = Self(u32::MAX);
}
impl NonHardenedIndex {
    /// The smallest possible value of non-hardened index. Equals to $0$
    pub const MIN: Self = Self(0);
    /// The largest possible value of non-hardened index. Equals to $2^{31} - 1$
    pub const MAX: Self = Self(H - 1);
}
impl ops::Deref for HardenedIndex {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ops::Deref for NonHardenedIndex {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ops::Deref for ChildIndex {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Hardened(i) => i,
            Self::NonHardened(i) => i,
        }
    }
}
impl From<u32> for ChildIndex {
    fn from(value: u32) -> Self {
        match value {
            H.. => Self::Hardened(HardenedIndex(value)),
            _ => Self::NonHardened(NonHardenedIndex(value)),
        }
    }
}
impl TryFrom<u32> for HardenedIndex {
    type Error = errors::OutOfRange;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match ChildIndex::from(value) {
            ChildIndex::Hardened(v) => Ok(v),
            _ => Err(errors::OutOfRange),
        }
    }
}
impl TryFrom<u32> for NonHardenedIndex {
    type Error = errors::OutOfRange;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match ChildIndex::from(value) {
            ChildIndex::NonHardened(v) => Ok(v),
            _ => Err(errors::OutOfRange),
        }
    }
}
impl From<ChildIndex> for u32 {
    fn from(value: ChildIndex) -> Self {
        match value {
            ChildIndex::Hardened(v) => v.0,
            ChildIndex::NonHardened(v) => v.0,
        }
    }
}
impl From<HardenedIndex> for u32 {
    fn from(value: HardenedIndex) -> Self {
        value.0
    }
}
impl From<NonHardenedIndex> for u32 {
    fn from(value: NonHardenedIndex) -> Self {
        value.0
    }
}
impl core::str::FromStr for ChildIndex {
    type Err = core::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(Into::into)
    }
}
impl core::str::FromStr for HardenedIndex {
    type Err = errors::ParseChildIndexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let index = s
            .parse::<u32>()
            .map_err(errors::ParseChildIndexError::ParseInt)?;
        HardenedIndex::try_from(index).map_err(errors::ParseChildIndexError::IndexNotInRange)
    }
}
impl core::str::FromStr for NonHardenedIndex {
    type Err = errors::ParseChildIndexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let index = s
            .parse::<u32>()
            .map_err(errors::ParseChildIndexError::ParseInt)?;
        NonHardenedIndex::try_from(index).map_err(errors::ParseChildIndexError::IndexNotInRange)
    }
}

impl<E: Curve> From<&ExtendedSecretKey<E>> for ExtendedPublicKey<E> {
    fn from(sk: &ExtendedSecretKey<E>) -> Self {
        ExtendedPublicKey {
            public_key: Point::generator() * &sk.secret_key,
            chain_code: sk.chain_code,
        }
    }
}

impl<E: Curve> From<ExtendedSecretKey<E>> for ExtendedKeyPair<E> {
    fn from(secret_key: ExtendedSecretKey<E>) -> Self {
        Self {
            public_key: (&secret_key).into(),
            secret_key,
        }
    }
}

impl<E: Curve> ExtendedKeyPair<E> {
    /// Returns chain code of the key
    pub fn chain_code(&self) -> &ChainCode {
        debug_assert_eq!(self.public_key.chain_code, self.secret_key.chain_code);
        &self.public_key.chain_code
    }

    /// Returns extended public key
    pub fn public_key(&self) -> &ExtendedPublicKey<E> {
        &self.public_key
    }

    /// Returns extended secret key
    pub fn secret_key(&self) -> &ExtendedSecretKey<E> {
        &self.secret_key
    }
}

/// Marker for a curve supported by SLIP10 specs and this library
///
/// Only implement this trait for the curves that are supported by SLIP10 specs.
/// Curves provided by the crate out-of-box in [supported_curves] module already
/// implement this trait.
pub trait SupportedCurve {
    /// Specifies which curve it is
    const CURVE_TYPE: CurveType;
}
#[cfg(feature = "curve-secp256k1")]
impl SupportedCurve for supported_curves::Secp256k1 {
    const CURVE_TYPE: CurveType = CurveType::Secp256k1;
}
#[cfg(feature = "curve-secp256r1")]
impl SupportedCurve for supported_curves::Secp256r1 {
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
pub fn derive_master_key<E: Curve + SupportedCurve>(
    seed: &[u8],
) -> Result<ExtendedSecretKey<E>, errors::InvalidLength> {
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
pub fn derive_master_key_with_curve_tag<E: Curve>(
    curve_tag: &[u8],
    seed: &[u8],
) -> Result<ExtendedSecretKey<E>, errors::InvalidLength> {
    if !(16 <= seed.len() && seed.len() <= 64) {
        return Err(errors::InvalidLength);
    }

    let hmac = HmacSha512::new_from_slice(curve_tag)
        .expect("this never fails: hmac can handle keys of any size");
    let mut i = hmac.clone().chain_update(seed).finalize().into_bytes();

    loop {
        let (i_left, i_right) = split_into_two_halfes(&i);

        if let Ok(mut sk) = Scalar::<E>::from_be_bytes(i_left) {
            if !bool::from(subtle::ConstantTimeEq::ct_eq(&sk, &Scalar::zero())) {
                return Ok(ExtendedSecretKey {
                    secret_key: SecretScalar::new(&mut sk),
                    chain_code: (*i_right).into(),
                });
            }
        }

        i = hmac.clone().chain_update(&i[..]).finalize().into_bytes()
    }
}

/// Derives child key pair (extended secret key + public key) from parent key pair
///
/// ### Example
/// Derive child key m/1<sub>H</sub> from master key
/// ```rust
/// use slip_10::supported_curves::Secp256k1;
///
/// # let seed = b"do not use this seed :)".as_slice();
/// let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
/// let master_key_pair = slip_10::ExtendedKeyPair::from(master_key);
///
/// let derived_key = slip_10::derive_child_key_pair(
///     &master_key_pair,
///     1 + slip_10::H,
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn derive_child_key_pair<E: Curve>(
    parent_key: &ExtendedKeyPair<E>,
    child_index: impl Into<ChildIndex>,
) -> ExtendedKeyPair<E> {
    let child_index = child_index.into();
    let shift = match child_index {
        ChildIndex::Hardened(i) => derive_hardened_shift(parent_key, i),
        ChildIndex::NonHardened(i) => derive_public_shift(&parent_key.public_key, i),
    };
    let mut child_sk = &parent_key.secret_key.secret_key + shift.shift;
    let child_sk = SecretScalar::new(&mut child_sk);
    ExtendedKeyPair {
        secret_key: ExtendedSecretKey {
            secret_key: child_sk,
            chain_code: shift.child_public_key.chain_code,
        },
        public_key: shift.child_public_key,
    }
}

/// Derives a child key pair with specified derivation path from parent key pair
///
/// Derivation path is an iterator that yields child indexes.
///
/// If derivation path is empty, `parent_key` is returned
///
/// ### Example
/// Derive a child key with path m/1/10/1<sub>H</sub>
/// ```rust
/// use slip_10::supported_curves::Secp256k1;
/// # let seed = b"16-64 bytes of high entropy".as_slice();
/// let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
/// let master_key_pair = slip_10::ExtendedKeyPair::from(master_key);
///
/// let child_key = slip_10::derive_child_key_pair_with_path(
///     &master_key_pair,
///     [1, 10, 1 + slip_10::H],
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn derive_child_key_pair_with_path<E: Curve>(
    parent_key: &ExtendedKeyPair<E>,
    path: impl IntoIterator<Item = impl Into<ChildIndex>>,
) -> ExtendedKeyPair<E> {
    let result = try_derive_child_key_pair_with_path(
        parent_key,
        path.into_iter().map(Ok::<_, core::convert::Infallible>),
    );
    match result {
        Ok(key) => key,
        Err(err) => match err {},
    }
}

/// Derives a child key pair with specified derivation path from parent key pair
///
/// Derivation path is a fallible iterator that yields child indexes. If iterator
/// yields an error, it's propagated to the caller.
///
/// ### Example
/// Parse a path from the string and derive a child without extra allocations:
/// ```rust
/// use slip_10::supported_curves::Secp256k1;
/// # let seed = b"16-64 bytes of high entropy".as_slice();
/// let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
/// let master_key_pair = slip_10::ExtendedKeyPair::from(master_key);
///
/// let path = "1/10/2";
/// let child_indexes = path.split('/').map(str::parse::<u32>);
/// let child_key = slip_10::try_derive_child_key_pair_with_path(
///     &master_key_pair,
///     child_indexes,
/// )?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub fn try_derive_child_key_pair_with_path<E: Curve, Err>(
    parent_key: &ExtendedKeyPair<E>,
    path: impl IntoIterator<Item = Result<impl Into<ChildIndex>, Err>>,
) -> Result<ExtendedKeyPair<E>, Err> {
    let mut derived_key = parent_key.clone();
    for child_index in path {
        derived_key = derive_child_key_pair(&derived_key, child_index?);
    }
    Ok(derived_key)
}

/// Derives child extended public key from parent extended public key
///
/// ### Example
/// Derive a master public key m/1
/// ```rust
/// use slip_10::supported_curves::Secp256k1;
///
/// # let seed = b"do not use this seed :)".as_slice();
/// let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
/// let master_public_key = slip_10::ExtendedPublicKey::from(&master_key);
///
/// let derived_key = slip_10::derive_child_public_key(
///     &master_public_key,
///     1.try_into()?,
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn derive_child_public_key<E: Curve>(
    parent_public_key: &ExtendedPublicKey<E>,
    child_index: NonHardenedIndex,
) -> ExtendedPublicKey<E> {
    derive_public_shift(parent_public_key, child_index).child_public_key
}

/// Derives a child public key with specified derivation path
///
/// Derivation path is an iterator that yields child indexes.
///
/// If derivation path is empty, `parent_public_key` is returned
///
/// ### Example
/// Derive a child key with path m/1/10
/// ```rust
/// use slip_10::supported_curves::Secp256k1;
/// # let seed = b"16-64 bytes of high entropy".as_slice();
/// let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
/// let master_public_key = slip_10::ExtendedPublicKey::from(&master_key);
///
/// let child_key = slip_10::derive_child_public_key_with_path(
///     &master_public_key,
///     [1.try_into()?, 10.try_into()?],
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn derive_child_public_key_with_path<E: Curve>(
    parent_public_key: &ExtendedPublicKey<E>,
    path: impl IntoIterator<Item = NonHardenedIndex>,
) -> ExtendedPublicKey<E> {
    let result = try_derive_child_public_key_with_path(
        parent_public_key,
        path.into_iter().map(Ok::<_, core::convert::Infallible>),
    );
    match result {
        Ok(key) => key,
        Err(err) => match err {},
    }
}

/// Derives a child public key with specified derivation path
///
/// Derivation path is a fallible iterator that yields child indexes. If iterator
/// yields an error, it's propagated to the caller.
///
/// ### Example
/// Parse a path from the string and derive a child without extra allocations:
/// ```rust
/// use slip_10::supported_curves::Secp256k1;
/// # let seed = b"16-64 bytes of high entropy".as_slice();
/// let master_key = slip_10::derive_master_key::<Secp256k1>(seed)?;
/// let master_public_key = slip_10::ExtendedPublicKey::from(&master_key);
///
/// let path = "1/10/2";
/// let child_indexes = path.split('/').map(str::parse);
/// let child_key = slip_10::try_derive_child_public_key_with_path(
///     &master_public_key,
///     child_indexes,
/// )?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
pub fn try_derive_child_public_key_with_path<E: Curve, Err>(
    parent_public_key: &ExtendedPublicKey<E>,
    path: impl IntoIterator<Item = Result<NonHardenedIndex, Err>>,
) -> Result<ExtendedPublicKey<E>, Err> {
    let mut derived_key = *parent_public_key;
    for child_index in path {
        derived_key = derive_child_public_key(&derived_key, child_index?);
    }
    Ok(derived_key)
}

/// Derive a shift for hardened child
pub fn derive_hardened_shift<E: Curve>(
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
    calculate_shift(&hmac, &parent_key.public_key, *child_index, i)
}

/// Derives a shift for non-hardened child
pub fn derive_public_shift<E: Curve>(
    parent_public_key: &ExtendedPublicKey<E>,
    child_index: NonHardenedIndex,
) -> DerivedShift<E> {
    let hmac = HmacSha512::new_from_slice(&parent_public_key.chain_code)
        .expect("this never fails: hmac can handle keys of any size");
    let i = hmac
        .clone()
        .chain_update(&parent_public_key.public_key.to_bytes(true))
        .chain_update(child_index.to_be_bytes())
        .finalize()
        .into_bytes();
    calculate_shift(&hmac, parent_public_key, *child_index, i)
}

fn calculate_shift<E: Curve>(
    hmac: &HmacSha512,
    parent_public_key: &ExtendedPublicKey<E>,
    child_index: u32,
    mut i: hmac::digest::Output<HmacSha512>,
) -> DerivedShift<E> {
    loop {
        let (i_left, i_right) = split_into_two_halfes(&i);

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

/// Splits array `I` of 64 bytes into two arrays `I_L = I[..32]` and `I_R = I[32..]`
fn split_into_two_halfes(
    i: &GenericArray<u8, U64>,
) -> (&GenericArray<u8, U32>, &GenericArray<u8, U32>) {
    generic_array::sequence::Split::split(i)
}
