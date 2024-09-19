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
pub use generic_ec::curves;

pub mod errors;
pub mod slip10;

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// Beginning of hardened child indexes
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

/// Child index in range $2^{31} \le i < 2^{32}$ corresponding to a hardened wallet
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(into = "u32"))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(try_from = "u32"))]
pub struct HardenedIndex(u32);

/// Child index in range $0 \le i < 2^{31}$ corresponding to a non-hardened wallet
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

#[cfg(feature = "serde")]
impl<E: Curve> serde::Serialize for ExtendedKeyPair<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.secret_key.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, E: Curve> serde::Deserialize<'de> for ExtendedKeyPair<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let secret_key = ExtendedSecretKey::<E>::deserialize(deserializer)?;
        Ok(secret_key.into())
    }
}

/// Type of HD wallet, like [BIP32] or [SLIP10]
pub trait HdWallet<E: Curve>: DeriveShift<E> {
    /// Derives a shift for non-hardened child
    ///
    /// Returns error if child key is not defined for given child index
    fn derive_public_shift(
        parent_public_key: &ExtendedPublicKey<E>,
        child_index: NonHardenedIndex,
    ) -> Result<DerivedShift<E>, Self::DeriveErr> {
        let hmac = HmacSha512::new_from_slice(&parent_public_key.chain_code)
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .clone()
            .chain_update(&parent_public_key.public_key.to_bytes(true))
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift(&hmac, parent_public_key, *child_index, i)
    }

    /// Derive a shift for hardened child
    ///
    /// Returns error if child key is not defined for given child index
    fn derive_hardened_shift(
        parent_key: &ExtendedKeyPair<E>,
        child_index: HardenedIndex,
    ) -> Result<DerivedShift<E>, Self::DeriveErr> {
        let hmac = HmacSha512::new_from_slice(parent_key.chain_code())
            .expect("this never fails: hmac can handle keys of any size");
        let i = hmac
            .clone()
            .chain_update([0x00])
            .chain_update(parent_key.secret_key.secret_key.as_ref().to_be_bytes())
            .chain_update(child_index.to_be_bytes())
            .finalize()
            .into_bytes();
        Self::calculate_shift(&hmac, &parent_key.public_key, *child_index, i)
    }

    /// Derives child extended public key from parent extended public key
    ///
    /// Returns error if child key is not defined for given child index
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
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn derive_child_public_key(
        parent_public_key: &ExtendedPublicKey<E>,
        child_index: NonHardenedIndex,
    ) -> Result<ExtendedPublicKey<E>, Self::DeriveErr> {
        Self::derive_public_shift(parent_public_key, child_index).map(|c| c.child_public_key)
    }

    /// Derives child key pair (extended secret key + public key) from parent key pair
    ///
    /// Returns error if child key is not defined for given child index
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
    fn derive_child_key_pair(
        parent_key: &ExtendedKeyPair<E>,
        child_index: impl Into<ChildIndex>,
    ) -> Result<ExtendedKeyPair<E>, Self::DeriveErr> {
        let child_index = child_index.into();
        let shift = match child_index {
            ChildIndex::Hardened(i) => Self::derive_hardened_shift(parent_key, i)?,
            ChildIndex::NonHardened(i) => Self::derive_public_shift(&parent_key.public_key, i)?,
        };
        let mut child_sk = &parent_key.secret_key.secret_key + shift.shift;
        let child_sk = SecretScalar::new(&mut child_sk);
        Ok(ExtendedKeyPair {
            secret_key: ExtendedSecretKey {
                secret_key: child_sk,
                chain_code: shift.child_public_key.chain_code,
            },
            public_key: shift.child_public_key,
        })
    }

    /// Derives a child key pair with specified derivation path from parent key pair
    ///
    /// Derivation path is a fallible iterator that yields child indexes. If iterator
    /// yields an error, it's propagated to the caller.
    ///
    /// Returns:
    /// * `Ok(Ok(child_key_pair))` if derivation was successful
    /// * `Ok(Err(derive_err))` if child key is not defined for given path
    /// * `Err(index_err)` if path contained `Err(index_err)`
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
    /// )??;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    fn try_derive_child_key_pair_with_path<Err>(
        parent_key: &ExtendedKeyPair<E>,
        path: impl IntoIterator<Item = Result<impl Into<ChildIndex>, Err>>,
    ) -> Result<Result<ExtendedKeyPair<E>, Self::DeriveErr>, Err> {
        let mut derived_key = parent_key.clone();
        for child_index in path {
            derived_key = match Self::derive_child_key_pair(&derived_key, child_index?) {
                Ok(k) => k,
                Err(err) => return Ok(Err(err)),
            };
        }
        Ok(Ok(derived_key))
    }

    /// Derives a child key pair with specified derivation path from parent key pair
    ///
    /// Derivation path is an iterator that yields child indexes.
    ///
    /// If derivation path is empty, `parent_key` is returned
    ///
    /// Returns error if child key is not defined for given child index
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
    fn derive_child_key_pair_with_path(
        parent_key: &ExtendedKeyPair<E>,
        path: impl IntoIterator<Item = impl Into<ChildIndex>>,
    ) -> Result<ExtendedKeyPair<E>, Self::DeriveErr> {
        let result = Self::try_derive_child_key_pair_with_path(
            parent_key,
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
    /// Returns:
    /// * `Ok(Ok(child_pk))` if derivation was successful
    /// * `Ok(Err(derive_err))` if child key is not defined for given path
    /// * `Err(index_err)` if path contained `Err(index_err)`
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
    fn try_derive_child_public_key_with_path<Err>(
        parent_public_key: &ExtendedPublicKey<E>,
        path: impl IntoIterator<Item = Result<NonHardenedIndex, Err>>,
    ) -> Result<Result<ExtendedPublicKey<E>, Self::DeriveErr>, Err> {
        let mut derived_key = *parent_public_key;
        for child_index in path {
            derived_key = match Self::derive_child_public_key(&derived_key, child_index?) {
                Ok(k) => k,
                Err(index_err) => return Ok(Err(index_err)),
            };
        }
        Ok(Ok(derived_key))
    }

    /// Derives a child public key with specified derivation path
    ///
    /// Derivation path is an iterator that yields child indexes.
    ///
    /// If derivation path is empty, `parent_public_key` is returned
    ///
    /// Returns error if child key is not defined for given child index
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
    fn derive_child_public_key_with_path(
        parent_public_key: &ExtendedPublicKey<E>,
        path: impl IntoIterator<Item = NonHardenedIndex>,
    ) -> Result<ExtendedPublicKey<E>, Self::DeriveErr> {
        let result = Self::try_derive_child_public_key_with_path(
            parent_public_key,
            path.into_iter().map(Ok::<_, core::convert::Infallible>),
        );
        match result {
            Ok(key) => key,
            Err(err) => match err {},
        }
    }
}

impl<E: Curve, S: DeriveShift<E>> HdWallet<E> for S {}

/// Core functionality of HD wallet derivation, everything is defined on top of it
pub trait DeriveShift<E: Curve> {
    /// Shift derivation error
    type DeriveErr;

    /// Calculates an additive shift
    ///
    /// Returns an error if shift is not defined for given inputs
    fn calculate_shift(
        hmac: &HmacSha512,
        parent_public_key: &ExtendedPublicKey<E>,
        child_index: u32,
        i: hmac::digest::Output<HmacSha512>,
    ) -> Result<DerivedShift<E>, Self::DeriveErr>;
}

/// SLIP10-like HD wallet derivation
///
/// SLIP10 standard is only defined for a specific set of curves and key types, however,
/// it can be extended to support any curve. `Slip10Like` works with any curve, not limited
/// to what defined in the standard. When instantiated with secp256k1 or secp256r1 curves,
/// it follows exactly SLIP10 derivation rules.
///
/// ## Constraints
/// `Slip10Like` must be used with curves which operate on 32 bytes scalars.
///
/// `Slip10Like` is not recommended to be used with curves with order significantly lower
/// than $2^{256}$ as it worsens the performance.
///
/// ## Ed25519 curve
/// Although `Slip10Like` will work on ed25519 curve, we do not recommend using it, because:
/// 1. it's confusing as ed25519 curve is defined in SLIP10, however,
///    `Slip10Like<Ed25519>` will not follow SLIP10 standard
/// 2. it's quite inefficient
///
/// Prefer using [`Edwards`](Edwards) derivation method for ed25519 curve.
pub struct Slip10Like;

impl<E: Curve> DeriveShift<E> for Slip10Like {
    /// Slip10 derivation is always defined
    type DeriveErr = core::convert::Infallible;

    fn calculate_shift(
        hmac: &HmacSha512,
        parent_public_key: &ExtendedPublicKey<E>,
        child_index: u32,
        mut i: hmac::digest::Output<HmacSha512>,
    ) -> Result<DerivedShift<E>, Self::DeriveErr> {
        loop {
            let (i_left, i_right) = split_into_two_halves(&i);

            if let Ok(shift) = Scalar::<E>::from_be_bytes(i_left) {
                let child_pk = parent_public_key.public_key + Point::generator() * shift;
                if !child_pk.is_zero() {
                    return Ok(DerivedShift {
                        shift,
                        child_public_key: ExtendedPublicKey {
                            public_key: child_pk,
                            chain_code: (*i_right).into(),
                        },
                    });
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

/// [SLIP10][slip10-spec] HD wallet derivation
///
/// Performs HD derivation as defined in the spec. Refer to [`slip10`] module for more details.
pub struct Slip10;

#[cfg(feature = "curve-secp256k1")]
impl DeriveShift<generic_ec::curves::Secp256k1> for Slip10 {
    type DeriveErr = core::convert::Infallible;
    fn calculate_shift(
        hmac: &HmacSha512,
        parent_public_key: &ExtendedPublicKey<generic_ec::curves::Secp256k1>,
        child_index: u32,
        i: hmac::digest::Output<HmacSha512>,
    ) -> Result<DerivedShift<generic_ec::curves::Secp256k1>, Self::DeriveErr> {
        Slip10Like::calculate_shift(hmac, parent_public_key, child_index, i)
    }
}
#[cfg(feature = "curve-secp256r1")]
impl DeriveShift<generic_ec::curves::Secp256r1> for Slip10 {
    type DeriveErr = core::convert::Infallible;
    fn calculate_shift(
        hmac: &HmacSha512,
        parent_public_key: &ExtendedPublicKey<generic_ec::curves::Secp256r1>,
        child_index: u32,
        i: hmac::digest::Output<HmacSha512>,
    ) -> Result<DerivedShift<generic_ec::curves::Secp256r1>, Self::DeriveErr> {
        Slip10Like::calculate_shift(hmac, parent_public_key, child_index, i)
    }
}

/// Splits array `I` of 64 bytes into two arrays `I_L = I[..32]` and `I_R = I[32..]`
fn split_into_two_halves(
    i: &GenericArray<u8, U64>,
) -> (&GenericArray<u8, U32>, &GenericArray<u8, U32>) {
    generic_array::sequence::Split::split(i)
}
