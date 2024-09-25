//! When something goes wrong

use core::fmt;

/// Length of the argument is not valid
#[derive(Debug)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLength {}

/// Value was out of range
#[derive(Debug)]
pub struct OutOfRange;

impl fmt::Display for OutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("out of range")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutOfRange {}

/// Error returned by parsing child index
#[derive(Debug)]
pub enum ParseChildIndexError {
    /// Indicates that parsing an `u32` integer failed
    ParseInt(core::num::ParseIntError),
    /// Parsed index was out of acceptable range
    IndexNotInRange(OutOfRange),
}

impl fmt::Display for ParseChildIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseInt(_) => f.write_str("child index is not valid u32 integer"),
            Self::IndexNotInRange(_) => f.write_str("child index is not in acceptable range"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseChildIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseChildIndexError::ParseInt(e) => Some(e),
            ParseChildIndexError::IndexNotInRange(e) => Some(e),
        }
    }
}

/// Error indicating that HD derivation is not defined for given parent key and child path
///
/// This error may occur in [Bip32](crate::Bip32) derivation, only with negligible probability
#[derive(Debug)]
pub struct UndefinedChildKey;

impl fmt::Display for UndefinedChildKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("child key is not defined for given parent key and child path")
    }
}
