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
