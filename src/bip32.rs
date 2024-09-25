//! BIP32-specific functions

use generic_ec::core::Reduce;
use hmac::Mac as _;

/// Derives a master key from the seed
///
/// Seed must be 16-64 bytes long, otherwise an error is returned
pub fn derive_master_key(
    seed: &[u8],
) -> Result<crate::ExtendedSecretKey<generic_ec::curves::Secp256k1>, crate::errors::InvalidLength> {
    if !(16 <= seed.len() && seed.len() <= 64) {
        return Err(crate::errors::InvalidLength);
    }

    let i = crate::HmacSha512::new_from_slice(b"Bitcoin seed")
        .expect("this never fails: hmac can handle keys of any size")
        .chain_update(seed)
        .finalize()
        .into_bytes();
    let (i_left, i_right) = crate::split_into_two_halves(&i);
    let i_left: [u8; 32] = (*i_left).into();
    Ok(crate::ExtendedSecretKey {
        secret_key: generic_ec::SecretScalar::new(
            &mut generic_ec::Scalar::from_be_array_mod_order(&i_left),
        ),
        chain_code: (*i_right).into(),
    })
}
