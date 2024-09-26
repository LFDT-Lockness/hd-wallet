use hd_wallet::HdWallet;
use hex_literal::hex;

struct TestVector {
    root_secret_key: [u8; 32],
    root_public_key: [u8; 32],
    chain_code: hd_wallet::ChainCode,
    derivations: &'static [Derivation],
}

struct Derivation {
    path: &'static [u32],

    expected_secret_key: [u8; 32],
    expected_public_key: [u8; 32],
}

const TEST_VECTORS: &[TestVector] = &[TestVector {
    root_secret_key: hex!("09ba1ad29fabe87a0cf23fec142db2adfb8f9e7089928000dcba5714e08236ec"),
    root_public_key: hex!("6fa093b0e855f5fdb40d77f6efe9b67b709092a71d73f35de6afc70cac40d57a"),
    chain_code: hex!("64ae4b48b206ef11f75059af10d209546586baf8418222c6f4b989b75d008ddd"),
    derivations: &[
        // Non-hardened derivation
        Derivation {
            path: &[0],
            expected_secret_key: hex!(
                "0542fcce4962a2e1785bc9d183e6d80f754d7ad70251b7d9239b434bc6b117d4"
            ),
            expected_public_key: hex!(
                "4fefbecb1d4a584b289e457ffe868d87b27ab421f66e32a078616552a837c7e2"
            ),
        },
        Derivation {
            path: &[1],
            expected_secret_key: hex!(
                "0a25f8ffae098918dff9b24afbe8dae365015f14b4b559f5097684747a62ec97"
            ),
            expected_public_key: hex!(
                "0dc358776f744c4d6c282dbca128d123a0ac38fd7cda5cf87805b82c70a0e2cd"
            ),
        },
        Derivation {
            path: &[2],
            expected_secret_key: hex!(
                "0b68998b58f5b96ec64b754d421339869a439c6249b843e78610c675d51f01f9"
            ),
            expected_public_key: hex!(
                "d634d478dfb41b9bc8cc6653febd00f89bf5bf8c6f665dbdf541a203abef0882"
            ),
        },
        Derivation {
            path: &[1245290303, 456055179, 1419108629, 261968456],
            expected_secret_key: hex!(
                "089f32db21f3027a39ee9a6bebae1ffa0bd07527120f5fe943a7d6363bd90ff6"
            ),
            expected_public_key: hex!(
                "4671c7c639c8421d16488a59618bc4d06dbae56741df740eea6be993eb99f734"
            ),
        },
        Derivation {
            path: &[1478344788, 731157828, 912233245, 1553129543],
            expected_secret_key: hex!(
                "04fe0f016a5b070f49f5b8f76de8862f5520661461b7914463d9ecd81a893f90"
            ),
            expected_public_key: hex!(
                "d983da0a4f2a368bbc5ada8af0c5a003adea602c2e7ad1feca60c73401dc606e"
            ),
        },
        // Hardened derivation
        Derivation {
            path: &[0 + hd_wallet::H],
            expected_secret_key: hex!(
                "098b5d8be3cd71cecf390facd083ca0e3e03cc78a10920094e2cee300f8de291"
            ),
            expected_public_key: hex!(
                "5963e6410d44538fec067ff59d54814de6dfd5daf03d693c655f44e2fd89ae86"
            ),
        },
        Derivation {
            path: &[1 + hd_wallet::H],
            expected_secret_key: hex!(
                "06928b571aa8659d2976ab000e27f962b62b9d4e61ce6ab76380bd5f9ab6b1f9"
            ),
            expected_public_key: hex!(
                "97d28095b4cc43ef45eb10da1b5c01ff85a0695472252f218c93f21a3ebe8a42"
            ),
        },
        Derivation {
            path: &[2 + hd_wallet::H],
            expected_secret_key: hex!(
                "009193ef5345093a2c787c93ff3099731a605ffde2836cbc5d4979ed9a20a3be"
            ),
            expected_public_key: hex!(
                "d98a33fcb65f6ace1c6599c5895c8cee338d34f6fd21f883f306086e2e0af2bf"
            ),
        },
        // Mixed hardened and non-hardened derivation
        Derivation {
            path: &[2805853951, 2012627329, 3396580781, 1663824773],
            expected_secret_key: hex!(
                "0f0e4dfa88132151409f014584d112152dbd78c238afc1fa095cc852c49ffd46"
            ),
            expected_public_key: hex!(
                "51b8f57fa35e2d95ed518dc9c0defcc7268e600781cb5d65f20f1e2898c92905"
            ),
        },
        Derivation {
            path: &[3136119273, 140597163, 2240167577, 148040763],
            expected_secret_key: hex!(
                "08019f789391f195786891702464f7302e669c51f3e8af7c7f6f46f8d14b0182"
            ),
            expected_public_key: hex!(
                "3b2cbb00f208011f4322a6c09020a437b1676e86e83f5d6953f94f3b1f0d4a39"
            ),
        },
    ],
}];

#[test]
fn test_vectors() {
    for vector in TEST_VECTORS {
        let mut root_sk = generic_ec::Scalar::<generic_ec::curves::Ed25519>::from_be_bytes(
            &vector.root_secret_key,
        )
        .expect("invalid root_sk");
        let root_sk = generic_ec::SecretScalar::new(&mut root_sk);

        let esk = hd_wallet::ExtendedSecretKey {
            secret_key: root_sk,
            chain_code: vector.chain_code,
        };
        let ekey = hd_wallet::ExtendedKeyPair::from(esk);

        assert_eq!(
            hex::encode(ekey.public_key().public_key.to_bytes(true)),
            hex::encode(vector.root_public_key)
        );

        for derivation in vector.derivations {
            eprintln!("path: {:?}", derivation.path);
            let child_key = hd_wallet::Edwards::derive_child_key_pair_with_path(
                &ekey,
                derivation.path.iter().copied(),
            );

            assert_eq!(
                hex::encode(child_key.secret_key().secret_key.as_ref().to_be_bytes()),
                hex::encode(derivation.expected_secret_key)
            );
            assert_eq!(
                hex::encode(child_key.public_key().public_key.to_bytes(true)),
                hex::encode(derivation.expected_public_key)
            );
        }
    }
}
