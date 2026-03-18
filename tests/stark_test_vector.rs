use hd_wallet::HdWallet;
use hex_literal::hex;

struct TestVector {
    root_secret_key: [u8; 32],
    root_public_key: [u8; 33],
    chain_code: hd_wallet::ChainCode,
    derivations: &'static [Derivation],
}

struct Derivation {
    path: &'static [u32],

    expected_secret_key: [u8; 32],
    expected_public_key: [u8; 33],
    expected_chain_code: [u8; 32],
}

/// These test vectors were obtained by running:
///
/// ```bash
/// cargo run --all-features --example generate_test_vectors
/// ```
const TEST_VECTORS: &[TestVector] = &[TestVector {
    root_secret_key: hex!("0488a73eebe871ec429b37cdbd1dc160d4d2faa34556c8e9a76e8cd51b6cfbb8"),
    root_public_key: hex!("0205c89b4a3d5f4650cd63a48baf0df21280ce0fb85ea872853de3ce18e1e61223"),
    chain_code: hex!("9e88c71e0435e16662469e464ba3bd242b4c99f6ff54960cb682edceb42223ed"),
    derivations: &[
        // Non-hardened derivation
        Derivation {
            path: &[0],
            expected_secret_key: hex!(
                "0597872991a7759365513efb163a8c28b14f10b969f11da6fd3653f92e2d57ca"
            ),
            expected_public_key: hex!(
                "030625a1ed01a061183d9b8bfc87ea6fa3a788195250516415ed6e196a070de55f"
            ),
            expected_chain_code: hex!(
                "fed5a2ca5e8321c7f95c46539047eb50faf13e026e3d41d075540c1a9cf1d380"
            ),
        },
        Derivation {
            path: &[1],
            expected_secret_key: hex!(
                "07e57c758044ba70ea08e0edb43ea1eb1a38d118d431560bcbcd6785cc999b70"
            ),
            expected_public_key: hex!(
                "0203cdcfb32317c7b7d5ada6218145e89bae0190b97e1c0b3b982018a59b279975"
            ),
            expected_chain_code: hex!(
                "b615bd8245089297147a77915bda2ffc0a142e1d333844b31a964e601ff89987"
            ),
        },
        Derivation {
            path: &[2],
            expected_secret_key: hex!(
                "06b2ba84b7b0c1df4e3c8c579a6f53e7c8181bc816008050499c80c2426009c8"
            ),
            expected_public_key: hex!(
                "02072fafedc815e5817cb3203b328074c7a9deca71f93f3a9729a6910323c4f5aa"
            ),
            expected_chain_code: hex!(
                "5ca62c03e8c03bbb2717fedda726d28ce76982ac45ae69110ab48320470fc17d"
            ),
        },
        Derivation {
            path: &[1951614227, 785687956, 1701190516, 997951189],
            expected_secret_key: hex!(
                "07eddf7b3dec89605d3d15392d9ed3e985407775a58dbaea51ad55e415b45494"
            ),
            expected_public_key: hex!(
                "030430e999917068df34f32c35beff2a1caf0d2cd4ed0defe666249d63e031379b"
            ),
            expected_chain_code: hex!(
                "c1fac37faab34cdbf2d8cfc39a16dce21b615604cd07e4586729ff3f03582594"
            ),
        },
        Derivation {
            path: &[2122015632, 1105344888, 1598870552, 200678536],
            expected_secret_key: hex!(
                "0691c9420bf4f47011cb0448993b8f141a15c072ffe22cb417e05979327b426c"
            ),
            expected_public_key: hex!(
                "0305343fd6ac0ed00978277e62366c029b151044119b339fec8e61254168318a7b"
            ),
            expected_chain_code: hex!(
                "b25e59c29f1894a5d716c2e72d251f34ee8be02194e474329607f7c707a37c59"
            ),
        },
        // Hardened derivation
        Derivation {
            path: &[hd_wallet::H],
            expected_secret_key: hex!(
                "0075fc3585d3bedd04c7cd0d7fe871f3e52d5ab9c4bfcc6cc626957cbe45545c"
            ),
            expected_public_key: hex!(
                "030789614405216d8cc36454c4108975c0d2d66035ecd6a2bd8c3dca628b3ab546"
            ),
            expected_chain_code: hex!(
                "ebe602cef4168ba94fb3b43b442ad67bd91f62039896887a140baa1c4585c470"
            ),
        },
        Derivation {
            path: &[1 + hd_wallet::H],
            expected_secret_key: hex!(
                "03e9223be5643943972f68584119c2b349ea4dedf9be0a52943c125fed0a1998"
            ),
            expected_public_key: hex!(
                "03017457b4d6f24a0a9e449e1b2dba89afef7fd985d5500569285365913d454829"
            ),
            expected_chain_code: hex!(
                "c71dde186014797faf2d54629600c31e5277c54c7274136c61a46a6a358dec34"
            ),
        },
        Derivation {
            path: &[2 + hd_wallet::H],
            expected_secret_key: hex!(
                "0005ed54ac0e6f1570447183c678e33eb370b7d5d6772ba1fb27b856f0bf74dd"
            ),
            expected_public_key: hex!(
                "02066f79bdeae47d079560e09b9ecde60ec4ac536fa6ac5794d7c850300cabdbce"
            ),
            expected_chain_code: hex!(
                "26b7f3e97f5ab4db4c3308799e7cc6e45be74787a1eafd6d14dcc34a8a598cca"
            ),
        },
        // Mixed hardened and non-hardened derivation
        Derivation {
            path: &[
                251411281,
                923229946 + hd_wallet::H,
                496028387,
                1163470860 + hd_wallet::H,
            ],
            expected_secret_key: hex!(
                "01bf3dce889f48ce16cd2df102b32b2362fb805a9bf33474d391891bd650cbf6"
            ),
            expected_public_key: hex!(
                "02038b86fc2cf121a2216660d7fe8a2f68c28b80f645641a8e9554bbc2bae2a56e"
            ),
            expected_chain_code: hex!(
                "021b195e90deec762d078f51d729720f5d5ed3b9d44a98725b9abc90a596e4ff"
            ),
        },
        Derivation {
            path: &[
                182835681,
                2001004627,
                826457658 + hd_wallet::H,
                1973700623 + hd_wallet::H,
            ],
            expected_secret_key: hex!(
                "07ac0e9e7b6792efdacb187b7bd44fbc9841f79ca7fbe8f0f016dc6f3ac8dbeb"
            ),
            expected_public_key: hex!(
                "0307637c9e9df9184aa631dff4be452cc47b5f03e8dae8b6a78f9e4f8e7c0d8471"
            ),
            expected_chain_code: hex!(
                "cc63852ec5ce6ac12af2b068c7f54fc5011356c717f9d7f43ab1471d412a85af"
            ),
        },
    ],
}];

#[test]
fn test_vectors() {
    for vector in TEST_VECTORS {
        let mut root_sk =
            generic_ec::Scalar::<generic_ec::curves::Stark>::from_be_bytes(vector.root_secret_key)
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
            let child_key = hd_wallet::Stark::derive_child_key_pair_with_path(
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
            assert_eq!(
                hex::encode(child_key.chain_code()),
                hex::encode(derivation.expected_chain_code)
            );
        }
    }
}
