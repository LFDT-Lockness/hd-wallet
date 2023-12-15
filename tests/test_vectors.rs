use generic_ec::Curve;
use hex_literal::hex;

struct TestVector {
    curve_type: slip10::CurveType,
    seed: &'static [u8],
    derivations: &'static [Derivation],
}

struct Derivation {
    path: &'static [u32],

    expected_chain_code: slip10::ChainCode,
    expected_secret_key: [u8; 32],
    expected_public_key: [u8; 33],
}

/// Test vectors defined in
/// https://github.com/satoshilabs/slips/blob/817d54acc9989793288910a40f9eb59bebef3c6e/slip-0010.md#test-vectors
const TEST_VECTORS: &[TestVector] = &[
    // Test vector 1 for secp256k1
    TestVector {
        seed: &hex!("000102030405060708090a0b0c0d0e0f"),
        curve_type: slip10::CurveType::Secp256k1,
        derivations: &[
            Derivation {
                path: &[],
                expected_chain_code: hex!(
                    "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
                ),
                expected_secret_key: hex!(
                    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
                ),
                expected_public_key: hex!(
                    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
                ),
            },
            Derivation {
                path: &[0 + slip10::H],
                expected_chain_code: hex!(
                    "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
                ),
                expected_secret_key: hex!(
                    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
                ),
                expected_public_key: hex!(
                    "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1],
                expected_chain_code: hex!(
                    "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
                ),
                expected_secret_key: hex!(
                    "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
                ),
                expected_public_key: hex!(
                    "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1, 2 + slip10::H],
                expected_chain_code: hex!(
                    "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"
                ),
                expected_secret_key: hex!(
                    "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
                ),
                expected_public_key: hex!(
                    "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1, 2 + slip10::H, 2],
                expected_chain_code: hex!(
                    "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"
                ),
                expected_secret_key: hex!(
                    "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
                ),
                expected_public_key: hex!(
                    "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1, 2 + slip10::H, 2, 1000000000],
                expected_chain_code: hex!(
                    "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
                ),
                expected_secret_key: hex!(
                    "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
                ),
                expected_public_key: hex!(
                    "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
                ),
            },
        ],
    },
    // Test vector 1 for nist256p1
    TestVector {
        curve_type: slip10::CurveType::Secp256r1,
        seed: &hex!("000102030405060708090a0b0c0d0e0f"),
        derivations: &[
            Derivation {
                path: &[],
                expected_chain_code: hex!(
                    "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea"
                ),
                expected_secret_key: hex!(
                    "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2"
                ),
                expected_public_key: hex!(
                    "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"
                ),
            },
            Derivation {
                path: &[0 + slip10::H],
                expected_chain_code: hex!(
                    "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11"
                ),
                expected_secret_key: hex!(
                    "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c"
                ),
                expected_public_key: hex!(
                    "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1],
                expected_chain_code: hex!(
                    "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c"
                ),
                expected_secret_key: hex!(
                    "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129"
                ),
                expected_public_key: hex!(
                    "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1, 2 + slip10::H],
                expected_chain_code: hex!(
                    "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318"
                ),
                expected_secret_key: hex!(
                    "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7"
                ),
                expected_public_key: hex!(
                    "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1, 2 + slip10::H, 2],
                expected_chain_code: hex!(
                    "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0"
                ),
                expected_secret_key: hex!(
                    "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa"
                ),
                expected_public_key: hex!(
                    "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20"
                ),
            },
            Derivation {
                path: &[0 + slip10::H, 1, 2 + slip10::H, 2, 1000000000],
                expected_chain_code: hex!(
                    "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059"
                ),
                expected_secret_key: hex!(
                    "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119"
                ),
                expected_public_key: hex!(
                    "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4"
                ),
            },
        ],
    },
    // Test vector 2 for secp256k1
    TestVector {
        curve_type: slip10::CurveType::Secp256k1,
        seed: &hex!(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ),
        derivations: &[
            Derivation {
                path: &[],
                expected_chain_code: hex!(
                    "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
                ),
                expected_secret_key: hex!(
                    "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
                ),
                expected_public_key: hex!(
                    "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"
                ),
            },
            Derivation {
                path: &[0],
                expected_chain_code: hex!(
                    "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"
                ),
                expected_secret_key: hex!(
                    "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"
                ),
                expected_public_key: hex!(
                    "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"
                ),
            },
            Derivation {
                path: &[0, 2147483647 + slip10::H],
                expected_chain_code: hex!(
                    "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9"
                ),
                expected_secret_key: hex!(
                    "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"
                ),
                expected_public_key: hex!(
                    "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"
                ),
            },
            Derivation {
                path: &[0, 2147483647 + slip10::H, 1],
                expected_chain_code: hex!(
                    "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb"
                ),
                expected_secret_key: hex!(
                    "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"
                ),
                expected_public_key: hex!(
                    "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"
                ),
            },
            Derivation {
                path: &[0, 2147483647 + slip10::H, 1, 2147483646 + slip10::H],
                expected_chain_code: hex!(
                    "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"
                ),
                expected_secret_key: hex!(
                    "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"
                ),
                expected_public_key: hex!(
                    "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
                ),
            },
            Derivation {
                path: &[0, 2147483647 + slip10::H, 1, 2147483646 + slip10::H, 2],
                expected_chain_code: hex!(
                    "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
                ),
                expected_secret_key: hex!(
                    "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
                ),
                expected_public_key: hex!(
                    "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
                ),
            },
        ],
    },
    // Test derivation retry for nist256p1
    TestVector {
        curve_type: slip10::CurveType::Secp256r1,
        seed: &hex!("000102030405060708090a0b0c0d0e0f"),
        derivations: &[
            Derivation {
                path: &[],
                expected_chain_code: hex!(
                    "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea"
                ),
                expected_secret_key: hex!(
                    "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2"
                ),
                expected_public_key: hex!(
                    "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"
                ),
            },
            Derivation {
                path: &[28578 + slip10::H],
                expected_chain_code: hex!(
                    "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2"
                ),
                expected_secret_key: hex!(
                    "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669"
                ),
                expected_public_key: hex!(
                    "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7"
                ),
            },
            Derivation {
                path: &[28578 + slip10::H, 33941],
                expected_chain_code: hex!(
                    "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071"
                ),
                expected_secret_key: hex!(
                    "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a"
                ),
                expected_public_key: hex!(
                    "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120"
                ),
            },
        ],
    },
    // Test seed retry for nist256p1
    TestVector {
        curve_type: slip10::CurveType::Secp256r1,
        seed: &hex!("a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446"),
        derivations: &[Derivation {
            path: &[],
            expected_chain_code: hex!(
                "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c"
            ),
            expected_secret_key: hex!(
                "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f"
            ),
            expected_public_key: hex!(
                "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20"
            ),
        }],
    },
];

#[test]
fn test_vectors() {
    for vector in TEST_VECTORS {
        match vector.curve_type {
            slip10::CurveType::Secp256k1 => {
                run_vector::<slip10::supported_curves::Secp256k1>(vector)
            }
            slip10::CurveType::Secp256r1 => {
                run_vector::<slip10::supported_curves::Secp256r1>(vector)
            }
        }
    }
}

fn run_vector<E: Curve + slip10::SupportedCurve>(v: &TestVector) {
    let master_key = slip10::derive_master_key::<E>(&v.seed).unwrap();
    let master_key_pair = slip10::ExtendedKeyPair::from(master_key);

    for derivation in v.derivations {
        let mut key = master_key_pair.clone();

        for &child_index in derivation.path {
            key = slip10::derive_child_key_pair(&key, child_index);
        }

        assert_eq!(key.chain_code(), &derivation.expected_chain_code);
        assert_eq!(
            &key.public_key().public_key.to_bytes(true)[..],
            &derivation.expected_public_key,
        );
        assert_eq!(
            &key.secret_key().secret_key.as_ref().to_be_bytes()[..],
            &derivation.expected_secret_key,
        );
    }
}
