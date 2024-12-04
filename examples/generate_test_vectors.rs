use generic_ec::{Curve, Point, SecretScalar};
use rand::Rng;

fn main() {
    generate_test_vectors::<generic_ec::curves::Stark, hd_wallet::Stark>();
}

fn generate_test_vectors<E: Curve, Hd: hd_wallet::HdWallet<E>>() {
    let mut rng = rand::thread_rng();

    let sk = SecretScalar::<E>::random(&mut rng);
    let pk = Point::generator() * &sk;
    let chain_code: hd_wallet::ChainCode = rng.gen();

    println!("sk: {}", hex::encode(sk.as_ref().to_be_bytes()));
    println!("pk: {}", hex::encode(pk.to_bytes(true)));
    println!("chain code: {}", hex::encode(chain_code));

    let paths: &[&[u32]] = &[
        // Non-hardened derivation
        &[0],
        &[1],
        &[2],
        &[
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(0..hd_wallet::H),
        ],
        &[
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(0..hd_wallet::H),
        ],
        // Hardened derivation
        &[0 + hd_wallet::H],
        &[1 + hd_wallet::H],
        &[2 + hd_wallet::H],
        // Mixed hardened and non-hardened derivation
        &[
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(hd_wallet::H..=u32::MAX),
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(hd_wallet::H..=u32::MAX),
        ],
        &[
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(0..hd_wallet::H),
            rng.gen_range(hd_wallet::H..=u32::MAX),
            rng.gen_range(hd_wallet::H..=u32::MAX),
        ],
    ];

    let key = hd_wallet::ExtendedSecretKey {
        secret_key: sk,
        chain_code,
    };
    let key = hd_wallet::ExtendedKeyPair::from(key);
    assert_eq!(key.public_key().public_key, pk);

    for path in paths {
        println!("{:?}", PathFmt(path));
        let child_key = Hd::derive_child_key_pair_with_path(&key, path.iter().copied());
        println!(
            "child secret key: {}",
            hex::encode(child_key.secret_key().secret_key.as_ref().to_be_bytes())
        );
        println!(
            "child public key: {}",
            hex::encode(child_key.public_key().public_key.to_bytes(true))
        );
        println!("child chain code: {}", hex::encode(child_key.chain_code()));
        println!();
    }
}

struct PathFmt<'a>(&'a [u32]);

impl<'a> std::fmt::Debug for PathFmt<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (is_first, index) in std::iter::once(true)
            .chain(std::iter::repeat(false))
            .zip(self.0)
        {
            if !is_first {
                write!(f, ", ")?;
            }

            if *index < hd_wallet::H {
                write!(f, "{index}")?;
            } else {
                write!(
                    f,
                    "{} + hd_wallet::H",
                    index.checked_sub(hd_wallet::H).unwrap()
                )?;
            }
        }
        write!(f, "]")
    }
}
