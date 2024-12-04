use generic_ec::Curve;
use rug::{ops::DivRounding, Complete};

fn main() {
    println!(
        "========================\n\n\
        This tool analyzes curves parameters, which should help determining the best HD \
        derivation algorithm to use. It provides following characteristics per each curve:\n\
        - Probability that rand(32 bytes) correspond to an invalid scalar on that curve\n\
        - Statistical difference of rand(N bytes) mod curve_order distribution with uniform \
          distribution\n\
          \n\
        After observing the parameters, skilled conscious observer makes a decision which \
        HD derivation algorithm works the best for that curve, but the general guidelines are:\n\
        1. If probability that random 32 bytes do not correspond to a valid scalar is greater than \
           2^-32, DO NOT use slip10-like derivation or any other algorithm based on rejection sampling\n\
        2. DO NOT use `rand(N bytes) mod curve_order` if statistical difference of its distribution with \
           uniform is greater than 2^-80\n\
        \n========================"
    );

    analyze_curve::<generic_ec::curves::Secp256k1>([32]);
    analyze_curve::<generic_ec::curves::Secp256r1>([32]);
    analyze_curve::<generic_ec::curves::Stark>(32..=48);
    analyze_curve::<generic_ec::curves::Ed25519>([32]);

    assert_eq!(
        48,
        recommended_random_string_size::<generic_ec::curves::Stark>()
    )
}

/// How many random bytes we need to have distribution indistinguishable from uniform when we take
/// the bytes mod curve order
///
/// This function is taken from hash to curve RFC9380: https://datatracker.ietf.org/doc/rfc9380/ (see
/// section 5)
fn recommended_random_string_size<E: Curve>() -> usize {
    let order: rug::Integer = {
        let order_minus_one = -generic_ec::Scalar::<E>::one();
        let bytes_be = order_minus_one.to_be_bytes();
        let order_minus_one = rug::Integer::from_digits::<u8>(&bytes_be, rug::integer::Order::Msf);
        order_minus_one + 1
    };
    let order_log2 = order.significant_bits();
    let l: rug::Integer = rug::Rational::from((order_log2 + 128, 8)).ceil_ref().into();
    l.try_into().unwrap()
}

fn analyze_curve<E: Curve>(rand_bytes: impl IntoIterator<Item = usize>) {
    println!();
    println!("Curve: {}", E::CURVE_NAME);

    let order: rug::Integer = {
        let order_minus_one = -generic_ec::Scalar::<E>::one();
        let bytes_be = order_minus_one.to_be_bytes();
        let order_minus_one = rug::Integer::from_digits::<u8>(&bytes_be, rug::integer::Order::Msf);
        order_minus_one + 1
    };

    {
        let prob = rug::Rational::from((
            rug::Integer::from(rug::Integer::ONE << 256) - &order,
            rug::Integer::from(rug::Integer::ONE << 256),
        ));
        println!(
            "Probability that random 32 bytes are invalid scalar: {prob_num} in 2^256: {prob_f64:.4} in range {prob_range}",
            prob_num = prob.numer(),
            prob_f64 = prob.to_f64(),
            prob_range = find_closest_power_of_minus_two_str(&prob),
        );
    }

    println!("order = {order}");

    for rand_bytes in rand_bytes {
        let rand_bits = rand_bytes * 8;
        let rand_mod: rug::Integer = (rug::Integer::ONE << rand_bits).into();

        let (n, w) = rand_mod.div_rem_ref(&order).complete();

        let prob_uniform = rug::Rational::from((rug::Integer::ONE, &order));
        println!("When we take rand({rand_bytes} bytes) modulo curve_order, we have distribution:");
        {
            let prob_actual = rug::Rational::from((&n + 1, &rand_mod));
            println!(
                "- for any y < w, Pr[x = y] = {} in 2^{rand_bits}, diff with uniform in range: {range}",
                rug::Integer::from(&n + 1),
                range = find_closest_power_of_minus_two_str(&(prob_actual - &prob_uniform).abs())
            );
        }
        {
            let prob_actual = rug::Rational::from((&n, &rand_mod));
            println!(
                "- for any y >= w, Pr[x = y] = {n} in 2^{rand_bits}, diff with uniform in range: {range}",
                range = find_closest_power_of_minus_two_str(&(prob_actual - &prob_uniform).abs())
            );
        }
        println!("where w = {w}");

        let stat_diff = {
            let before_w_per_each =
                (rug::Rational::from((&n + 1, &rand_mod)) - &prob_uniform).abs();
            let before_w = &w * before_w_per_each;

            let after_w_per_each = (rug::Rational::from((&n, &rand_mod)) - &prob_uniform).abs();
            let after_w = (&order - &w).complete() * after_w_per_each;

            (before_w + after_w) / 2
        };

        println!(
            "statistical difference between actual and uniform distribution is in range: {}",
            find_closest_power_of_minus_two_str(&stat_diff)
        );

        assert_eq!(stat_diff, stat_diff_from_book(&rand_mod, &order));
    }
}

/// Given 0 < x < 1, returns `lo`, `hi` such that 2^-lo <= x <= 2^-hi
fn find_closest_power_of_minus_two(x: &rug::Rational) -> (u32, u32) {
    assert!(x.is_positive() && x < rug::Rational::ONE);

    for (lo, hi) in (1..).zip(0..) {
        let x_lo = rug::Rational::from((rug::Integer::ONE, rug::Integer::ONE << lo));
        let x_hi = rug::Rational::from((rug::Integer::ONE, rug::Integer::ONE << hi));
        if x_lo <= *x && *x <= x_hi {
            return (lo, hi);
        }
    }

    unreachable!()
}

/// Same as [`find_closest_power_of_minus_two`] but returns a formatted repr of the range
fn find_closest_power_of_minus_two_str(x: &rug::Rational) -> String {
    let (lo, hi) = find_closest_power_of_minus_two(x);
    format!("2^-{lo}..2^-{hi}")
}

/// Formula taken from some book. I have no idea how it works, but we check if it produces the same result
/// as the other formula which is more understandable but less compact
fn stat_diff_from_book(a: &rug::Integer, b: &rug::Integer) -> rug::Rational {
    let c = a.div_ceil(b).complete();
    let f = a.div_floor(b).complete();

    (rug::Rational::from((&c, a)) - rug::Rational::from((1, b))) * (a - (&f * b).complete())
}
