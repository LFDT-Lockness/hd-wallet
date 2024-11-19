use generic_ec::Curve;
use rug::Complete;

fn main() {
    analyze_curve::<generic_ec::curves::Secp256k1>();
    analyze_curve::<generic_ec::curves::Secp256r1>();
    analyze_curve::<generic_ec::curves::Stark>();
    analyze_curve::<generic_ec::curves::Ed25519>();
}

fn analyze_curve<E: Curve>() {
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
            "Probability that random 32 bytes are invalid scalar: {prob_nom} in 2^256: {prob_f64:.4} in range {prob_range}",
            prob_nom = prob.numer(),
            prob_f64 = prob.to_f64(),
            prob_range = find_closest_power_of_minus_two_str(&prob),
        );
    }

    let (n, w) = rug::Integer::from(rug::Integer::ONE << 256).div_rem(order.clone());
    let n = n.to_u32().unwrap();

    println!("order = {order}");
    println!("w = {w}");

    println!("When we take rand(32 bytes) modulo curve_order, we have distribution:");
    {
        let prob_actual = rug::Rational::from((n + 1, rug::Integer::ONE << 256));
        let prob_uniform = &rug::Rational::from((rug::Integer::ONE, &order));
        println!(
            "- for any y < w, Pr[x = y] = {} in 2^256, diff with uniform in range: {range}",
            n + 1,
            range = find_closest_power_of_minus_two_str(&(prob_actual - prob_uniform).abs())
        );
    }
    {
        let prob_actual = rug::Rational::from((n + 1, rug::Integer::ONE << 256));
        let prob_uniform = &rug::Rational::from((rug::Integer::ONE, &order));
        println!(
            "- for any y >= w, Pr[x = y] = {n} in 2^256, diff with uniform in range: {range}",
            range = find_closest_power_of_minus_two_str(&(prob_actual - prob_uniform).abs())
        );
    }

    let stat_diff = {
        let before_w_per_each = rug::Rational::from((n + 1, rug::Integer::ONE << 256))
            - rug::Rational::from((rug::Integer::ONE, &order));
        let before_w = (&w * before_w_per_each).abs();

        let after_w_per_each = rug::Rational::from((n, rug::Integer::ONE << 256))
            - rug::Rational::from((rug::Integer::ONE, &order));
        let after_w = ((&order - &w).complete() * after_w_per_each).abs();

        (before_w + after_w) / 2
    };

    println!("statistical difference of actual and uniform distribution = {stat_diff}");
    println!(
        "statistical difference lies in range: {}",
        find_closest_power_of_minus_two_str(&stat_diff)
    );
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
