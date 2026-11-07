use bankshield_gate::{decide, score, Decision, Signals};

fn main() {
    // One sensitive payment signal set with full proof and low risk.
    let payment = Signals {
        r: "pay".to_string(),
        pk: 1,
        dp: 1,
        dt: 1,
        sk: 1,
        nr: 0,
        dm: 0,
        hl: 0,
        mb: 0,
        dc: 0,
        rpm: 10,
        cov: 0,
        tv: 1.0,
        ov: 0,
        np: 0,
        amt: 5000,
    };
    let d = decide(&payment);
    println!(
        "sensitive payment with full proof: score={} decision={}",
        score(&payment),
        d.as_str()
    );
    assert_eq!(d, Decision::Allow);

    // One replay case: nonce replayed must BLOCK regardless of other signals.
    let replay = Signals {
        nr: 1,
        ..payment.clone()
    };
    let d2 = decide(&replay);
    println!(
        "replay case: score={} decision={} (expected BLOCK)",
        score(&replay),
        d2.as_str()
    );
    assert_eq!(d2, Decision::Block);
    println!("example OK: ALLOW case and BLOCK replay case as expected");
}
