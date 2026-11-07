use bankshield_gate::{decide, Decision, Signals};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct VectorCase {
    #[serde(rename = "i")]
    i: i64,
    #[serde(rename = "g", default)]
    #[allow(dead_code)]
    g: String,
    #[serde(rename = "k", default)]
    #[allow(dead_code)]
    k: String,
    #[serde(rename = "t", default)]
    #[allow(dead_code)]
    t: String,
    #[serde(rename = "s")]
    s: Signals,
    #[serde(rename = "e")]
    e: String,
}

fn expected_to_decision(e: &str) -> Decision {
    match e {
        "A" => Decision::Allow,
        "C" => Decision::Challenge,
        "B" => Decision::Block,
        other => panic!("unknown expected code: {}", other),
    }
}

fn vectors_path() -> PathBuf {
    if let Ok(p) = std::env::var("BSG_VECTORS") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    // Integration tests run with the crate root as working directory.
    PathBuf::from("../shared/test_vectors.json")
}

#[test]
fn shared_vectors() {
    let path = vectors_path();
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read vectors file {:?}: {}", path, err));
    let cases: Vec<VectorCase> = serde_json::from_str(&data)
        .unwrap_or_else(|err| panic!("failed to parse vectors file {:?}: {}", path, err));

    let mut allow_count = 0usize;
    let mut challenge_count = 0usize;
    let mut block_count = 0usize;

    for case in &cases {
        let expected = expected_to_decision(&case.e);
        let got = decide(&case.s);
        assert_eq!(
            got, expected,
            "case i={} expected {} ({}) got {} score={} signals={:?}",
            case.i,
            case.e,
            expected.as_str(),
            got.as_str(),
            bankshield_gate::score(&case.s),
            case.s
        );
        match got {
            Decision::Allow => allow_count += 1,
            Decision::Challenge => challenge_count += 1,
            Decision::Block => block_count += 1,
        }
    }

    eprintln!(
        "verified {} cases: ALLOW={} CHALLENGE={} BLOCK={}",
        cases.len(),
        allow_count,
        challenge_count,
        block_count
    );
}
