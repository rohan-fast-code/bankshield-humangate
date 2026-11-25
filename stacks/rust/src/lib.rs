use serde::{Deserialize, Serialize};

/// Signals for the shared gate specification.
///
/// Field names in JSON use the short names from the specification.
/// `tv` is a float (`f64`), `r` is a string, all other fields are integers
/// (booleans encoded as 0/1 in JSON). `amt` is informational and never scored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signals {
    /// Route: pay, trf, ben, exp, sec are sensitive; view, login, prof are not.
    #[serde(rename = "r", default)]
    pub r: String,
    /// Passkey proof.
    #[serde(rename = "pk", default)]
    pub pk: i32,
    /// Device proof valid.
    #[serde(rename = "dp", default)]
    pub dp: i32,
    /// Device bound token valid.
    #[serde(rename = "dt", default)]
    pub dt: i32,
    /// Session key signature valid.
    #[serde(rename = "sk", default)]
    pub sk: i32,
    /// Nonce replayed.
    #[serde(rename = "nr", default)]
    pub nr: i32,
    /// Token device mismatch.
    #[serde(rename = "dm", default)]
    pub dm: i32,
    /// Headless.
    #[serde(rename = "hl", default)]
    pub hl: i32,
    /// Missing browser signals.
    #[serde(rename = "mb", default)]
    pub mb: i32,
    /// Datacenter IP.
    #[serde(rename = "dc", default)]
    pub dc: i32,
    /// Requests per minute.
    #[serde(rename = "rpm", default)]
    pub rpm: i32,
    /// API coverage percent.
    #[serde(rename = "cov", default)]
    pub cov: i32,
    /// Timing variance seconds.
    #[serde(rename = "tv", default)]
    pub tv: f64,
    /// Overlay abuse detected.
    #[serde(rename = "ov", default)]
    pub ov: i32,
    /// New payee.
    #[serde(rename = "np", default)]
    pub np: i32,
    /// Amount in rupees (informational, never scored).
    #[serde(rename = "amt", default)]
    pub amt: i32,
    /// Spec v2: approval relationship or beneficiary changed recently.
    #[serde(rename = "ac", default)]
    pub ac: i32,
    /// Spec v2: disbursement destination changed from the approved one.
    #[serde(rename = "dd", default)]
    pub dd: i32,
    /// Spec v2: agent acting beyond its authorized task scope.
    #[serde(rename = "ag", default)]
    pub ag: i32,
    /// Spec v2: inbound content contains embedded instructions.
    #[serde(rename = "pi", default)]
    pub pi: i32,
    /// Spec v2: mule chain pattern, rapid hops across accounts.
    #[serde(rename = "mc", default)]
    pub mc: i32,
    /// Spec v2: record deletion or tampering attempt.
    #[serde(rename = "rd", default)]
    pub rd: i32,
}

impl Default for Signals {
    fn default() -> Self {
        Self {
            r: String::new(),
            pk: 0,
            dp: 0,
            dt: 0,
            sk: 0,
            nr: 0,
            dm: 0,
            hl: 0,
            mb: 0,
            dc: 0,
            rpm: 0,
            cov: 0,
            tv: 0.0,
            ov: 0,
            np: 0,
            amt: 0,
            ac: 0,
            dd: 0,
            ag: 0,
            pi: 0,
            mc: 0,
            rd: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Challenge,
    Block,
}

impl Decision {
    /// Map a decision to its canonical string: ALLOW, CHALLENGE, or BLOCK.
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Challenge => "CHALLENGE",
            Decision::Block => "BLOCK",
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Helper to map a `Decision` to the strings ALLOW, CHALLENGE, BLOCK.
pub fn decision_to_str(d: &Decision) -> &'static str {
    d.as_str()
}

/// Risk weights (spec v2) as compile-time constants.
///
/// Performance note: the gate decision is O(1) per request. All risk
/// weights are compile-time constants, the sensitive-route check below
/// is a constant `matches!` table, and `decide`/`score` do fixed
/// straight-line arithmetic over the signal fields only: no loops, no
/// I/O, no regular expressions, and no per-request allocation in the hot
/// path (`decide` takes `&Signals` and returns a `Copy` enum). Nothing
/// is computed per request that could be precomputed. The runtime gate
/// never loads the shared test vector file; vectors are test data only.
const WEIGHT_HEADLESS: i32 = 40;
const WEIGHT_MISSING_BROWSER: i32 = 15;
const WEIGHT_DATACENTER: i32 = 10;
const WEIGHT_RPM_OVER_60: i32 = 20;
const WEIGHT_RPM_OVER_150: i32 = 20;
const WEIGHT_COVERAGE_OVER_70: i32 = 30;
const WEIGHT_LOW_TIMING_VAR: i32 = 25;
const WEIGHT_OVERLAY: i32 = 20;
const WEIGHT_NEW_PAYEE: i32 = 15;
const WEIGHT_NO_DEVICE_PROOF: i32 = 30;
const WEIGHT_NO_DEVICE_TOKEN: i32 = 20;
const WEIGHT_APPROVAL_CHANGED: i32 = 25;
const WEIGHT_DEST_CHANGED: i32 = 50;
const WEIGHT_AGENT_SCOPE: i32 = 35;
const WEIGHT_PROMPT_INJECTION: i32 = 45;
const WEIGHT_MULE_CHAIN: i32 = 40;
const WEIGHT_RECORD_DELETION: i32 = 40;

/// Returns true if the route is sensitive.
///
/// The route set is a constant `matches!` table, evaluated per request
/// with no allocation, no I/O, and no lookup over any runtime data.
pub fn is_sensitive(route: &str) -> bool {
    matches!(route, "pay" | "trf" | "ben" | "exp" | "sec")
}

/// Compute the risk score exactly as specified.
///
/// hl 40; mb 15; dc 10; rpm>60 adds 20; rpm>150 adds another 20;
/// cov>70 adds 30; tv<0.2 AND rpm>20 adds 25; ov 20; np 15;
/// dp==0 adds 30; dt==0 adds 20. Spec v2: ac 25; dd 50; ag 35; pi 45;
/// mc 40; rd 40. `amt` is never scored.
pub fn score(s: &Signals) -> i32 {
    let mut total: i32 = 0;
    if s.hl == 1 {
        total += WEIGHT_HEADLESS;
    }
    if s.mb == 1 {
        total += WEIGHT_MISSING_BROWSER;
    }
    if s.dc == 1 {
        total += WEIGHT_DATACENTER;
    }
    if s.rpm > 60 {
        total += WEIGHT_RPM_OVER_60;
    }
    if s.rpm > 150 {
        total += WEIGHT_RPM_OVER_150;
    }
    if s.cov > 70 {
        total += WEIGHT_COVERAGE_OVER_70;
    }
    if s.tv < 0.2 && s.rpm > 20 {
        total += WEIGHT_LOW_TIMING_VAR;
    }
    if s.ov == 1 {
        total += WEIGHT_OVERLAY;
    }
    if s.np == 1 {
        total += WEIGHT_NEW_PAYEE;
    }
    if s.dp == 0 {
        total += WEIGHT_NO_DEVICE_PROOF;
    }
    if s.dt == 0 {
        total += WEIGHT_NO_DEVICE_TOKEN;
    }
    if s.ac == 1 {
        total += WEIGHT_APPROVAL_CHANGED;
    }
    if s.dd == 1 {
        total += WEIGHT_DEST_CHANGED;
    }
    if s.ag == 1 {
        total += WEIGHT_AGENT_SCOPE;
    }
    if s.pi == 1 {
        total += WEIGHT_PROMPT_INJECTION;
    }
    if s.mc == 1 {
        total += WEIGHT_MULE_CHAIN;
    }
    if s.rd == 1 {
        total += WEIGHT_RECORD_DELETION;
    }
    total
}

/// Decide in the exact order specified:
///
/// `decide` is O(1) per request: fixed straight-line checks, no loops,
/// no I/O, no regular expressions, and no per-request allocation; the
/// score is computed once by `score` and reused for the threshold checks.
///
/// (1) dm==1 -> BLOCK.
/// (2) nr==1 -> BLOCK.
/// (3) sk==0 -> BLOCK.
/// (4) Sensitive route: dd==1 -> BLOCK; mc==1 -> BLOCK; rd==1 -> BLOCK;
///     pi==1 -> BLOCK; ag==1 -> BLOCK; ac==1 -> never ALLOW (CHALLENGE at
///     minimum; BLOCK if score>=80).
/// (5) Sensitive route: full proof means pk==1 and dp==1 and dt==1;
///     if full proof and score<50 -> ALLOW;
///     else if score>=80 -> BLOCK; else CHALLENGE.
/// (6) Non sensitive route: score>=80 -> BLOCK else ALLOW.
pub fn decide(s: &Signals) -> Decision {
    if s.dm == 1 {
        return Decision::Block;
    }
    if s.nr == 1 {
        return Decision::Block;
    }
    if s.sk == 0 {
        return Decision::Block;
    }
    let sc = score(s);
    if is_sensitive(&s.r) {
        if s.dd == 1 {
            return Decision::Block;
        }
        if s.mc == 1 {
            return Decision::Block;
        }
        if s.rd == 1 {
            return Decision::Block;
        }
        if s.pi == 1 {
            return Decision::Block;
        }
        if s.ag == 1 {
            return Decision::Block;
        }
        if s.ac == 1 {
            if sc >= 80 {
                return Decision::Block;
            }
            return Decision::Challenge;
        }
        let full_proof = s.pk == 1 && s.dp == 1 && s.dt == 1;
        if full_proof && sc < 50 {
            return Decision::Allow;
        }
        if sc >= 80 {
            return Decision::Block;
        }
        Decision::Challenge
    } else {
        if sc >= 80 {
            return Decision::Block;
        }
        Decision::Allow
    }
}
