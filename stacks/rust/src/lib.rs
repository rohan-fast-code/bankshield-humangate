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

/// Returns true if the route is sensitive.
pub fn is_sensitive(route: &str) -> bool {
    matches!(route, "pay" | "trf" | "ben" | "exp" | "sec")
}

/// Compute the risk score exactly as specified.
///
/// hl 40; mb 15; dc 10; rpm>60 adds 20; rpm>150 adds another 20;
/// cov>70 adds 30; tv<0.2 AND rpm>20 adds 25; ov 20; np 15;
/// dp==0 adds 30; dt==0 adds 20. `amt` is never scored.
pub fn score(s: &Signals) -> i32 {
    let mut total: i32 = 0;
    if s.hl == 1 {
        total += 40;
    }
    if s.mb == 1 {
        total += 15;
    }
    if s.dc == 1 {
        total += 10;
    }
    if s.rpm > 60 {
        total += 20;
    }
    if s.rpm > 150 {
        total += 20;
    }
    if s.cov > 70 {
        total += 30;
    }
    if s.tv < 0.2 && s.rpm > 20 {
        total += 25;
    }
    if s.ov == 1 {
        total += 20;
    }
    if s.np == 1 {
        total += 15;
    }
    if s.dp == 0 {
        total += 30;
    }
    if s.dt == 0 {
        total += 20;
    }
    total
}

/// Decide in the exact order specified:
///
/// (1) dm==1 -> BLOCK.
/// (2) nr==1 -> BLOCK.
/// (3) sk==0 -> BLOCK.
/// (4) Sensitive route: full proof means pk==1 and dp==1 and dt==1;
///     if full proof and score<50 -> ALLOW;
///     else if score>=80 -> BLOCK; else CHALLENGE.
/// (5) Non sensitive route: score>=80 -> BLOCK else ALLOW.
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
