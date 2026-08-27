use serde::{Deserialize, Serialize};

/// How certain a `Finding` is, given the evidence behind it. This is the
/// type that keeps the investigation engine honest structurally: a
/// `Finding` can only be constructed with one of these variants, so there
/// is no code path that presents a guess with the confidence of an
/// observation.
///
/// Variants are declared weakest-to-strongest so the derived `Ord` orders
/// them that way (`Unknown < Likely < Correlated < Observed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    /// Data was insufficient to say anything stronger than this.
    Unknown,
    /// A pattern that matches a documented heuristic threshold, but is not
    /// certain (e.g. ">50% growth in 60 minutes" flagged as a likely
    /// leak — could still be legitimate cache warm-up).
    Likely,
    /// Two or more `Observed` facts combined without inference (e.g. "RSS
    /// grew from 100MB to 200MB between these two timestamps").
    Correlated,
    /// Directly read from a kernel/system source this instant (e.g. "RSS
    /// is 512MB right now" from `/proc/[pid]/status`).
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Notice,
    Warning,
    Critical,
}

/// A single piece of raw data backing a `Finding`, so a caller can always
/// show "why do you say that" down to the exact source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Where this came from, e.g. `"/proc/1234/status"` or
    /// `"dmesg (OOM killer)"`.
    pub source: String,
    /// Unix timestamp (seconds) this evidence was collected.
    pub collected_at: i64,
    /// Human-readable description of what this evidence shows.
    pub description: String,
    /// The raw value read, verbatim, before any interpretation.
    pub raw: String,
}

/// The output of an investigation-engine rule: a claim, backed by
/// evidence, carrying an honest confidence level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub narrative: String,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    /// Constructs a `Finding`. Panics in debug builds if `evidence` is
    /// empty and `confidence` is anything above `Unknown` — a stronger
    /// claim than "unknown" must always point at something, since an
    /// evidence-free `Likely`/`Correlated`/`Observed` finding is exactly
    /// the "claim more certainty than the data supports" failure this type
    /// exists to prevent.
    pub fn new(
        severity: Severity,
        title: impl Into<String>,
        narrative: impl Into<String>,
        confidence: Confidence,
        evidence: Vec<Evidence>,
    ) -> Self {
        debug_assert!(
            confidence == Confidence::Unknown || !evidence.is_empty(),
            "a Finding with confidence above Unknown must carry evidence"
        );
        Self {
            severity,
            title: title.into(),
            narrative: narrative.into(),
            confidence,
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_orders_from_weakest_to_strongest() {
        assert!(Confidence::Unknown < Confidence::Likely);
        assert!(Confidence::Likely < Confidence::Correlated);
        assert!(Confidence::Correlated < Confidence::Observed);
    }

    #[test]
    #[should_panic(expected = "must carry evidence")]
    fn finding_new_panics_on_unsupported_confidence() {
        Finding::new(
            Severity::Warning,
            "title",
            "narrative",
            Confidence::Likely,
            vec![],
        );
    }

    #[test]
    fn finding_new_allows_unknown_without_evidence() {
        let finding = Finding::new(
            Severity::Info,
            "title",
            "narrative",
            Confidence::Unknown,
            vec![],
        );
        assert_eq!(finding.confidence, Confidence::Unknown);
    }

    #[test]
    fn finding_json_round_trip() {
        let finding = Finding::new(
            Severity::Warning,
            "Sustained memory growth",
            "RSS grew 62% in the last 60 minutes",
            Confidence::Likely,
            vec![Evidence {
                source: "/proc/1234/status".into(),
                collected_at: 1_700_000_000,
                description: "VmRSS reading".into(),
                raw: "VmRSS:  512000 kB".into(),
            }],
        );
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }
}
