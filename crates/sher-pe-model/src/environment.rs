use serde::{Deserialize, Serialize};

/// One `KEY=VALUE` entry from `/proc/[pid]/environ`. A typed struct rather
/// than a raw tuple to match every other public field this project
/// exposes, and to keep the JSON output self-documenting (`{"key": ...,
/// "value": ...}` instead of an ambiguous two-element array).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_json_round_trip() {
        let var = EnvVar {
            key: "PATH".into(),
            value: "/usr/bin:/bin".into(),
        };
        let json = serde_json::to_string(&var).unwrap();
        let back: EnvVar = serde_json::from_str(&json).unwrap();
        assert_eq!(var, back);
    }
}
