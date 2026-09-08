use serde::{Deserialize, Serialize};

use crate::detector::AnomalyReport;

/// A command proposed to the Raft log when an anomaly is detected. Being
/// Raft-replicated (rather than each node just sealing itself locally)
/// is the entire point: every node in the cluster applies the same seal
/// decision in the same order, so a client that fails over to a
/// different node after a detection doesn't find a vault that's still
/// wide open there. The actual "apply this to local state" step (Phase
/// 7's `AppState.kek` being cleared) happens wherever a node processes
/// its committed log entries — this type only carries *what* was
/// decided and *why*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealCommand {
    pub reason: String,
    pub current_count: u32,
    pub baseline_mean: f64,
    pub z_score: f64,
}

impl SealCommand {
    pub fn from_report(reason: impl Into<String>, report: &AnomalyReport) -> Self {
        Self {
            reason: reason.into(),
            current_count: report.current_count,
            baseline_mean: report.baseline_mean,
            z_score: report.z_score,
        }
    }

    /// A fixed prefix on the serialized command bytes so a node applying
    /// committed log entries can distinguish a seal command from an
    /// ordinary secret-write command without needing a shared "command
    /// type" enum spanning every crate that proposes to the log. Simple
    /// and explicit rather than clever — the alternative (a single big
    /// tagged-union `Command` enum owned by, say, the `consensus` crate)
    /// would create a dependency from consensus back onto anomaly/api,
    /// which inverts the layering this project has kept clean so far.
    pub const COMMAND_TAG: &'static [u8] = b"SEAL:";

    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut bytes = Self::COMMAND_TAG.to_vec();
        bytes.extend(bincode::serialize(self)?);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let payload = bytes.strip_prefix(Self::COMMAND_TAG)?;
        bincode::deserialize(payload).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::AnomalyReport;

    fn sample_report() -> AnomalyReport {
        AnomalyReport { current_count: 40, baseline_mean: 2.0, baseline_stddev: 0.5, z_score: 76.0 }
    }

    #[test]
    fn encode_then_decode_round_trips() {
        let cmd = SealCommand::from_report("access rate anomaly", &sample_report());
        let bytes = cmd.encode().unwrap();
        let decoded = SealCommand::decode(&bytes).unwrap();
        assert_eq!(decoded.reason, "access rate anomaly");
        assert_eq!(decoded.current_count, 40);
        assert_eq!(decoded.z_score, 76.0);
    }

    #[test]
    fn decode_rejects_bytes_without_the_seal_tag() {
        let ordinary_command = b"some other command bytes".to_vec();
        assert!(SealCommand::decode(&ordinary_command).is_none());
    }

    #[test]
    fn decode_rejects_tagged_but_corrupt_payload() {
        let mut bytes = SealCommand::COMMAND_TAG.to_vec();
        bytes.extend_from_slice(b"not valid bincode");
        assert!(SealCommand::decode(&bytes).is_none());
    }
}