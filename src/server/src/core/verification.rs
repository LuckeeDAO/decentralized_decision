//! 结果验证与证明模块
//!
//! - 承诺正确性验证
//! - 选择过程验证（重放）
//! - 结果完整性与算法正确性基础校验

use crate::core::selection_algorithms::{SelectionResult, Participant, SelectorFactory};
use crate::core::lottery_config::LevelParameters;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentProof {
    pub commitment: String,
    pub message_hash: String,
}

pub struct Verifier;

impl Verifier {
    pub fn verify_commitment(proof: &CommitmentProof, message: &[u8], randomness: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(message);
        let msg_hash = format!("{:x}", h.finalize());
        let mut h2 = Sha256::new();
        h2.update(message);
        h2.update(randomness);
        let commit = format!("{:x}", h2.finalize());
        proof.message_hash == msg_hash && proof.commitment == commit
    }

    pub fn verify_selection(
        results: &HashMap<String, SelectionResult>,
        participants: &[Participant],
        level_params: &HashMap<String, LevelParameters>,
    ) -> Result<bool, String> {
        // 对每个等级使用对应算法重放验证
        for (level, res) in results {
            let params = level_params.get(level).ok_or_else(|| format!("缺少等级参数: {}", level))?;
            let selector = SelectorFactory::create(&params.selection_algorithm);
            if !selector.verify(res, participants, params)? { return Ok(false); }
        }
        // 全局唯一性检查
        let mut ids = std::collections::HashSet::new();
        for r in results.values() {
            for w in &r.winners {
                if !ids.insert(&w.id) { return Ok(false); }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::lottery_config::SelectionAlgorithm;

    #[test]
    fn test_commitment_verify() {
        let msg = b"hello";
        let rand = b"salt";
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new(); h.update(msg); let msg_hash = format!("{:x}", h.finalize());
        let mut h2 = Sha256::new(); h2.update(msg); h2.update(rand); let commitment = format!("{:x}", h2.finalize());
        let proof = CommitmentProof { commitment, message_hash: msg_hash };
        assert!(Verifier::verify_commitment(&proof, msg, rand));
    }

    #[test]
    fn test_selection_verify_basic() {
        let mut params = HashMap::new();
        params.insert("L1".to_string(), LevelParameters {
            min_participants: 2,
            max_participants: None,
            winner_count: 1,
            selection_algorithm: SelectionAlgorithm::Random,
            algorithm_params: HashMap::new(),
            time_limit: None,
            cost_limit: None,
        });
        let participants = vec![
            Participant { id: "1".into(), address: "a1".into(), weight: 1.0, level: "L1".into(), attributes: HashMap::new(), is_winner: false },
            Participant { id: "2".into(), address: "a2".into(), weight: 1.0, level: "L1".into(), attributes: HashMap::new(), is_winner: false },
        ];
        // 生成一个结果
        let selector = SelectorFactory::create(&SelectionAlgorithm::Random);
        let res = selector.select(&participants, params.get("L1").unwrap(), "seed").unwrap();
        let mut map = HashMap::new(); map.insert("L1".to_string(), res);
        assert!(Verifier::verify_selection(&map, &participants, &params).unwrap());
    }
}


