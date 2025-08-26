//! 比特承诺协议实现
//! 
//! 实现承诺生成、验证、揭示等核心功能

use crate::types::{BitCommitment, CommitmentProof, VotingError};
use crate::crypto::{HashUtils, RandomUtils};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// 比特承诺协议实现
pub struct CommitmentProtocol;

impl CommitmentProtocol {
    /// 创建新的比特承诺
    pub fn create_commitment(message: &[u8]) -> Result<(BitCommitment, [u8; 32]), VotingError> {
        // 生成随机数
        let randomness = RandomUtils::random_32_bytes();
        
        // 计算消息哈希
        let message_hash = HashUtils::sha256(message);
        
        // 计算承诺: H(message || randomness)
        let mut combined = Vec::new();
        combined.extend_from_slice(message);
        combined.extend_from_slice(&randomness);
        let commitment = HashUtils::sha256(&combined);
        
        let bit_commitment = BitCommitment {
            commitment,
            opening: randomness,
            message_hash,
        };
        
        Ok((bit_commitment, randomness))
    }
    
    /// 验证比特承诺
    pub fn verify_commitment(commitment: &BitCommitment, message: &[u8], randomness: &[u8; 32]) -> bool {
        // 重新计算承诺
        let mut combined = Vec::new();
        combined.extend_from_slice(message);
        combined.extend_from_slice(randomness);
        let computed_commitment = HashUtils::sha256(&combined);
        
        // 验证承诺是否匹配
        computed_commitment == commitment.commitment
    }
    
    /// 揭示承诺
    pub fn reveal_commitment(commitment: &BitCommitment, randomness: &[u8; 32]) -> Result<Vec<u8>, VotingError> {
        // 验证随机数是否匹配
        if randomness != &commitment.opening {
            return Err(VotingError::InvalidReveal);
        }
        
        // 这里我们无法直接恢复原始消息，因为承诺是单向的
        // 在实际应用中，原始消息应该由承诺者保存
        // 这里返回一个占位符，表示揭示成功
        Ok(vec![1u8]) // 表示揭示成功
    }
    
    /// 创建承诺证明
    pub fn create_proof(commitment: &BitCommitment, message: &[u8], randomness: &[u8; 32]) -> Result<CommitmentProof, VotingError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VotingError::StorageError)?
            .as_secs();
        
        Ok(CommitmentProof {
            commitment: commitment.commitment,
            opening: *randomness,
            message: message.to_vec(),
            timestamp,
        })
    }
    
    /// 验证承诺证明
    pub fn verify_proof(proof: &CommitmentProof) -> bool {
        // 验证承诺
        let mut combined = Vec::new();
        combined.extend_from_slice(&proof.message);
        combined.extend_from_slice(&proof.opening);
        let computed_commitment = HashUtils::sha256(&combined);
        
        computed_commitment == proof.commitment
    }
}

/// 承诺管理器
pub struct CommitmentManager {
    commitments: HashMap<String, BitCommitment>,
    proofs: HashMap<String, CommitmentProof>,
}

impl CommitmentManager {
    /// 创建新的承诺管理器
    pub fn new() -> Self {
        Self {
            commitments: HashMap::new(),
            proofs: HashMap::new(),
        }
    }
    
    /// 存储承诺
    pub fn store_commitment(&mut self, id: &str, commitment: BitCommitment) {
        self.commitments.insert(id.to_string(), commitment);
    }
    
    /// 获取承诺
    pub fn get_commitment(&self, id: &str) -> Option<&BitCommitment> {
        self.commitments.get(id)
    }
    
    /// 存储证明
    pub fn store_proof(&mut self, id: &str, proof: CommitmentProof) {
        self.proofs.insert(id.to_string(), proof);
    }
    
    /// 获取证明
    pub fn get_proof(&self, id: &str) -> Option<&CommitmentProof> {
        self.proofs.get(id)
    }
    
    /// 验证承诺
    pub fn verify_commitment(&self, id: &str, message: &[u8], randomness: &[u8; 32]) -> bool {
        if let Some(commitment) = self.get_commitment(id) {
            CommitmentProtocol::verify_commitment(commitment, message, randomness)
        } else {
            false
        }
    }
    
    /// 批量验证承诺
    pub fn batch_verify_commitments(&self, commitments: &[(String, Vec<u8>, [u8; 32])]) -> Vec<bool> {
        commitments
            .iter()
            .map(|(id, message, randomness)| self.verify_commitment(id, message, randomness))
            .collect()
    }
    
    /// 清理过期的承诺
    pub fn cleanup_expired_commitments(&mut self, max_age: u64) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.commitments.retain(|_, _| true); // 暂时保留所有承诺
        self.proofs.retain(|_, proof| {
            current_time - proof.timestamp < max_age
        });
    }
}

/// 承诺批次处理
pub struct BatchCommitmentProcessor;

impl BatchCommitmentProcessor {
    /// 批量创建承诺
    pub fn batch_create_commitments(messages: &[Vec<u8>]) -> Result<Vec<(BitCommitment, [u8; 32])>, VotingError> {
        let mut results = Vec::new();
        
        for message in messages {
            let result = CommitmentProtocol::create_commitment(message)?;
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// 批量验证承诺
    pub fn batch_verify_commitments(
        commitments: &[BitCommitment],
        messages: &[Vec<u8>],
        randomnesses: &[[u8; 32]]
    ) -> Result<Vec<bool>, VotingError> {
        if commitments.len() != messages.len() || commitments.len() != randomnesses.len() {
            return Err(VotingError::InvalidState);
        }
        
        let mut results = Vec::new();
        
        for i in 0..commitments.len() {
            let is_valid = CommitmentProtocol::verify_commitment(
                &commitments[i],
                &messages[i],
                &randomnesses[i]
            );
            results.push(is_valid);
        }
        
        Ok(results)
    }
}

/// 承诺统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentStats {
    pub total_commitments: u64,
    pub valid_commitments: u64,
    pub invalid_commitments: u64,
    pub average_creation_time_ms: u64,
    pub average_verification_time_ms: u64,
}

impl CommitmentStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self {
            total_commitments: 0,
            valid_commitments: 0,
            invalid_commitments: 0,
            average_creation_time_ms: 0,
            average_verification_time_ms: 0,
        }
    }
    
    /// 更新统计信息
    pub fn update(&mut self, is_valid: bool, creation_time_ms: u64, verification_time_ms: u64) {
        self.total_commitments += 1;
        
        if is_valid {
            self.valid_commitments += 1;
        } else {
            self.invalid_commitments += 1;
        }
        
        // 更新平均时间
        let total_creation_time = self.average_creation_time_ms * (self.total_commitments - 1) + creation_time_ms;
        self.average_creation_time_ms = total_creation_time / self.total_commitments;
        
        let total_verification_time = self.average_verification_time_ms * (self.total_commitments - 1) + verification_time_ms;
        self.average_verification_time_ms = total_verification_time / self.total_commitments;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_protocol() {
        let message = b"test message";
        
        // 创建承诺
        let (commitment, randomness) = CommitmentProtocol::create_commitment(message).unwrap();
        
        // 验证承诺
        assert!(CommitmentProtocol::verify_commitment(&commitment, message, &randomness));
        
        // 验证错误消息
        let wrong_message = b"wrong message";
        assert!(!CommitmentProtocol::verify_commitment(&commitment, wrong_message, &randomness));
        
        // 验证错误随机数
        let wrong_randomness = RandomUtils::random_32_bytes();
        assert!(!CommitmentProtocol::verify_commitment(&commitment, message, &wrong_randomness));
    }

    #[test]
    fn test_commitment_proof() {
        let message = b"test message";
        let (commitment, randomness) = CommitmentProtocol::create_commitment(message).unwrap();
        
        // 创建证明
        let proof = CommitmentProtocol::create_proof(&commitment, message, &randomness).unwrap();
        
        // 验证证明
        assert!(CommitmentProtocol::verify_proof(&proof));
        
        // 验证错误证明
        let mut wrong_proof = proof.clone();
        wrong_proof.message = b"wrong message".to_vec();
        assert!(!CommitmentProtocol::verify_proof(&wrong_proof));
    }

    #[test]
    fn test_commitment_manager() {
        let mut manager = CommitmentManager::new();
        let message = b"test message";
        let (commitment, randomness) = CommitmentProtocol::create_commitment(message).unwrap();
        
        // 存储承诺
        manager.store_commitment("test_id", commitment.clone());
        
        // 获取承诺
        let retrieved_commitment = manager.get_commitment("test_id").unwrap();
        assert_eq!(*retrieved_commitment, commitment);
        
        // 验证承诺
        assert!(manager.verify_commitment("test_id", message, &randomness));
        
        // 验证不存在的承诺
        assert!(!manager.verify_commitment("nonexistent", message, &randomness));
    }

    #[test]
    fn test_batch_processing() {
        let messages = vec![
            b"message1".to_vec(),
            b"message2".to_vec(),
            b"message3".to_vec(),
        ];
        
        // 批量创建承诺
        let results = BatchCommitmentProcessor::batch_create_commitments(&messages).unwrap();
        assert_eq!(results.len(), 3);
        
        // 提取数据
        let commitments: Vec<BitCommitment> = results.iter().map(|(c, _)| c.clone()).collect();
        let randomnesses: Vec<[u8; 32]> = results.iter().map(|(_, r)| *r).collect();
        
        // 批量验证
        let verification_results = BatchCommitmentProcessor::batch_verify_commitments(
            &commitments,
            &messages,
            &randomnesses
        ).unwrap();
        
        assert_eq!(verification_results.len(), 3);
        assert!(verification_results.iter().all(|&valid| valid));
    }

    #[test]
    fn test_commitment_stats() {
        let mut stats = CommitmentStats::new();
        
        // 更新统计信息
        stats.update(true, 10, 5);
        stats.update(false, 15, 8);
        stats.update(true, 12, 6);
        
        assert_eq!(stats.total_commitments, 3);
        assert_eq!(stats.valid_commitments, 2);
        assert_eq!(stats.invalid_commitments, 1);
        assert!(stats.average_creation_time_ms > 0);
        assert!(stats.average_verification_time_ms > 0);
    }
}
