//! 偏好投票客户端SDK模块
//!
//! 实现第五阶段的客户端SDK核心功能

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rand::RngCore;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tracing::{info, warn, error};
use chrono;

use crate::core::voting_lifecycle::{VotingSession, VotingStatus, VotingResults, VotingFlowEngine};
use crate::core::participants::ParticipantService;
use crate::core::audit::AuditLogger;


/// 投票结果报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingResultsReport {
    pub session_id: String,
    pub is_valid: bool,
    pub issues: Vec<String>,
    pub total_votes: usize,
    pub valid_votes: usize,
    pub invalid_votes: usize,
    pub winner_count: usize,
    pub timestamp: u64,
}

/// SDK配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingSdkConfig {
    pub api_endpoint: String,
    pub timeout_seconds: u64,
    pub retry_count: u32,
    pub retry_delay_ms: u64,
    pub enable_cache: bool,
    pub cache_ttl_seconds: u64,
}

/// 比特承诺生成器
#[allow(dead_code)]
pub struct CommitmentGenerator {
    rng: Mutex<Box<dyn RngCore + Send + Sync>>,
}

impl CommitmentGenerator {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            rng: Mutex::new(Box::new(StdRng::from_entropy())),
        }
    }

    /// 生成比特承诺
    #[allow(dead_code)]
    pub fn generate_commitment(&self, message: &[u8]) -> (String, Vec<u8>) {
        // 生成32字节随机数
        let mut randomness = [0u8; 32];
        let mut rng = self.rng.lock().unwrap();
        rng.fill_bytes(&mut randomness);
        
        // 计算承诺哈希: H(message || randomness)
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(&randomness);
        let commitment_hash = hasher.finalize();
        
        // 返回十六进制格式的承诺哈希和随机数
        (hex::encode(commitment_hash), randomness.to_vec())
    }

    /// 验证比特承诺
    #[allow(dead_code)]
    pub fn verify_commitment(&self, message: &[u8], randomness: &[u8], commitment_hash: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(randomness);
        let calculated_hash = hasher.finalize();
        
        hex::encode(calculated_hash) == commitment_hash
    }
}

/// 投票提交接口
#[allow(dead_code)]
pub struct VotingSubmitter {
    flow_engine: Arc<VotingFlowEngine>,
    participant_service: Arc<ParticipantService>,
    audit_logger: Arc<AuditLogger>,
    config: VotingSdkConfig,
}

impl VotingSubmitter {
    #[allow(dead_code)]
    pub fn new(
        flow_engine: Arc<VotingFlowEngine>,
        participant_service: Arc<ParticipantService>,
        audit_logger: Arc<AuditLogger>,
        config: VotingSdkConfig,
    ) -> Self {
        Self {
            flow_engine,
            participant_service,
            audit_logger,
            config,
        }
    }

    /// 提交投票承诺
    #[allow(dead_code)]
    pub async fn submit_commitment(
        &self,
        session_id: &str,
        user_id: &str,
        preference_value: i32,
        nft_proof: NFTProof,
    ) -> Result<String, String> {
        // 验证NFT证明
        if !self.verify_nft_proof(&nft_proof).await {
            return Err("NFT证明验证失败".to_string());
        }
        
        // 生成承诺
        let commitment_data = format!("{}:{}:{}", session_id, user_id, preference_value);
        let (commitment_hash, _randomness) = self.generate_commitment(&commitment_data.as_bytes());
        
        // 提交到投票流程引擎
        self.flow_engine.submit_commitment(session_id, user_id, &commitment_hash).await?;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "commitment_submitted_via_sdk",
            &serde_json::json!({
                "session_id": session_id,
                "user_id": user_id,
                "preference_value": preference_value,
                "commitment_hash": commitment_hash
            })
        ).await;
        
        info!("SDK提交投票承诺成功: session_id={}, user_id={}", session_id, user_id);
        Ok(commitment_hash)
    }

    /// 提交投票揭示
    #[allow(dead_code)]
    pub async fn submit_reveal(
        &self,
        session_id: &str,
        user_id: &str,
        preference_value: i32,
        randomness: &str,
        nft_proof: NFTProof,
    ) -> Result<String, String> {
        // 验证NFT证明
        if !self.verify_nft_proof(&nft_proof).await {
            return Err("NFT证明验证失败".to_string());
        }
        
        // 验证随机数格式
        let _randomness_bytes = hex::decode(randomness)
            .map_err(|_| "随机数格式错误".to_string())?;
        
        // 生成揭示数据
        let reveal_data = format!("{}:{}:{}:{}", session_id, user_id, preference_value, randomness);
        
        // 提交到投票流程引擎
        self.flow_engine.submit_reveal(session_id, user_id, &reveal_data).await?;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "reveal_submitted_via_sdk",
            &serde_json::json!({
                "session_id": session_id,
                "user_id": user_id,
                "preference_value": preference_value,
                "reveal_data": reveal_data
            })
        ).await;
        
        info!("SDK提交投票揭示成功: session_id={}, user_id={}", session_id, user_id);
        Ok(reveal_data)
    }

    /// 生成承诺
    #[allow(dead_code)]
    fn generate_commitment(&self, data: &[u8]) -> (String, Vec<u8>) {
        let mut rng = StdRng::from_entropy();
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&randomness);
        let commitment_hash = hasher.finalize();
        
        (hex::encode(commitment_hash), randomness.to_vec())
    }

    /// 验证NFT证明
    #[allow(dead_code)]
    async fn verify_nft_proof(&self, nft_proof: &NFTProof) -> bool {
        // 验证NFT所有权
        if !self.participant_service.verify_nft_ownership(&nft_proof.user_id, &nft_proof.nft_id).await {
            return false;
        }
        
        // 验证NFT类型
        if !self.participant_service.verify_nft_type(&nft_proof.nft_id, &nft_proof.nft_type).await {
            return false;
        }
        
        // 验证签名
        // 这里应该实现实际的签名验证逻辑
        true
    }

    /// 验证NFT所有权
    #[allow(dead_code)]
    async fn verify_nft_ownership(&self, nft_proof: &NFTProof) -> Result<(), String> {
        // 这里应该实现具体的NFT所有权验证逻辑
        // 包括调用智能合约验证NFT所有权
        info!("验证NFT所有权: token_id={}, owner={}", nft_proof.user_id, nft_proof.user_id);
        Ok(())
    }

    /// 存储承诺信息
    #[allow(dead_code)]
    async fn store_commitment(
        &self,
        session_id: &str,
        user_id: &str,
        commitment_hash: &str,
        _randomness: &[u8],
    ) -> Result<(), String> {
        // 实际实现中应该存储到IPFS和区块链
        // 这里使用内存存储作为示例
        info!("存储承诺信息: session={}, user={}, hash={}", session_id, user_id, commitment_hash);
        Ok(())
    }

    /// 获取存储的承诺
    #[allow(dead_code)]
    async fn get_stored_commitment(&self, _session_id: &str, _user_id: &str) -> Option<String> {
        // 实际实现中应该从IPFS或区块链获取
        // 这里返回示例数据
        Some("example_commitment_hash".to_string())
    }

    /// 存储揭示信息
    #[allow(dead_code)]
    async fn store_reveal(
        &self,
        session_id: &str,
        user_id: &str,
        _reveal_data: &serde_json::Value,
    ) -> Result<String, String> {
        // 实际实现中应该存储到IPFS和区块链
        // 这里生成示例哈希
        let reveal_hash = format!("reveal_{}_{}_{}", session_id, user_id, chrono::Utc::now().timestamp());
        info!("存储揭示信息: session={}, user={}, hash={}", session_id, user_id, reveal_hash);
        Ok(reveal_hash)
    }

    /// 使用参与者服务验证用户资格
    #[allow(dead_code)]
    pub async fn validate_user_eligibility(&self, user_id: &str, nft_type: &str) -> Result<bool, String> {
        // 使用参与者服务进行验证
        info!("验证用户资格: user_id={}, user_id={}, nft_type={}", user_id, user_id, nft_type);
        
        // 这里应该调用参与者服务的实际验证方法
        // 暂时返回成功
        Ok(true)
    }

    /// 获取SDK配置信息
    #[allow(dead_code)]
    pub fn get_sdk_config(&self) -> &VotingSdkConfig {
        &self.config
    }

    /// 检查SDK配置
    #[allow(dead_code)]
    pub fn check_sdk_config(&self) -> Result<(), String> {
        // 检查配置的有效性
        if self.config.timeout_seconds == 0 {
            return Err("超时时间不能为0".to_string());
        }
        
        if self.config.retry_count == 0 {
            return Err("重试次数不能为0".to_string());
        }
        
        if self.config.cache_ttl_seconds == 0 {
            return Err("缓存TTL不能为0".to_string());
        }
        
        Ok(())
    }
}

/// 投票验证器
#[allow(dead_code)]
pub struct VotingVerifier {
    flow_engine: Arc<VotingFlowEngine>,
    audit_logger: Arc<AuditLogger>,
}

impl VotingVerifier {
    #[allow(dead_code)]
    pub fn new(
        flow_engine: Arc<VotingFlowEngine>,
        audit_logger: Arc<AuditLogger>,
    ) -> Self {
        Self {
            flow_engine,
            audit_logger,
        }
    }

    /// 验证会话完整性
    #[allow(dead_code)]
    pub async fn verify_session_integrity(&self, session_id: &str) -> Result<SessionIntegrityReport, String> {
        let session = self.flow_engine.get_session(session_id).await
            .ok_or_else(|| format!("会话不存在: {}", session_id))?;
        
        let mut issues = Vec::new();
        
        // 检查参与者数量
        if session.participants.len() < session.phase_config.min_participants {
            issues.push("参与者数量不足".to_string());
        }
        
        // 检查承诺数量
        if session.commitments.len() > session.participants.len() {
            issues.push("承诺数量超过参与者数量".to_string());
        }
        
        // 检查揭示数量
        if session.reveals.len() > session.commitments.len() {
            issues.push("揭示数量超过承诺数量".to_string());
        }
        
        // 检查时间配置
        if session.phase_config.commit_start_time >= session.phase_config.commit_end_time {
            issues.push("承诺阶段时间配置错误".to_string());
        }
        
        if session.phase_config.reveal_start_time >= session.phase_config.reveal_end_time {
            issues.push("揭示阶段时间配置错误".to_string());
        }
        
        let is_valid = issues.is_empty();
        let issue_count = issues.len();
        
        let report = SessionIntegrityReport {
            session_id: session_id.to_string(),
            is_valid,
            issues,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "session_integrity_verified",
            &serde_json::json!({
                "session_id": session_id,
                "is_valid": is_valid,
                "issue_count": issue_count
            })
        ).await;
        
        Ok(report)
    }

    /// 验证投票结果
    #[allow(dead_code)]
    pub async fn verify_voting_results(&self, session_id: &str) -> Result<VotingResultsReport, String> {
        let session = self.flow_engine.get_session(session_id).await
            .ok_or_else(|| format!("会话不存在: {}", session_id))?;
        
        let results = session.results.as_ref()
            .ok_or_else(|| "投票结果不存在".to_string())?;
        
        let mut issues = Vec::new();
        
        // 验证总票数
        if results.total_votes != session.participants.len() {
            issues.push(format!("总票数不匹配: 期望{}, 实际{}", session.participants.len(), results.total_votes));
        }
        
        // 验证有效票数
        if results.valid_votes != session.reveals.len() {
            issues.push(format!("有效票数不匹配: 期望{}, 实际{}", session.reveals.len(), results.valid_votes));
        }
        
        // 验证无效票数
        let expected_invalid = results.total_votes - results.valid_votes;
        if results.invalid_votes != expected_invalid {
            issues.push(format!("无效票数不匹配: 期望{}, 实际{}", expected_invalid, results.invalid_votes));
        }
        
        // 验证中奖者数量
        if results.winner_count != results.winners.len() {
            issues.push("中奖者数量不匹配".to_string());
        }
        
        let is_valid = issues.is_empty();
        let issue_count = issues.len();
        
        let report = VotingResultsReport {
            session_id: session_id.to_string(),
            is_valid,
            issues: issues.clone(),
            total_votes: results.total_votes,
            valid_votes: results.valid_votes,
            invalid_votes: results.invalid_votes,
            winner_count: results.winner_count,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "voting_results_verified",
            &serde_json::json!({
                "session_id": session_id,
                "is_valid": is_valid,
                "issue_count": issue_count
            })
        ).await;
        
        Ok(report)
    }

    /// 记录验证事件
    #[allow(dead_code)]
    pub async fn log_verification_event(&self, event_type: &str, details: &serde_json::Value) -> Result<(), String> {
        let _ = self.audit_logger.log_event(event_type, details).await;
        Ok(())
    }
}

/// 结果查询接口
#[allow(dead_code)]
pub struct ResultQueryInterface {
    flow_engine: Arc<VotingFlowEngine>,
    audit_logger: Arc<AuditLogger>,
}

impl ResultQueryInterface {
    #[allow(dead_code)]
    pub fn new(
        flow_engine: Arc<VotingFlowEngine>,
        audit_logger: Arc<AuditLogger>,
    ) -> Self {
        Self {
            flow_engine,
            audit_logger,
        }
    }

    /// 查询会话信息
    #[allow(dead_code)]
    pub async fn get_session_info(&self, session_id: &str) -> Result<Option<VotingSession>, String> {
        let session = self.flow_engine.get_session(session_id).await;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "session_info_queried",
            &serde_json::json!({
                "session_id": session_id,
                "found": session.is_some()
            })
        ).await;
        
        Ok(session)
    }

    /// 查询会话状态
    #[allow(dead_code)]
    pub async fn get_session_status(&self, session_id: &str) -> Result<Option<VotingStatus>, String> {
        let session = self.flow_engine.get_session(session_id).await;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "session_status_queried",
            &serde_json::json!({
                "session_id": session_id,
                "found": session.is_some()
            })
        ).await;
        
        Ok(session.map(|s| s.status))
    }

    /// 查询投票结果
    #[allow(dead_code)]
    pub async fn get_voting_results(&self, session_id: &str) -> Result<Option<VotingResults>, String> {
        let session = self.flow_engine.get_session(session_id).await;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "voting_results_queried",
            &serde_json::json!({
                "session_id": session_id,
                "found": session.is_some()
            })
        ).await;
        
        Ok(session.and_then(|s| s.results))
    }

    /// 查询所有会话
    #[allow(dead_code)]
    pub async fn get_all_sessions(&self) -> Result<Vec<VotingSession>, String> {
        let sessions = self.flow_engine.get_all_sessions().await;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "all_sessions_queried",
            &serde_json::json!({
                "session_count": sessions.len()
            })
        ).await;
        
        Ok(sessions)
    }
}

/// 错误处理器
#[allow(dead_code)]
pub struct ErrorHandler {
    retry_count: u32,
    retry_delay_ms: u64,
}

impl ErrorHandler {
    #[allow(dead_code)]
    pub fn new(retry_count: u32, retry_delay_ms: u64) -> Self {
        Self {
            retry_count,
            retry_delay_ms,
        }
    }

    /// 处理错误并重试
    #[allow(dead_code)]
    pub async fn handle_with_retry<F, T, E>(
        &self,
        operation: F,
        _operation_name: &str,
    ) -> Result<T, E>
    where
        F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>> + Send + Sync,
        E: std::fmt::Display + Send + Sync + Clone,
    {
        let mut last_error = None;
        
        for attempt in 1..=self.retry_count {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e.clone());
                    if attempt < self.retry_count {
                        warn!("操作失败，准备重试: {} (尝试 {}/{})", e, attempt, self.retry_count);
                        tokio::time::sleep(tokio::time::Duration::from_millis(self.retry_delay_ms)).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap())
    }
}

/// 密钥管理器
#[allow(dead_code)]
pub struct KeyManager {
    keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl KeyManager {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 生成新密钥
    #[allow(dead_code)]
    pub async fn generate_key(&self, key_id: &str) -> Result<Vec<u8>, String> {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        
        {
            let mut keys = self.keys.write().await;
            keys.insert(key_id.to_string(), key.clone());
        }
        
        Ok(key)
    }

    /// 获取密钥
    #[allow(dead_code)]
    pub async fn get_key(&self, key_id: &str) -> Option<Vec<u8>> {
        let keys = self.keys.read().await;
        keys.get(key_id).cloned()
    }

    /// 删除密钥
    #[allow(dead_code)]
    pub async fn delete_key(&self, key_id: &str) -> bool {
        let mut keys = self.keys.write().await;
        keys.remove(key_id).is_some()
    }
}

/// 日志记录器
#[allow(dead_code)]
pub struct SdkLogger {
    audit_logger: Arc<AuditLogger>,
}

impl SdkLogger {
    #[allow(dead_code)]
    pub fn new(audit_logger: Arc<AuditLogger>) -> Self {
        Self { audit_logger }
    }

    /// 记录操作日志
    #[allow(dead_code)]
    pub async fn log_operation(&self, operation: &str, details: &serde_json::Value) {
        if let Err(e) = self.audit_logger.log_event(operation, details).await {
            error!("记录操作日志失败: {}", e);
        }
    }

    /// 记录错误日志
    #[allow(dead_code)]
    pub async fn log_error(&self, error: &str, context: &serde_json::Value) {
        let error_details = serde_json::json!({
            "error": error,
            "context": context,
            "timestamp": chrono::Utc::now().timestamp() as u64
        });
        
        if let Err(e) = self.audit_logger.log_event("sdk_error", &error_details).await {
            error!("记录错误日志失败: {}", e);
        }
    }
}

/// NFT证明
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct NFTProof {
    pub user_id: String,
    pub nft_id: String,
    pub nft_type: String,
    pub signature: String,
}

/// 会话完整性报告
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct SessionIntegrityReport {
    pub session_id: String,
    pub is_valid: bool,
    pub issues: Vec<String>,
    pub timestamp: u64,
}

impl SessionIntegrityReport {
    #[allow(dead_code)]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            is_valid: false,
            issues: Vec::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    #[allow(dead_code)]
    pub fn add_issue(&mut self, issue: String) {
        self.issues.push(issue);
    }
}

/// 结果验证报告
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ResultVerificationReport {
    pub session_id: String,
    pub is_valid: bool,
    pub issues: Vec<String>,
    pub timestamp: u64,
}

impl ResultVerificationReport {
    #[allow(dead_code)]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            is_valid: false,
            issues: Vec::new(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    #[allow(dead_code)]
    pub fn add_issue(&mut self, issue: String) {
        self.issues.push(issue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_generation() {
        let gen = CommitmentGenerator::new();
        let message = b"test_message";
        
        let (commitment_hash, randomness) = gen.generate_commitment(message);
        
        assert!(!commitment_hash.is_empty());
        assert_eq!(randomness.len(), 32);
        
        // 验证承诺
        assert!(gen.verify_commitment(message, &randomness, &commitment_hash));
    }

    #[test]
    fn test_commitment_verification_failure() {
        let gen = CommitmentGenerator::new();
        let wrong_message = b"wrong_message";
        let randomness = vec![1u8; 32];
        let commitment_hash = "wrong_hash";
        
        assert!(!gen.verify_commitment(wrong_message, &randomness, commitment_hash));
    }

    #[tokio::test]
    async fn test_session_integrity_report() {
        let mut report = SessionIntegrityReport::new("test_session");
        
        assert!(!report.is_valid);
        assert_eq!(report.issues.len(), 0);
        
        report.add_issue("测试问题1".to_string());
        report.add_issue("测试问题2".to_string());
        
        assert_eq!(report.issues.len(), 2);
        assert!(report.issues.contains(&"测试问题1".to_string()));
        assert!(report.issues.contains(&"测试问题2".to_string()));
    }
}
