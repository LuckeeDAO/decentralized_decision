//! 投票生命周期管理模块
//!
//! 实现第五阶段的投票流程管理和生命周期状态机

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::core::session::SessionManager;
use crate::core::participants::ParticipantService;
use crate::core::audit::AuditLogger;
use crate::core::cache::CacheManager;

/// 投票状态枚举
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VotingStatus {
    /// 创建阶段
    Created,
    /// 承诺阶段
    CommitmentPhase,
    /// 揭示阶段
    RevealPhase,
    /// 计票阶段
    CountingPhase,
    /// 完成阶段
    Completed,
    /// 取消阶段
    Cancelled,
    /// 错误状态
    Error,
}

/// 投票阶段配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingPhaseConfig {
    pub commit_start_time: u64,
    pub commit_end_time: u64,
    pub reveal_start_time: u64,
    pub reveal_end_time: u64,
    pub buffer_time: u64, // 缓冲期
    pub min_participants: usize,
    pub max_participants: Option<usize>,
}

/// 投票会话信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingSession {
    pub session_id: String,
    pub title: String,
    pub description: String,
    pub status: VotingStatus,
    pub phase_config: VotingPhaseConfig,
    pub participants: Vec<String>,
    pub commitments: HashMap<String, String>, // user_id -> commitment_hash
    pub reveals: HashMap<String, String>, // user_id -> reveal_data
    pub results: Option<VotingResults>,
    pub created_at: u64,
    pub updated_at: u64,
    pub creator: String,
    pub nft_type: String,
    pub metadata: serde_json::Value,
}

/// 投票结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingResults {
    pub total_votes: usize,
    pub valid_votes: usize,
    pub invalid_votes: usize,
    pub winner_count: usize,
    pub winners: Vec<String>,
    pub calculation_proof: String,
    pub calculated_at: u64,
}

/// 投票流程引擎
#[allow(dead_code)]
pub struct VotingFlowEngine {
    session_manager: Arc<SessionManager>,
    participant_service: Arc<ParticipantService>,
    audit_logger: Arc<AuditLogger>,
    cache_manager: Arc<CacheManager>,
    sessions: Arc<RwLock<HashMap<String, VotingSession>>>,
}

impl VotingFlowEngine {
    #[allow(dead_code)]
    pub fn new(
        session_manager: Arc<SessionManager>,
        participant_service: Arc<ParticipantService>,
        audit_logger: Arc<AuditLogger>,
        cache_manager: Arc<CacheManager>,
    ) -> Self {
        Self {
            session_manager,
            participant_service,
            audit_logger,
            cache_manager,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 创建投票流程
    pub async fn create_voting_flow(
        &self,
        request: CreateVotingFlowRequest,
    ) -> Result<VotingSession, String> {
        let session_id = request.session_id.clone();
        
        // 验证会话ID唯一性
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(&session_id) {
                return Err(format!("会话ID已存在: {}", session_id));
            }
        }
        
        // 验证参与者权限
        for participant in &request.participants {
            if !self.participant_service.has_voting_permission(participant).await {
                return Err(format!("参与者无投票权限: {}", participant));
            }
        }
        
        // 创建投票会话
        let session = VotingSession {
            session_id: session_id.clone(),
            title: request.title,
            description: request.description,
            status: VotingStatus::Created,
            phase_config: request.phase_config,
            participants: request.participants,
            commitments: HashMap::new(),
            reveals: HashMap::new(),
            results: None,
            created_at: chrono::Utc::now().timestamp() as u64,
            updated_at: chrono::Utc::now().timestamp() as u64,
            creator: request.creator,
            nft_type: request.nft_type,
            metadata: request.metadata,
        };
        
        // 存储会话
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session.clone());
        }
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "voting_flow_created",
            &serde_json::json!({
                "session_id": session_id,
                "creator": session.creator,
                "participant_count": session.participants.len()
            })
        ).await;
        
        info!("创建投票流程成功: session_id={}", session_id);
        Ok(session)
    }

    /// 启动投票阶段
    pub async fn start_voting_phase(
        &self,
        session_id: &str,
        phase: VotingStatus,
    ) -> Result<VotingSession, String> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| format!("会话不存在: {}", session_id))?;
        
        // 验证状态转换的合法性
        if !self.is_valid_state_transition(&session.status, &phase) {
            return Err(format!("无效的状态转换: {:?} -> {:?}", session.status, phase));
        }
        
        // 更新状态
        session.status = phase.clone();
        session.updated_at = chrono::Utc::now().timestamp() as u64;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "voting_phase_started",
            &serde_json::json!({
                "session_id": session_id,
                "new_phase": format!("{:?}", phase)
            })
        ).await;
        
        info!("启动投票阶段成功: session_id={}, phase={:?}", session_id, phase);
        Ok(session.clone())
    }

    /// 提交投票承诺
    pub async fn submit_commitment(
        &self,
        session_id: &str,
        user_id: &str,
        commitment_hash: &str,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| format!("会话不存在: {}", session_id))?;
        
        // 验证会话状态
        if session.status != VotingStatus::CommitmentPhase {
            return Err("当前不是承诺阶段".to_string());
        }
        
        // 验证参与者资格
        if !session.participants.contains(&user_id.to_string()) {
            return Err(format!("用户不是参与者: {}", user_id));
        }
        
        // 检查是否已经提交过承诺
        if session.commitments.contains_key(user_id) {
            return Err("已经提交过承诺".to_string());
        }
        
        // 存储承诺
        session.commitments.insert(user_id.to_string(), commitment_hash.to_string());
        session.updated_at = chrono::Utc::now().timestamp() as u64;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "commitment_submitted",
            &serde_json::json!({
                "session_id": session_id,
                "user_id": user_id,
                "commitment_hash": commitment_hash
            })
        ).await;
        
        info!("提交投票承诺成功: session_id={}, user_id={}", session_id, user_id);
        Ok(())
    }

    /// 提交投票揭示
    pub async fn submit_reveal(
        &self,
        session_id: &str,
        user_id: &str,
        reveal_data: &str,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| format!("会话不存在: {}", session_id))?;
        
        // 验证会话状态
        if session.status != VotingStatus::RevealPhase {
            return Err("当前不是揭示阶段".to_string());
        }
        
        // 验证参与者资格
        if !session.participants.contains(&user_id.to_string()) {
            return Err(format!("用户不是参与者: {}", user_id));
        }
        
        // 检查是否已经提交过承诺
        if !session.commitments.contains_key(user_id) {
            return Err("必须先提交承诺".to_string());
        }
        
        // 检查是否已经提交过揭示
        if session.reveals.contains_key(user_id) {
            return Err("已经提交过揭示".to_string());
        }
        
        // 存储揭示
        session.reveals.insert(user_id.to_string(), reveal_data.to_string());
        session.updated_at = chrono::Utc::now().timestamp() as u64;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "reveal_submitted",
            &serde_json::json!({
                "session_id": session_id,
                "user_id": user_id,
                "reveal_data": reveal_data
            })
        ).await;
        
        info!("提交投票揭示成功: session_id={}, user_id={}", session_id, user_id);
        Ok(())
    }

    /// 计算投票结果
    pub async fn calculate_results(
        &self,
        session_id: &str,
    ) -> Result<VotingResults, String> {
        let mut sessions = self.sessions.write().await;
        
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| format!("会话不存在: {}", session_id))?;
        
        // 验证会话状态
        if session.status != VotingStatus::RevealPhase {
            return Err("当前不是揭示阶段".to_string());
        }
        
        // 检查是否有足够的揭示
        if session.reveals.len() < session.phase_config.min_participants {
            return Err(format!("揭示数量不足: {} < {}", session.reveals.len(), session.phase_config.min_participants));
        }
        
        // 计算结果
        let total_votes = session.participants.len();
        let valid_votes = session.reveals.len();
        let invalid_votes = total_votes - valid_votes;
        
        // 这里应该实现实际的结果计算逻辑
        // 暂时使用简单的示例逻辑
        let winners: Vec<String> = session.reveals.keys().take(3).cloned().collect();
        let winner_count = winners.len();
        
        let results = VotingResults {
            total_votes,
            valid_votes,
            invalid_votes,
            winner_count,
            winners,
            calculation_proof: "example_proof".to_string(),
            calculated_at: chrono::Utc::now().timestamp() as u64,
        };
        
        // 更新会话状态和结果
        session.status = VotingStatus::Completed;
        session.results = Some(results.clone());
        session.updated_at = chrono::Utc::now().timestamp() as u64;
        
        // 记录审计日志
        let _ = self.audit_logger.log_event(
            "results_calculated",
            &serde_json::json!({
                "session_id": session_id,
                "total_votes": total_votes,
                "valid_votes": valid_votes,
                "winner_count": winner_count
            })
        ).await;
        
        info!("计算投票结果成功: session_id={}", session_id);
        Ok(results)
    }

    /// 获取投票会话
    pub async fn get_session(&self, session_id: &str) -> Option<VotingSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// 获取所有投票会话
    pub async fn get_all_sessions(&self) -> Vec<VotingSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// 删除投票会话
    pub async fn delete_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().await;
        
        if sessions.remove(session_id).is_some() {
            // 记录审计日志
            let _ = self.audit_logger.log_event(
                "session_deleted",
                &serde_json::json!({
                    "session_id": session_id
                })
            ).await;
            
            info!("删除投票会话成功: session_id={}", session_id);
            Ok(())
        } else {
            Err(format!("会话不存在: {}", session_id))
        }
    }

    /// 验证状态转换的合法性
    fn is_valid_state_transition(&self, current: &VotingStatus, next: &VotingStatus) -> bool {
        match (current, next) {
            (VotingStatus::Created, VotingStatus::CommitmentPhase) => true,
            (VotingStatus::CommitmentPhase, VotingStatus::RevealPhase) => true,
            (VotingStatus::RevealPhase, VotingStatus::CountingPhase) => true,
            (VotingStatus::CountingPhase, VotingStatus::Completed) => true,
            (_, VotingStatus::Cancelled) => true,
            (_, VotingStatus::Error) => true,
            _ => false,
        }
    }
}

/// 创建投票流程请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVotingFlowRequest {
    pub session_id: String,
    pub title: String,
    pub description: String,
    pub phase_config: VotingPhaseConfig,
    pub participants: Vec<String>,
    pub creator: String,
    pub nft_type: String,
    pub metadata: serde_json::Value,
}

/// 投票流程监控器
#[allow(dead_code)]
pub struct VotingFlowMonitor {
    flow_engine: Arc<VotingFlowEngine>,
    check_interval: std::time::Duration,
}

#[allow(dead_code)]
impl VotingFlowMonitor {
    pub fn new(flow_engine: Arc<VotingFlowEngine>) -> Self {
        Self {
            flow_engine,
            check_interval: std::time::Duration::from_secs(60), // 每分钟检查一次
        }
    }

    /// 启动监控
    pub async fn start_monitoring(&self) {
        let flow_engine = Arc::clone(&self.flow_engine);
        let check_interval = self.check_interval;
        
        tokio::spawn(async move {
            loop {
                if let Err(e) = Self::check_voting_phases(&flow_engine).await {
                    error!("检查投票阶段失败: {}", e);
                }
                
                tokio::time::sleep(check_interval).await;
            }
        });
    }

    /// 检查投票阶段
    async fn check_voting_phases(flow_engine: &VotingFlowEngine) -> Result<(), String> {
        // 获取所有活跃的投票会话
        let sessions = {
            let sessions = flow_engine.sessions.read().await;
            sessions.values().filter(|s| {
                matches!(s.status, VotingStatus::Created | VotingStatus::CommitmentPhase | VotingStatus::RevealPhase)
            }).cloned().collect::<Vec<_>>()
        };
        
        let current_time = chrono::Utc::now().timestamp() as u64;
        
        for session in sessions {
            match session.status {
                VotingStatus::Created => {
                    if current_time >= session.phase_config.commit_start_time {
                        if let Err(e) = flow_engine.start_voting_phase(&session.session_id, VotingStatus::CommitmentPhase).await {
                            warn!("启动承诺阶段失败: session={}, error={}", session.session_id, e);
                        }
                    }
                }
                VotingStatus::CommitmentPhase => {
                    if current_time >= session.phase_config.reveal_start_time {
                        if let Err(e) = flow_engine.start_voting_phase(&session.session_id, VotingStatus::RevealPhase).await {
                            warn!("启动揭示阶段失败: session={}, error={}", session.session_id, e);
                        }
                    }
                }
                VotingStatus::RevealPhase => {
                    if current_time >= session.phase_config.reveal_end_time + session.phase_config.buffer_time {
                        if let Err(e) = flow_engine.start_voting_phase(&session.session_id, VotingStatus::CountingPhase).await {
                            warn!("启动计票阶段失败: session={}, error={}", session.session_id, e);
                        }
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::session::SessionManager;
    use crate::core::participants::ParticipantService;
    use crate::core::audit::AuditLogger;
    use crate::core::cache::CacheManager;

    #[tokio::test]
    async fn test_voting_flow_creation() {
        let session_manager = Arc::new(SessionManager::new());
        let participant_service = Arc::new(ParticipantService::new());
        let audit_logger = Arc::new(AuditLogger::new());
        let cache_manager = Arc::new(CacheManager::new());
        
        let flow_engine = VotingFlowEngine::new(
            session_manager,
            participant_service,
            audit_logger,
            cache_manager,
        );
        
        let current_time = chrono::Utc::now().timestamp() as u64;
        let request = CreateVotingFlowRequest {
            session_id: "test_session".to_string(),
            title: "测试投票".to_string(),
            description: "测试投票描述".to_string(),
            phase_config: VotingPhaseConfig {
                commit_start_time: current_time + 60,
                commit_end_time: current_time + 120,
                reveal_start_time: current_time + 180,
                reveal_end_time: current_time + 240,
                buffer_time: 30,
                min_participants: 1,
                max_participants: Some(100),
            },
            participants: vec!["participant1".to_string()],
            creator: "creator1".to_string(),
            nft_type: "lottery".to_string(),
            metadata: serde_json::json!({}),
        };
        
        let result = flow_engine.create_voting_flow(request).await;
        assert!(result.is_ok());
        
        let session = result.unwrap();
        assert_eq!(session.status, VotingStatus::Created);
        assert_eq!(session.session_id, "test_session");
    }
}
