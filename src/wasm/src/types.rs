//! 核心数据类型定义

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 比特承诺结构
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BitCommitment {
    pub commitment: [u8; 32],
    pub opening: [u8; 32],
    pub message_hash: [u8; 32],
}

/// 承诺证明结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentProof {
    pub commitment: [u8; 32],
    pub opening: [u8; 32],
    pub message: Vec<u8>,
    pub timestamp: u64,
}

/// iAgent配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAgentConfig {
    pub agent_id: String,
    pub automation_enabled: bool,
    pub auto_commit_interval: Option<u64>, // 自动承诺间隔（秒）
    pub auto_reveal_delay: Option<u64>,   // 自动揭示延迟（秒）
    pub commitment_strategy: CommitmentStrategy,
    pub reveal_conditions: Vec<RevealCondition>,
}

/// 承诺策略枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitmentStrategy {
    Immediate,      // 立即承诺
    Scheduled,      // 定时承诺
    Conditional,    // 条件触发承诺
    Batch,          // 批量承诺
}

/// 揭示条件结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealCondition {
    pub condition_type: RevealConditionType,
    pub threshold: Option<u64>,
    pub time_trigger: Option<u64>,
    pub participant_count: Option<u32>,
}

/// 揭示条件类型枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevealConditionType {
    TimeBased,          // 基于时间
    ParticipantCount,   // 基于参与者数量
    Manual,             // 手动触发
    Automatic,          // 自动触发
}

/// 投票会话状态枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VotingSessionState {
    Created,        // 已创建
    CommitPhase,    // 承诺阶段
    RevealPhase,    // 揭示阶段
    Counting,       // 计票阶段
    Completed,      // 已完成
    Cancelled,      // 已取消
}

/// 投票会话结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingSession {
    pub session_id: String,
    pub state: VotingSessionState,
    pub created_at: u64,
    pub commit_deadline: u64,
    pub reveal_deadline: u64,
    pub participants: Vec<String>,
    pub commitments: HashMap<String, BitCommitment>,
    pub reveals: HashMap<String, CommitmentProof>,
    pub results: Option<VotingResults>,
}

/// 投票结果结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingResults {
    pub total_votes: u32,
    pub valid_votes: u32,
    pub invalid_votes: u32,
    pub winner_indices: Vec<u32>,
    pub proof: String,
}

/// NFT类型枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NftType {
    Lottery,        // 抽奖
    LotteryTicket,  // 彩票
    Distribution,   // 分配
    Governance,     // 治理
}

/// 权限等级枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PermissionLevel {
    Basic,          // 基础权限
    Creator,        // 创建者权限
    Admin,          // 管理员权限
}

/// 用户权限结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPermissions {
    pub user_id: String,
    pub token_balance: u64,
    pub nft_ownership: Vec<String>,
    pub permission_level: PermissionLevel,
    pub permissions: HashMap<String, bool>,
}

/// 错误类型枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VotingError {
    InvalidCommitment,
    InvalidReveal,
    SessionNotFound,
    SessionExpired,
    InsufficientPermissions,
    InvalidState,
    NetworkError,
    StorageError,
}

impl std::fmt::Display for VotingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VotingError::InvalidCommitment => write!(f, "无效的承诺"),
            VotingError::InvalidReveal => write!(f, "无效的揭示"),
            VotingError::SessionNotFound => write!(f, "会话未找到"),
            VotingError::SessionExpired => write!(f, "会话已过期"),
            VotingError::InsufficientPermissions => write!(f, "权限不足"),
            VotingError::InvalidState => write!(f, "无效状态"),
            VotingError::NetworkError => write!(f, "网络错误"),
            VotingError::StorageError => write!(f, "存储错误"),
        }
    }
}

impl std::error::Error for VotingError {}
