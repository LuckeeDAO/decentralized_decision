use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use serde_json::Value;

/// 抽奖等级定义
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LotteryLevel {
    /// 等级ID，唯一标识符
    pub id: String,
    /// 等级名称
    pub name: String,
    /// 等级描述
    pub description: String,
    /// 等级优先级（数字越小优先级越高）
    pub priority: u32,
    /// 等级权重（用于选择算法）
    pub weight: f64,
    /// 等级参数配置
    pub parameters: LevelParameters,
    /// 等级权限要求
    pub permissions: LevelPermissions,
    /// 等级状态
    pub status: LevelStatus,
    /// 创建时间戳
    pub created_at: u64,
    /// 更新时间戳
    pub updated_at: u64,
}

/// 等级参数配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LevelParameters {
    /// 最小参与者数量
    pub min_participants: u32,
    /// 最大参与者数量
    pub max_participants: Option<u32>,
    /// 中奖者数量
    pub winner_count: u32,
    /// 选择算法类型
    pub selection_algorithm: SelectionAlgorithm,
    /// 算法特定参数
    pub algorithm_params: HashMap<String, Value>,
    /// 时间限制（秒）
    pub time_limit: Option<u64>,
    /// 成本限制
    pub cost_limit: Option<u128>,
}

/// 选择算法类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionAlgorithm {
    /// 随机选择
    Random,
    /// 加权随机选择
    WeightedRandom,
    /// 轮盘赌选择
    RouletteWheel,
    /// 锦标赛选择
    Tournament,
    /// 自定义算法
    Custom(String),
}

/// 等级权限要求
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LevelPermissions {
    /// 最小代币余额要求
    pub min_balance: u128,
    /// 最小质押要求
    pub min_stake: u128,
    /// 最小持有时间（秒）
    pub min_holding_time: u64,
    /// 需要的NFT类型列表
    pub required_nft_types: Vec<String>,
    /// 需要的权限等级
    pub required_permission_level: Option<String>,
    /// 黑名单地址
    pub blacklisted_addresses: Vec<String>,
    /// 白名单地址（如果非空，则只允许白名单中的地址）
    pub whitelisted_addresses: Vec<String>,
}

/// 等级状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LevelStatus {
    /// 草稿状态
    Draft,
    /// 激活状态
    Active,
    /// 暂停状态
    Paused,
    /// 已废弃
    Deprecated,
}

impl fmt::Display for LevelStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LevelStatus::Draft => write!(f, "draft"),
            LevelStatus::Active => write!(f, "active"),
            LevelStatus::Paused => write!(f, "paused"),
            LevelStatus::Deprecated => write!(f, "deprecated"),
        }
    }
}

impl Default for LotteryLevel {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            description: String::new(),
            priority: 0,
            weight: 1.0,
            parameters: LevelParameters {
                min_participants: 1,
                max_participants: None,
                winner_count: 1,
                selection_algorithm: SelectionAlgorithm::Random,
                algorithm_params: HashMap::new(),
                time_limit: None,
                cost_limit: None,
            },
            permissions: LevelPermissions {
                min_balance: 0,
                min_stake: 0,
                min_holding_time: 0,
                required_nft_types: Vec::new(),
                required_permission_level: None,
                blacklisted_addresses: Vec::new(),
                whitelisted_addresses: Vec::new(),
            },
            status: LevelStatus::Draft,
            created_at: 0,
            updated_at: 0,
        }
    }
}


