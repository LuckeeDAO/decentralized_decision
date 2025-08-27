//! 抽奖等级系统模块
//! 
//! 实现抽奖等级的定义、配置、验证和管理功能

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use jsonschema::{Draft, JSONSchema};
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
#[serde(rename_all = "lowercase")]
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

/// 等级验证器
pub struct LevelValidator {
    schema: JSONSchema,
}

impl LevelValidator {
    /// 创建新的等级验证器
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        static SCHEMA_JSON: once_cell::sync::Lazy<serde_json::Value> = once_cell::sync::Lazy::new(|| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 50,
                        "pattern": "^[a-zA-Z0-9_-]+$"
                    },
                    "name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 100
                    },
                    "description": {
                        "type": "string",
                        "maxLength": 500
                    },
                    "priority": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 1000
                    },
                    "weight": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 100.0
                    },
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "min_participants": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "max_participants": {
                                "type": ["integer", "null"],
                                "minimum": 1
                            },
                            "winner_count": {
                                "type": "integer",
                                "minimum": 1
                            },
                            "selection_algorithm": {
                                "type": "string",
                                "enum": ["random", "weighted_random", "roulette_wheel", "tournament"]
                            },
                            "time_limit": {
                                "type": ["integer", "null"],
                                "minimum": 0
                            },
                            "cost_limit": {
                                "type": ["integer", "null"],
                                "minimum": 0
                            }
                        },
                        "required": ["min_participants", "winner_count", "selection_algorithm"]
                    },
                    "permissions": {
                        "type": "object",
                        "properties": {
                            "min_balance": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "min_stake": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "min_holding_time": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "required_nft_types": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                }
                            },
                            "blacklisted_addresses": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                }
                            },
                            "whitelisted_addresses": {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                }
                            }
                        },
                        "required": ["min_balance", "min_stake", "min_holding_time"]
                    }
                },
                "required": ["id", "name", "priority", "weight", "parameters", "permissions"]
            })
        });

        let schema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&*SCHEMA_JSON)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(Self { schema })
    }

    /// 验证等级定义
    pub fn validate(&self, level: &LotteryLevel) -> Result<(), Vec<String>> {
        let level_json = serde_json::to_value(level)
            .map_err(|e| vec![format!("序列化失败: {}", e)])?;

        let validation_result = self.schema.validate(&level_json);
        match validation_result {
            Ok(_) => {
                // 额外业务逻辑验证
                self.validate_business_rules(level)
            }
            Err(errors) => {
                let error_messages: Vec<String> = errors
                    .map(|e| format!("{}", e))
                    .collect();
                Err(error_messages)
            }
        }
    }

    /// 验证业务规则
    fn validate_business_rules(&self, level: &LotteryLevel) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // 验证参与者数量逻辑
        if let Some(max_participants) = level.parameters.max_participants {
            if level.parameters.min_participants > max_participants {
                errors.push("最小参与者数量不能大于最大参与者数量".to_string());
            }
        }

        // 验证中奖者数量逻辑
        if level.parameters.winner_count > level.parameters.min_participants {
            errors.push("中奖者数量不能大于最小参与者数量".to_string());
        }

        // 验证权重范围
        if level.weight < 0.0 || level.weight > 100.0 {
            errors.push("权重必须在0.0到100.0之间".to_string());
        }

        // 验证算法参数
        if let Err(e) = self.validate_algorithm_params(&level.parameters) {
            errors.extend(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// 验证算法特定参数
    fn validate_algorithm_params(&self, params: &LevelParameters) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        match &params.selection_algorithm {
            SelectionAlgorithm::Tournament => {
                if let Some(tournament_size) = params.algorithm_params.get("tournament_size") {
                    if let Some(size) = tournament_size.as_u64() {
                        if size < 2 {
                            errors.push("锦标赛大小必须至少为2".to_string());
                        }
                    } else {
                        errors.push("锦标赛大小必须是正整数".to_string());
                    }
                } else {
                    errors.push("锦标赛算法需要指定tournament_size参数".to_string());
                }
            }
            SelectionAlgorithm::WeightedRandom => {
                if let Some(weight_field) = params.algorithm_params.get("weight_field") {
                    if !weight_field.is_string() {
                        errors.push("权重字段必须是字符串".to_string());
                    }
                } else {
                    errors.push("加权随机算法需要指定weight_field参数".to_string());
                }
            }
            SelectionAlgorithm::Custom(algorithm_name) => {
                if algorithm_name.is_empty() {
                    errors.push("自定义算法名称不能为空".to_string());
                }
            }
            _ => {} // 其他算法不需要特殊验证
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// 等级管理器
pub struct LevelManager {
    levels: HashMap<String, LotteryLevel>,
    validator: LevelValidator,
}

impl LevelManager {
    /// 创建新的等级管理器
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(Self {
            levels: HashMap::new(),
            validator: LevelValidator::new()?,
        })
    }

    /// 添加或更新等级
    pub fn upsert_level(&mut self, level: LotteryLevel) -> Result<(), Vec<String>> {
        // 验证等级定义
        self.validator.validate(&level)?;

        // 检查ID冲突（除了更新自己的情况）
        if let Some(existing) = self.levels.get(&level.id) {
            if existing.updated_at != level.updated_at {
                return Err(vec!["等级ID已存在，请使用不同的ID".to_string()]);
            }
        }

        // 检查优先级冲突
        for (existing_id, existing_level) in &self.levels {
            if existing_id != &level.id && existing_level.priority == level.priority {
                return Err(vec![format!("优先级{}已被等级{}使用", level.priority, existing_id)]);
            }
        }

        self.levels.insert(level.id.clone(), level);
        Ok(())
    }

    /// 获取等级
    pub fn get_level(&self, id: &str) -> Option<&LotteryLevel> {
        self.levels.get(id)
    }

    /// 获取所有等级
    pub fn get_all_levels(&self) -> Vec<&LotteryLevel> {
        self.levels.values().collect()
    }

    /// 获取激活的等级
    pub fn get_active_levels(&self) -> Vec<&LotteryLevel> {
        self.levels
            .values()
            .filter(|level| level.status == LevelStatus::Active)
            .collect()
    }

    /// 按优先级排序获取等级
    #[allow(dead_code)]
    pub fn get_levels_by_priority(&self) -> Vec<&LotteryLevel> {
        let mut levels: Vec<&LotteryLevel> = self.levels.values().collect();
        levels.sort_by(|a, b| a.priority.cmp(&b.priority));
        levels
    }

    /// 删除等级
    pub fn delete_level(&mut self, id: &str) -> bool {
        self.levels.remove(id).is_some()
    }

    /// 更新等级状态
    pub fn update_level_status(&mut self, id: &str, status: LevelStatus) -> Result<(), String> {
        if let Some(level) = self.levels.get_mut(id) {
            level.status = status;
            level.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(())
        } else {
            Err("等级不存在".to_string())
        }
    }

    /// 验证参与者是否符合等级要求
    pub fn validate_participant_eligibility(
        &self,
        level_id: &str,
        participant: &ParticipantInfo,
    ) -> Result<(), Vec<String>> {
        let level = self
            .get_level(level_id)
            .ok_or_else(|| vec!["等级不存在".to_string()])?;

        if level.status != LevelStatus::Active {
            return Err(vec!["等级未激活".to_string()]);
        }

        let mut errors = Vec::new();

        // 检查余额要求
        if participant.balance < level.permissions.min_balance {
            errors.push(format!(
                "余额不足: 需要{}, 当前{}",
                level.permissions.min_balance, participant.balance
            ));
        }

        // 检查质押要求
        if participant.staked_amount < level.permissions.min_stake {
            errors.push(format!(
                "质押不足: 需要{}, 当前{}",
                level.permissions.min_stake, participant.staked_amount
            ));
        }

        // 检查持有时间
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time - participant.first_stake_time < level.permissions.min_holding_time {
            errors.push("持有时间不足".to_string());
        }

        // 检查NFT要求
        for required_type in &level.permissions.required_nft_types {
            if !participant.nft_types.contains(required_type) {
                errors.push(format!("缺少必需的NFT类型: {}", required_type));
            }
        }

        // 检查黑名单
        if level.permissions.blacklisted_addresses.contains(&participant.address) {
            errors.push("地址在黑名单中".to_string());
        }

        // 检查白名单
        if !level.permissions.whitelisted_addresses.is_empty() {
            if !level.permissions.whitelisted_addresses.contains(&participant.address) {
                errors.push("地址不在白名单中".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// 参与者信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInfo {
    pub address: String,
    pub balance: u128,
    pub staked_amount: u128,
    pub first_stake_time: u64,
    pub nft_types: Vec<String>,
    pub permission_level: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_creation() {
        let level = LotteryLevel {
            id: "bronze".to_string(),
            name: "青铜等级".to_string(),
            description: "基础抽奖等级".to_string(),
            priority: 1,
            weight: 1.0,
            parameters: LevelParameters {
                min_participants: 10,
                max_participants: Some(100),
                winner_count: 5,
                selection_algorithm: SelectionAlgorithm::Random,
                algorithm_params: HashMap::new(),
                time_limit: Some(3600),
                cost_limit: Some(1000),
            },
            permissions: LevelPermissions {
                min_balance: 100,
                min_stake: 50,
                min_holding_time: 86400, // 24小时
                required_nft_types: vec!["basic_nft".to_string()],
                required_permission_level: Some("basic".to_string()),
                blacklisted_addresses: Vec::new(),
                whitelisted_addresses: Vec::new(),
            },
            status: LevelStatus::Active,
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        assert_eq!(level.id, "bronze");
        assert_eq!(level.priority, 1);
        assert_eq!(level.parameters.winner_count, 5);
    }

    #[test]
    fn test_level_validator() {
        let validator = LevelValidator::new().unwrap();
        
        let mut level = LotteryLevel::default();
        level.id = "test".to_string();
        level.name = "测试等级".to_string();
        level.priority = 1;
        level.weight = 1.0;
        level.parameters.min_participants = 10;
        level.parameters.winner_count = 5;
        level.parameters.selection_algorithm = SelectionAlgorithm::Random;
        level.permissions.min_balance = 100;
        level.permissions.min_stake = 50;
        level.permissions.min_holding_time = 0;

        let result = validator.validate(&level);
        assert!(result.is_ok());
    }

    #[test]
    fn test_level_manager() {
        let mut manager = LevelManager::new().unwrap();
        
        let level = LotteryLevel {
            id: "silver".to_string(),
            name: "白银等级".to_string(),
            description: "进阶抽奖等级".to_string(),
            priority: 2,
            weight: 2.0,
            parameters: LevelParameters {
                min_participants: 20,
                max_participants: Some(200),
                winner_count: 10,
                selection_algorithm: SelectionAlgorithm::WeightedRandom,
                algorithm_params: {
                    let mut params = HashMap::new();
                    params.insert("weight_field".to_string(), serde_json::json!("stake_amount"));
                    params
                },
                time_limit: Some(7200),
                cost_limit: Some(2000),
            },
            permissions: LevelPermissions {
                min_balance: 500,
                min_stake: 200,
                min_holding_time: 172800, // 48小时
                required_nft_types: vec!["premium_nft".to_string()],
                required_permission_level: Some("creator".to_string()),
                blacklisted_addresses: Vec::new(),
                whitelisted_addresses: Vec::new(),
            },
            status: LevelStatus::Active,
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        let result = manager.upsert_level(level);
        assert!(result.is_ok());

        let retrieved = manager.get_level("silver");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "白银等级");
    }

    #[test]
    fn test_participant_eligibility() {
        let mut manager = LevelManager::new().unwrap();
        
        let level = LotteryLevel {
            id: "gold".to_string(),
            name: "黄金等级".to_string(),
            description: "高级抽奖等级".to_string(),
            priority: 3,
            weight: 5.0,
            parameters: LevelParameters {
                min_participants: 50,
                max_participants: Some(500),
                winner_count: 25,
                selection_algorithm: SelectionAlgorithm::Tournament,
                algorithm_params: {
                    let mut params = HashMap::new();
                    params.insert("tournament_size".to_string(), serde_json::json!(8));
                    params
                },
                time_limit: Some(10800),
                cost_limit: Some(5000),
            },
            permissions: LevelPermissions {
                min_balance: 1000,
                min_stake: 500,
                min_holding_time: 259200, // 72小时
                required_nft_types: vec!["vip_nft".to_string()],
                required_permission_level: Some("admin".to_string()),
                blacklisted_addresses: vec!["bad_address".to_string()],
                whitelisted_addresses: Vec::new(),
            },
            status: LevelStatus::Active,
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        manager.upsert_level(level).unwrap();

        let participant = ParticipantInfo {
            address: "good_address".to_string(),
            balance: 1500,
            staked_amount: 600,
            first_stake_time: 1234567890,
            nft_types: vec!["vip_nft".to_string()],
            permission_level: "admin".to_string(),
        };

        let result = manager.validate_participant_eligibility("gold", &participant);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_levels_by_priority() {
        let mut manager = LevelManager::new().unwrap();
        
        // 创建多个等级，优先级不按顺序
        let level1 = LotteryLevel {
            id: "bronze".to_string(),
            name: "青铜等级".to_string(),
            description: "基础等级".to_string(),
            priority: 3,
            weight: 1.0,
            parameters: LevelParameters {
                min_participants: 10,
                max_participants: Some(100),
                winner_count: 5,
                selection_algorithm: SelectionAlgorithm::Random,
                algorithm_params: HashMap::new(),
                time_limit: Some(3600),
                cost_limit: Some(1000),
            },
            permissions: LevelPermissions {
                min_balance: 100,
                min_stake: 50,
                min_holding_time: 86400,
                required_nft_types: Vec::new(),
                required_permission_level: None,
                blacklisted_addresses: Vec::new(),
                whitelisted_addresses: Vec::new(),
            },
            status: LevelStatus::Active,
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        let level2 = LotteryLevel {
            id: "silver".to_string(),
            name: "白银等级".to_string(),
            description: "进阶等级".to_string(),
            priority: 1,
            weight: 2.0,
            parameters: LevelParameters {
                min_participants: 20,
                max_participants: Some(200),
                winner_count: 10,
                selection_algorithm: SelectionAlgorithm::WeightedRandom,
                algorithm_params: {
                    let mut params = HashMap::new();
                    params.insert("weight_field".to_string(), serde_json::json!("stake_amount"));
                    params
                },
                time_limit: Some(7200),
                cost_limit: Some(2000),
            },
            permissions: LevelPermissions {
                min_balance: 500,
                min_stake: 200,
                min_holding_time: 172800,
                required_nft_types: Vec::new(),
                required_permission_level: None,
                blacklisted_addresses: Vec::new(),
                whitelisted_addresses: Vec::new(),
            },
            status: LevelStatus::Active,
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        let level3 = LotteryLevel {
            id: "gold".to_string(),
            name: "黄金等级".to_string(),
            description: "高级等级".to_string(),
            priority: 2,
            weight: 5.0,
            parameters: LevelParameters {
                min_participants: 50,
                max_participants: Some(500),
                winner_count: 25,
                selection_algorithm: SelectionAlgorithm::Tournament,
                algorithm_params: {
                    let mut params = HashMap::new();
                    params.insert("tournament_size".to_string(), serde_json::json!(8));
                    params
                },
                time_limit: Some(10800),
                cost_limit: Some(5000),
            },
            permissions: LevelPermissions {
                min_balance: 1000,
                min_stake: 500,
                min_holding_time: 259200,
                required_nft_types: Vec::new(),
                required_permission_level: None,
                blacklisted_addresses: Vec::new(),
                whitelisted_addresses: Vec::new(),
            },
            status: LevelStatus::Active,
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        // 添加等级（不按优先级顺序）
        manager.upsert_level(level1).unwrap();
        manager.upsert_level(level2).unwrap();
        manager.upsert_level(level3).unwrap();

        // 获取按优先级排序的等级
        let sorted_levels = manager.get_levels_by_priority();
        
        // 验证排序结果
        assert_eq!(sorted_levels.len(), 3);
        assert_eq!(sorted_levels[0].id, "silver"); // 优先级 1
        assert_eq!(sorted_levels[1].id, "gold");   // 优先级 2
        assert_eq!(sorted_levels[2].id, "bronze"); // 优先级 3
        
        // 验证优先级顺序
        assert_eq!(sorted_levels[0].priority, 1);
        assert_eq!(sorted_levels[1].priority, 2);
        assert_eq!(sorted_levels[2].priority, 3);
    }
}
