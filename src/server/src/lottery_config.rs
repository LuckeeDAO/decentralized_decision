//! 抽奖等级配置管理模块
//! 
//! 实现抽奖等级配置的定义、存储、版本管理和验证功能

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

/// 抽奖等级配置定义
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LotteryLevelConfig {
    /// 配置ID，唯一标识符
    pub id: String,
    /// 配置名称
    pub name: String,
    /// 配置描述
    pub description: String,
    /// 配置版本
    pub version: u32,
    /// 配置状态
    pub status: ConfigStatus,
    /// 等级配置列表
    pub levels: Vec<LevelConfig>,
    /// 全局参数
    pub global_params: GlobalParameters,
    /// 创建时间戳
    pub created_at: u64,
    /// 更新时间戳
    pub updated_at: u64,
}

/// 等级配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LevelConfig {
    /// 等级ID
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

/// 全局参数
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobalParameters {
    /// 总参与者数量限制
    pub max_total_participants: Option<u32>,
    /// 总中奖者数量限制
    pub max_total_winners: Option<u32>,
    /// 全局时间限制（秒）
    pub global_time_limit: Option<u64>,
    /// 全局成本限制
    pub global_cost_limit: Option<u128>,
    /// 是否允许重复中奖
    pub allow_duplicate_winners: bool,
    /// 是否启用防作弊机制
    pub enable_anti_cheat: bool,
    /// 作弊检测参数
    pub anti_cheat_params: HashMap<String, Value>,
}

/// 配置状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfigStatus {
    /// 草稿状态
    Draft,
    /// 激活状态
    Active,
    /// 暂停状态
    Paused,
    /// 已废弃
    Deprecated,
}

impl fmt::Display for ConfigStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigStatus::Draft => write!(f, "draft"),
            ConfigStatus::Active => write!(f, "active"),
            ConfigStatus::Paused => write!(f, "paused"),
            ConfigStatus::Deprecated => write!(f, "deprecated"),
        }
    }
}

/// 配置验证器
#[allow(dead_code)]
pub struct ConfigValidator {
    schema: JSONSchema,
}

impl ConfigValidator {
    /// 创建新的配置验证器
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
                    "version": {
                        "type": "integer",
                        "minimum": 1
                    },
                    "levels": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {
                                    "type": "string",
                                    "minLength": 1
                                },
                                "name": {
                                    "type": "string",
                                    "minLength": 1
                                },
                                "priority": {
                                    "type": "integer",
                                    "minimum": 0
                                },
                                "weight": {
                                    "type": "number",
                                    "minimum": 0.0
                                }
                            },
                            "required": ["id", "name", "priority", "weight"]
                        },
                        "minItems": 1
                    },
                    "global_params": {
                        "type": "object",
                        "properties": {
                            "allow_duplicate_winners": {
                                "type": "boolean"
                            },
                            "enable_anti_cheat": {
                                "type": "boolean"
                            }
                        }
                    }
                },
                "required": ["id", "name", "version", "levels", "global_params"]
            })
        });

        let schema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&*SCHEMA_JSON)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(Self { schema })
    }

    /// 验证配置定义
    #[allow(dead_code)]
    pub fn validate(&self, config: &LotteryLevelConfig) -> Result<(), Vec<String>> {
        let config_json = serde_json::to_value(config)
            .map_err(|e| vec![format!("序列化失败: {}", e)])?;

        let validation_result = self.schema.validate(&config_json);
        match validation_result {
            Ok(_) => {
                // 额外业务逻辑验证
                self.validate_business_rules(config)
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
    #[allow(dead_code)]
    fn validate_business_rules(&self, config: &LotteryLevelConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // 验证等级ID唯一性
        let mut level_ids = std::collections::HashSet::new();
        for level in &config.levels {
            if !level_ids.insert(&level.id) {
                errors.push(format!("等级ID重复: {}", level.id));
            }
        }

        // 验证等级优先级唯一性
        let mut priorities = std::collections::HashSet::new();
        for level in &config.levels {
            if !priorities.insert(level.priority) {
                errors.push(format!("等级优先级重复: {}", level.priority));
            }
        }

        // 验证全局参数
        if let Some(max_total) = config.global_params.max_total_participants {
            let total_min_participants: u32 = config.levels.iter()
                .map(|l| l.parameters.min_participants)
                .sum();
            if total_min_participants > max_total {
                errors.push("等级最小参与者总数超过全局限制".to_string());
            }
        }

        if let Some(max_winners) = config.global_params.max_total_winners {
            let total_winners: u32 = config.levels.iter()
                .map(|l| l.parameters.winner_count)
                .sum();
            if total_winners > max_winners {
                errors.push("等级中奖者总数超过全局限制".to_string());
            }
        }

        // 验证每个等级的参数
        for level in &config.levels {
            if let Err(level_errors) = self.validate_level_params(&level.parameters) {
                errors.extend(level_errors.into_iter().map(|e| format!("等级{}: {}", level.id, e)));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// 验证等级参数
    #[allow(dead_code)]
    fn validate_level_params(&self, params: &LevelParameters) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // 验证参与者数量逻辑
        if let Some(max_participants) = params.max_participants {
            if params.min_participants > max_participants {
                errors.push("最小参与者数量不能大于最大参与者数量".to_string());
            }
        }

        // 验证中奖者数量逻辑
        if params.winner_count > params.min_participants {
            errors.push("中奖者数量不能大于最小参与者数量".to_string());
        }

        // 验证算法参数
        if let Err(e) = self.validate_algorithm_params(params) {
            errors.extend(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// 验证算法特定参数
    #[allow(dead_code)]
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

/// 配置管理器
#[allow(dead_code)]
pub struct ConfigManager {
    configs: HashMap<String, LotteryLevelConfig>,
    validator: ConfigValidator,
}

impl ConfigManager {
    /// 创建新的配置管理器
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(Self {
            configs: HashMap::new(),
            validator: ConfigValidator::new()?,
        })
    }

    /// 添加或更新配置
    #[allow(dead_code)]
    pub fn upsert_config(&mut self, config: LotteryLevelConfig) -> Result<(), Vec<String>> {
        // 验证配置定义
        self.validator.validate(&config)?;

        // 检查ID冲突（除了更新自己的情况）
        if let Some(existing) = self.configs.get(&config.id) {
            if existing.version != config.version {
                return Err(vec!["配置版本冲突，请使用递增的版本号".to_string()]);
            }
        }

        self.configs.insert(config.id.clone(), config);
        Ok(())
    }

    /// 获取配置
    #[allow(dead_code)]
    pub fn get_config(&self, id: &str) -> Option<&LotteryLevelConfig> {
        self.configs.get(id)
    }

    /// 获取所有配置
    #[allow(dead_code)]
    pub fn get_all_configs(&self) -> Vec<&LotteryLevelConfig> {
        self.configs.values().collect()
    }

    /// 获取激活的配置
    #[allow(dead_code)]
    pub fn get_active_configs(&self) -> Vec<&LotteryLevelConfig> {
        self.configs
            .values()
            .filter(|config| config.status == ConfigStatus::Active)
            .collect()
    }

    /// 删除配置
    #[allow(dead_code)]
    pub fn delete_config(&mut self, id: &str) -> bool {
        self.configs.remove(id).is_some()
    }

    /// 更新配置状态
    #[allow(dead_code)]
    pub fn update_config_status(&mut self, id: &str, status: ConfigStatus) -> Result<(), String> {
        if let Some(config) = self.configs.get_mut(id) {
            config.status = status;
            config.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(())
        } else {
            Err("配置不存在".to_string())
        }
    }

    /// 获取配置版本历史
    #[allow(dead_code)]
    pub fn get_config_versions(&self, id: &str) -> Vec<u32> {
        if let Some(config) = self.configs.get(id) {
            vec![config.version]
        } else {
            Vec::new()
        }
    }

    /// 回滚到指定版本（简化实现，实际应该支持多版本）
    #[allow(dead_code)]
    pub fn rollback_config(&mut self, id: &str, version: u32) -> Result<(), String> {
        if let Some(config) = self.configs.get_mut(id) {
            if config.version == version {
                return Ok(());
            }
            return Err("版本回滚功能需要多版本支持".to_string());
        } else {
            Err("配置不存在".to_string())
        }
    }
}

impl Default for LotteryLevelConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            description: String::new(),
            version: 1,
            status: ConfigStatus::Draft,
            levels: Vec::new(),
            global_params: GlobalParameters {
                max_total_participants: None,
                max_total_winners: None,
                global_time_limit: None,
                global_cost_limit: None,
                allow_duplicate_winners: false,
                enable_anti_cheat: true,
                anti_cheat_params: HashMap::new(),
            },
            created_at: 0,
            updated_at: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = LotteryLevelConfig {
            id: "test_config".to_string(),
            name: "测试配置".to_string(),
            description: "测试抽奖配置".to_string(),
            version: 1,
            status: ConfigStatus::Active,
            levels: vec![
                LevelConfig {
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
                        min_holding_time: 86400,
                        required_nft_types: vec!["basic_nft".to_string()],
                        required_permission_level: Some("basic".to_string()),
                        blacklisted_addresses: Vec::new(),
                        whitelisted_addresses: Vec::new(),
                    },
                }
            ],
            global_params: GlobalParameters {
                max_total_participants: Some(1000),
                max_total_winners: Some(100),
                global_time_limit: Some(86400),
                global_cost_limit: Some(10000),
                allow_duplicate_winners: false,
                enable_anti_cheat: true,
                anti_cheat_params: HashMap::new(),
            },
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        assert_eq!(config.id, "test_config");
        assert_eq!(config.version, 1);
        assert_eq!(config.levels.len(), 1);
    }

    #[test]
    fn test_config_validation() {
        let mut manager = ConfigManager::new().unwrap();
        
        let config = LotteryLevelConfig {
            id: "valid_config".to_string(),
            name: "有效配置".to_string(),
            description: "有效的抽奖配置".to_string(),
            version: 1,
            status: ConfigStatus::Active,
            levels: vec![
                LevelConfig {
                    id: "silver".to_string(),
                    name: "白银等级".to_string(),
                    description: "进阶抽奖等级".to_string(),
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
                        required_nft_types: vec!["premium_nft".to_string()],
                        required_permission_level: Some("creator".to_string()),
                        blacklisted_addresses: Vec::new(),
                        whitelisted_addresses: Vec::new(),
                    },
                }
            ],
            global_params: GlobalParameters {
                max_total_participants: Some(1000),
                max_total_winners: Some(100),
                global_time_limit: Some(86400),
                global_cost_limit: Some(10000),
                allow_duplicate_winners: false,
                enable_anti_cheat: true,
                anti_cheat_params: HashMap::new(),
            },
            created_at: 1234567890,
            updated_at: 1234567890,
        };

        let result = manager.upsert_config(config);
        assert!(result.is_ok());

        let retrieved = manager.get_config("valid_config");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "有效配置");
    }

    #[test]
    fn test_config_status_update() {
        let mut manager = ConfigManager::new().unwrap();
        
        let mut config = LotteryLevelConfig::default();
        config.id = "status_test".to_string();
        config.name = "状态测试".to_string();
        config.version = 1;
        config.status = ConfigStatus::Draft;
        
        manager.upsert_config(config).unwrap();
        
        let result = manager.update_config_status("status_test", ConfigStatus::Active);
        assert!(result.is_ok());
        
        let updated_config = manager.get_config("status_test").unwrap();
        assert_eq!(updated_config.status, ConfigStatus::Active);
    }
}
