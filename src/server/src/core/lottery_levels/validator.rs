use jsonschema::{Draft, JSONSchema};
use once_cell::sync::Lazy;
use serde_json::Value;

use super::types::{LevelParameters, LotteryLevel, SelectionAlgorithm};

/// 等级验证器
pub struct LevelValidator {
    pub(crate) schema: JSONSchema,
}

impl LevelValidator {
    /// 创建新的等级验证器
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        static SCHEMA_JSON: Lazy<Value> = Lazy::new(|| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "minLength": 1, "maxLength": 50, "pattern": "^[a-zA-Z0-9_-]+$" },
                    "name": { "type": "string", "minLength": 1, "maxLength": 100 },
                    "description": { "type": "string", "maxLength": 500 },
                    "priority": { "type": "integer", "minimum": 0, "maximum": 1000 },
                    "weight": { "type": "number", "minimum": 0.0, "maximum": 100.0 },
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "min_participants": { "type": "integer", "minimum": 1 },
                            "max_participants": { "type": ["integer", "null"], "minimum": 1 },
                            "winner_count": { "type": "integer", "minimum": 1 },
                            "selection_algorithm": { "type": "string", "enum": ["random", "weighted_random", "roulette_wheel", "tournament"] },
                            "time_limit": { "type": ["integer", "null"], "minimum": 0 },
                            "cost_limit": { "type": ["integer", "null"], "minimum": 0 }
                        },
                        "required": ["min_participants", "winner_count", "selection_algorithm"]
                    },
                    "permissions": {
                        "type": "object",
                        "properties": {
                            "min_balance": { "type": "integer", "minimum": 0 },
                            "min_stake": { "type": "integer", "minimum": 0 },
                            "min_holding_time": { "type": "integer", "minimum": 0 },
                            "required_nft_types": { "type": "array", "items": { "type": "string" } },
                            "blacklisted_addresses": { "type": "array", "items": { "type": "string" } },
                            "whitelisted_addresses": { "type": "array", "items": { "type": "string" } }
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
            Ok(_) => self.validate_business_rules(level),
            Err(errors) => {
                let error_messages: Vec<String> = errors.map(|e| format!("{}", e)).collect();
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

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// 验证算法特定参数
    fn validate_algorithm_params(&self, params: &LevelParameters) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        match &params.selection_algorithm {
            SelectionAlgorithm::Tournament => {
                if let Some(tournament_size) = params.algorithm_params.get("tournament_size") {
                    if let Some(size) = tournament_size.as_u64() {
                        if size < 2 { errors.push("锦标赛大小必须至少为2".to_string()); }
                    } else { errors.push("锦标赛大小必须是正整数".to_string()); }
                }
                // 未提供参数时采用默认值，不作为错误
            }
            SelectionAlgorithm::WeightedRandom => {
                if let Some(weight_field) = params.algorithm_params.get("weight_field") {
                    if !weight_field.is_string() { errors.push("权重字段必须是字符串".to_string()); }
                }
                // 未提供参数时采用默认权重字段，不作为错误
            }
            SelectionAlgorithm::Custom(algorithm_name) => {
                if algorithm_name.is_empty() {
                    errors.push("自定义算法名称不能为空".to_string());
                }
            }
            _ => {}
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}


