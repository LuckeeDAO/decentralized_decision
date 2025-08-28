//! 抽奖等级系统模块（拆分版）
//!
//! - 类型与结构体定义：types.rs
//! - 等级验证器：validator.rs
//! - 参与者信息：participant.rs
//! - 等级管理器：manager.rs

mod types;
pub mod validator;
pub mod participant;
mod manager;
pub mod configurator;
pub mod executor;

pub use types::{LotteryLevel, LevelParameters, SelectionAlgorithm, LevelPermissions, LevelStatus};
pub use manager::LevelManager;
// 类型按需由上层导入，避免当前模块内未使用告警

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::*;
    use super::validator::LevelValidator;
    use super::participant::ParticipantInfo;

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
                min_holding_time: 86400,
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
                min_holding_time: 172800,
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
                min_holding_time: 259200,
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

        manager.upsert_level(level1).unwrap();
        manager.upsert_level(level2).unwrap();
        manager.upsert_level(level3).unwrap();

        let sorted_levels = manager.get_levels_by_priority();

        assert_eq!(sorted_levels.len(), 3);
        assert_eq!(sorted_levels[0].id, "silver");
        assert_eq!(sorted_levels[1].id, "gold");
        assert_eq!(sorted_levels[2].id, "bronze");
    }
}


