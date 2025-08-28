use std::collections::{HashMap, HashSet};

use super::types::{LotteryLevel, LevelParameters, SelectionAlgorithm};
use super::validator::LevelValidator;

/// 等级配置器：负责定义/校验/优先级冲突检测与解析
#[allow(dead_code)]
pub struct LevelConfigurator {
    validator: LevelValidator,
}

#[allow(dead_code)]
impl LevelConfigurator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(Self { validator: LevelValidator::new()? })
    }

    /// 校验单个等级定义
    pub fn validate_level(&self, level: &LotteryLevel) -> Result<(), Vec<String>> {
        self.validator.validate(level)
    }

    /// 校验多个等级的集合（包含ID/优先级唯一性、参数一致性等）
    pub fn validate_levels(&self, levels: &[LotteryLevel]) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = Vec::new();

        // 基础单体校验
        for level in levels {
            if let Err(mut es) = self.validate_level(level) { errors.append(&mut es); }
        }

        // ID 唯一性
        let mut ids = HashSet::new();
        for l in levels {
            if !ids.insert(&l.id) {
                errors.push(format!("等级ID重复: {}", l.id));
            }
        }

        // 优先级唯一性
        let mut priorities = HashSet::new();
        for l in levels {
            if !priorities.insert(l.priority) {
                errors.push(format!("等级优先级重复: {}", l.priority));
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// 解决优先级冲突：若发现冲突，按字典序稳定重排并重新分配唯一priority
    pub fn resolve_priority_conflicts(&self, mut levels: Vec<LotteryLevel>) -> Vec<LotteryLevel> {
        // 按 (priority, id) 排序
        levels.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        // 重新分配递增的唯一优先级（从1起），保持原有先后关系
        let mut next = 1u32;
        for l in levels.iter_mut() {
            l.priority = next;
            next += 1;
        }
        levels
    }

    /// 生成等级 -> 参数 映射，便于执行器按等级驱动算法
    pub fn build_level_params_map(&self, levels: &[LotteryLevel]) -> HashMap<String, LevelParameters> {
        let mut map = HashMap::new();
        for l in levels {
            map.insert(l.id.clone(), l.parameters.clone());
        }
        map
    }

    /// 抽取等级 -> 算法 映射
    pub fn build_level_algorithm_map(&self, levels: &[LotteryLevel]) -> HashMap<String, SelectionAlgorithm> {
        let mut map = HashMap::new();
        for l in levels {
            map.insert(l.id.clone(), l.parameters.selection_algorithm.clone());
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::lottery_levels::types::{LevelPermissions, LevelStatus};

    fn sample_level(id: &str, priority: u32, alg: SelectionAlgorithm) -> LotteryLevel {
        LotteryLevel {
            id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            priority,
            weight: 1.0,
            parameters: LevelParameters {
                min_participants: 2,
                max_participants: Some(10),
                winner_count: 1,
                selection_algorithm: alg,
                algorithm_params: HashMap::new(),
                time_limit: None,
                cost_limit: None,
            },
            permissions: LevelPermissions {
                min_balance: 0,
                min_stake: 0,
                min_holding_time: 0,
                required_nft_types: vec![],
                required_permission_level: None,
                blacklisted_addresses: vec![],
                whitelisted_addresses: vec![],
            },
            status: LevelStatus::Active,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn test_validate_and_resolve_priorities() {
        let configurator = LevelConfigurator::new().unwrap();
        let a = sample_level("A", 1, SelectionAlgorithm::Random);
        let b = sample_level("B", 1, SelectionAlgorithm::WeightedRandom);
        let c = sample_level("C", 2, SelectionAlgorithm::Tournament);

        // 校验应报告冲突
        assert!(configurator.validate_levels(&[a.clone(), b.clone(), c.clone()]).is_err());

        // 解决冲突后应通过
        let fixed = configurator.resolve_priority_conflicts(vec![a, b, c]);
        assert!(configurator.validate_levels(&fixed).is_ok());

        // 构建map
        let params_map = configurator.build_level_params_map(&fixed);
        assert_eq!(params_map.len(), 3);
        let alg_map = configurator.build_level_algorithm_map(&fixed);
        assert_eq!(alg_map.len(), 3);
    }
}


